"""MCP export: one Streamable HTTP MCP endpoint serving a hub agent's built-in tools to external harnesses."""

import asyncio
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic_ai import RunContext
from pydantic_ai.models.test import TestModel
from pydantic_ai.toolsets import FunctionToolset
from pydantic_ai.usage import RunUsage
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from .diagnostics import diagnose
from .limits import GLOBAL_ADMIN_AGENT

TOKEN = re.compile(r'dsk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})')


class Unauthorized(Exception):
    pass


def export_url(service):
    return service.settings.origin + '/mcp'


def _digest(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def _mint(service, agent_id, label, created_by, *, seal=False):
    key_id, secret = secrets.token_hex(8), secrets.token_urlsafe(32)
    token = f'dsk_{key_id}_{secret}'
    service._remember_secret(token)
    service.store.execute('INSERT INTO mcp_export_keys(id,agent_id,label,hash,sealed,created_by,created) VALUES(?,?,?,?,?,?,?)',
                          (key_id, agent_id, label, _digest(secret), service.store.seal(token) if seal else None,
                           created_by, time.time()))
    return key_id, token


async def _authorize(service, identity, agent_id):
    if identity.get('_agent_id'):
        raise PermissionError('MCP export keys require a human administrator')
    if agent_id is None:
        if identity.get('type') != 1:
            raise PermissionError('Global MCP export keys require a platform administrator')
    else:
        await service.authorize(identity, agent_id)


async def create_key(service, identity, agent_id, label):
    """Create a per-agent key (or a global key for agent_id None); the token is returned once and never stored."""
    await _authorize(service, identity, agent_id)
    if not isinstance(label, str) or not label.strip() or len(label) > 64 or not label.isprintable():
        raise ValueError('Use a printable key label of 1–64 characters')
    key_id, token = _mint(service, agent_id, label.strip(), identity['userid'])
    service.store.audit(identity['userid'], 'mcp-key-create', key_id)
    return token


async def list_keys(service, identity, agent_id):
    await _authorize(service, identity, agent_id)
    return service.store.all(
        'SELECT id,label,created,last_used FROM mcp_export_keys WHERE agent_id IS ? AND revoked IS NULL ORDER BY created',
        (agent_id,))


async def revoke_key(service, identity, key_id):
    key = service.store.one('SELECT agent_id FROM mcp_export_keys WHERE id=? AND revoked IS NULL', (key_id,))
    if not key:
        raise ValueError('MCP export key is unavailable')
    await _authorize(service, identity, key['agent_id'])
    service.store.execute('UPDATE mcp_export_keys SET revoked=? WHERE id=?', (time.time(), key_id))
    service.store.audit(identity['userid'], 'mcp-key-revoke', key_id)


def vm_key(service, agent_id, vm_id):
    """The agent's reusable export token for one VM, minted on first use so the agent never sees it."""
    from .runtime import CURRENT_RUN
    label = 'vm:' + str(vm_id)
    row = service.store.one('SELECT sealed FROM mcp_export_keys WHERE agent_id=? AND label=? AND sealed IS NOT NULL '
                            'AND revoked IS NULL', (agent_id, label))
    if row:
        return service.store.open(row['sealed'])
    run = service.store.one('SELECT c.human_id FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id '
                            'WHERE r.id=?', (CURRENT_RUN.get(),))
    if not vm_id or not run:
        raise PermissionError('{{mcp_key}} is available only to run_vm_command and write_vm_secret_file in a conversation')
    key_id, token = _mint(service, agent_id, label, run['human_id'], seal=True)
    service.store.audit(agent_id, 'mcp-key-create', key_id)
    return token


async def authenticate(service, authorization, path_agent):
    """Return (key, acting agent id) for a bearer token and optional /mcp/<agent_id> path."""
    match = TOKEN.fullmatch(authorization[7:].strip()) if authorization[:7].lower() == 'bearer ' else None
    key = match and service.store.one('SELECT * FROM mcp_export_keys WHERE id=? AND revoked IS NULL', (match[1],))
    if not key or not hmac.compare_digest(key['hash'], _digest(match[2])):
        raise Unauthorized()
    acting = path_agent or key['agent_id'] or GLOBAL_ADMIN_AGENT
    if key['agent_id'] and acting != key['agent_id']:
        chain = await service.agent_chain(await service.agent(acting))
        if key['agent_id'] not in {member['id'] for member in chain[:-1]}:
            raise PermissionError('This key cannot act as that agent')
    service.store.execute('UPDATE mcp_export_keys SET last_used=? WHERE id=?', (time.time(), key['id']))
    return key, acting


class Exports:
    """Serves the tools Runtime builds for an agent, recording each call as a durable run in the key's conversation."""

    def __init__(self, service, runtime):
        self.service, self.runtime = service, runtime
        self.server = Server('dirigentenstab')
        self.manager = StreamableHTTPSessionManager(self.server, json_response=True, stateless=True)
        self.task, self.starting = None, asyncio.Lock()
        self.server.list_tools()(self.list_tools)
        self.server.call_tool(validate_input=False)(self.call_tool)

    def install(self, app):
        app.add_route('/mcp', self, include_in_schema=False)
        app.add_route('/mcp/{agent_id}', self, include_in_schema=False)

    async def start(self):
        async with self.starting:
            if self.task:
                return
            await self._start()

    async def _start(self):
        ready = asyncio.Event()

        async def serve():
            async with self.manager.run():
                ready.set()
                await asyncio.Event().wait()
        self.task = asyncio.create_task(serve())
        await ready.wait()

    async def stop(self):
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)

    async def __call__(self, scope, receive, send):
        try:
            scope['ds_mcp'] = await authenticate(self.service, Headers(scope=scope).get('authorization', ''),
                                                 scope.get('path_params', {}).get('agent_id'))
        except Unauthorized:
            response = JSONResponse({'error': 'Invalid or revoked MCP export key'}, 401,
                                    {'WWW-Authenticate': 'Bearer'})
        except (PermissionError, ValueError):
            response = JSONResponse({'error': 'This key cannot act as that agent'}, 403)
        else:
            await self.start()  # Lazily: NiceGUI forbids registering startup handlers once it is running.
            return await self.manager.handle_request(scope, receive, send)
        await response(scope, receive, send)

    def _scope(self):
        return self.server.request_context.request.scope['ds_mcp']

    async def _tools(self, key, acting, budget, conversation_id=None, call_id=None, name=None):
        identity = await self.service.execution_identity(acting, key['created_by'])
        agent = await self.runtime._agent(identity, acting, budget, None, conversation_id=conversation_id, export=True)
        toolset = next(t for t in agent.toolsets if isinstance(t, FunctionToolset))
        ctx = RunContext(deps=None, model=TestModel(), usage=budget['usage'], run_step=1,
                         tool_call_id=call_id, tool_name=name)
        return toolset, ctx, await toolset.get_tools(ctx)

    async def list_tools(self):
        key, acting = self._scope()
        _, _, tools = await self._tools(key, acting, {'usage': RunUsage(), 'state': {}, 'operation_id': None,
                                                       'events': [], 'save': lambda: None})
        return [types.Tool(name=name, description=tool.tool_def.description,
                           inputSchema=tool.tool_def.parameters_json_schema) for name, tool in tools.items()]

    def _conversation(self, key, acting):
        store = self.service.store
        store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages,imported,mcp_key_id) '
                      'VALUES(?,?,?,?,?,?,1,?) ON CONFLICT DO NOTHING',
                      (str(uuid.uuid4()), acting, key['created_by'], 'MCP · ' + key['label'], time.time(),
                       store.seal([]), key['id']))
        return store.one('SELECT id FROM conversations WHERE mcp_key_id=? AND agent_id=?', (key['id'], acting))['id']

    async def call_tool(self, name, arguments):
        key, acting = self._scope()
        service, store = self.service, self.service.store
        from .runtime import CURRENT_RUN
        conversation_id = self._conversation(key, acting)
        with store.connect() as conn:
            operation_id = self.runtime._new_run(conn, acting, conversation_id, time.time())
        state = store.open(store.one('SELECT checkpoint FROM chat_runs WHERE id=?', (operation_id,))['checkpoint'])
        events, call_id, active = [], str(uuid.uuid4()), None

        def save():
            store.execute('UPDATE chat_runs SET events=?,tool=?,updated=?,checkpoint=? WHERE id=?',
                          (store.seal(events), active, time.time(), store.seal(state), operation_id))

        def emit(event):
            nonlocal active
            events.append(service.redact(event | {'operation_id': operation_id, 'agent_id': acting}))
            active = name if event['type'] == 'tool_call' else None
            save()

        budget = {'usage': RunUsage(), 'state': state, 'operation_id': operation_id, 'events': events, 'save': save}
        token, status, started, target = CURRENT_RUN.set(operation_id), 'failed', time.monotonic(), ''
        try:
            toolset, ctx, tools = await self._tools(key, acting, budget, conversation_id, call_id, name)
            call = self.runtime._call_event(name, call_id, arguments or {})
            target = call['target']
            emit(call)
            if name not in tools:
                result = {'error': f'Unknown tool {name}'}
            else:
                tool = tools[name]
                result = await toolset.call_tool(
                    name, tool.args_validator.validate_python(arguments or {}), ctx, tool)
            status = 'completed'
        except asyncio.CancelledError:
            status = 'interrupted'
            state.update(reason='restart', resumable=True)
            for mutation in state['mutations'].values():
                if mutation['status'] == 'running':
                    mutation['status'] = 'uncertain'
            raise
        except Exception as exc:
            result = {'error': str(diagnose(exc, operation_id=operation_id, agent_id=acting, tool=name))}
        finally:
            self.runtime.config_changed.discard(operation_id)
            CURRENT_RUN.reset(token)
        try:
            emit(self.runtime._result_event(name, call_id, target, result, time.monotonic() - started))
        finally:
            store.execute('UPDATE chat_runs SET status=?,updated=? WHERE id=?', (status, time.time(), operation_id))
        text = json.dumps(service.redact(result), ensure_ascii=False, default=str)
        if len(text) > service.settings.max_output:
            if isinstance(result, dict) and result.get('truncated') and isinstance(result.get('preview'), str):
                # Already bounded by the tool layer: shrink its preview rather than wrapping it again.
                preview = result['preview']
                while len(text) > service.settings.max_output and preview:
                    preview = preview[:len(preview) // 2]
                    text = json.dumps(service.redact({**result, 'preview': preview}), ensure_ascii=False, default=str)
            if len(text) > service.settings.max_output:
                text = json.dumps({'truncated': True, 'preview': text[:service.settings.max_output]})
        return types.CallToolResult(content=[types.TextContent(type='text', text=text)],
                                    isError=isinstance(result, dict) and bool(result.get('error')))
