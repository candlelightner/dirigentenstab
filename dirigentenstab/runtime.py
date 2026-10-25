"""Pydantic AI agents with persistent, human-owned conversations."""

import asyncio
import json
import secrets
import time
import uuid

import httpx
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.messages import (
    FunctionToolCallEvent,
    FunctionToolResultEvent,
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    PartDeltaEvent,
    PartStartEvent,
    TextPart,
    TextPartDelta,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel
from pydantic_ai.profiles.openai import OpenAIModelProfile
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.usage import RunUsage, UsageLimits

from .guest import Guest
from .diagnostics import diagnose


def load_history(value):
    """Recover usage metadata damaged by v0.1.2's token-name secret redaction."""
    for message in value:
        if message.get('kind') == 'response' and isinstance(message.get('usage'), dict):
            # These are telemetry counts, not credentials. Unknown counts stay unknown/zero.
            message['usage'] = {key: item for key, item in message['usage'].items()
                                if item != '[redacted]'}
            details = message['usage'].get('details')
            if isinstance(details, dict):
                message['usage']['details'] = {key: item for key, item in details.items()
                                               if item != '[redacted]'}
    messages = ModelMessagesTypeAdapter.validate_python(value)
    pending = {}
    for message in messages:
        for part in message.parts:
            if isinstance(part, ToolCallPart):
                pending[part.tool_call_id] = part
            elif isinstance(part, ToolReturnPart) or part.part_kind == 'retry-prompt':
                pending.pop(getattr(part, 'tool_call_id', None), None)
    if pending:
        messages.append(ModelRequest(parts=[ToolReturnPart(
            tool_name=part.tool_name, tool_call_id=part.tool_call_id,
            content='Execution interrupted. Outcome unknown; inspect durable operation state before retrying mutations.')
            for part in pending.values()]))
    return messages


def build_model(provider, model_id, store):
    if not model_id or len(model_id) > 256:
        raise ValueError('Configure a model identifier before starting a conversation')
    client = OpenAIProvider(base_url=provider['base_url'], api_key=store.open(provider['api_key']) or 'unused')
    model_class = OpenAIResponsesModel if provider['protocol'] == 'responses' else OpenAIChatModel
    return model_class(model_id, provider=client,
                       profile=OpenAIModelProfile(openai_supports_strict_tool_definition=False))


async def provider_models(provider, store):
    headers = {}
    if key := store.open(provider['api_key']):
        headers['Authorization'] = 'Bearer ' + key
    async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
        async with client.stream('GET', provider['base_url'].rstrip('/') + '/models', headers=headers) as response:
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 1024 * 1024:
                    raise ValueError('Model catalogue exceeds the size limit')
    catalogue = json.loads(body)
    if not isinstance(catalogue, dict) or not isinstance(catalogue.get('data'), list):
        raise ValueError('Provider returned an invalid model catalogue; enter a model ID manually')
    return [item['id'] for item in catalogue['data'][:1000]
            if isinstance(item, dict) and isinstance(item.get('id'), str) and len(item['id']) <= 256]


discover_models = provider_models


async def test_provider(provider, model_id, store):
    result = {'reachable': False, 'authenticated': False, 'model_available': None,
              'tool_calling': False, 'error': None}
    try:
        models = await provider_models(provider, store)
        result.update(reachable=True, authenticated=True, model_available=model_id in models)
    except httpx.HTTPStatusError as exc:
        result['reachable'] = True
        if exc.response.status_code in {401, 403}:
            result['error'] = 'Provider rejected authentication'
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    nonce = secrets.token_hex(16)
    called = False
    try:
        agent = Agent(build_model(provider, model_id, store), retries=0)

        @agent.tool_plain
        def probe(value: str) -> str:
            """Echo the required connection-test nonce."""
            nonlocal called
            called = secrets.compare_digest(value, nonce)
            return 'pong' if called else 'incorrect nonce'

        async with asyncio.timeout(45):
            await agent.run(f'Call probe with value {nonce}, then report its result.',
                            usage_limits=UsageLimits(request_limit=3, tool_calls_limit=2))
        result.update(reachable=True, authenticated=True, model_available=True, tool_calling=called)
        result['error'] = None if called else 'The model did not successfully call the probe tool'
    except Exception:
        result['error'] = 'Agent-runtime test failed; check protocol, credentials, model and tool support'
    return result


class Runtime:
    def __init__(self, service):
        self.service = service
        self.guest = Guest(service)
        self.slots = asyncio.Semaphore(4)
        self.running = set()
        self.service.store.execute("UPDATE chat_runs SET status='interrupted',updated=? WHERE status='running'",
                                   (time.time(),))
        self.model_cache = {}

    async def models(self, identity, provider_id):
        allowed = await self.service.providers(identity)
        if not any(p['id'] == provider_id for p in allowed):
            raise PermissionError('Provider is unavailable')
        provider = self.service.store.one('SELECT * FROM providers WHERE id=?', (provider_id,))
        key = (provider_id, provider['base_url'], provider['api_key'])
        cached = self.model_cache.get(key)
        if cached and time.monotonic() - cached[0] < 60:
            return cached[1]
        models = await provider_models(provider, self.service.store)
        self.model_cache = {key: (time.monotonic(), models)}
        return models

    async def conversations(self, identity, agent_id):
        await self.service.authorize(identity, agent_id)
        return self.service.store.all(
            'SELECT id,title,created FROM conversations WHERE human_id=? AND agent_id=? ORDER BY created DESC',
            (identity['userid'], agent_id),
        )

    async def restore(self, identity, conversation_id):
        conversation = self.service.store.one('SELECT * FROM conversations WHERE id=? AND human_id=?',
                                              (conversation_id, identity['userid']))
        if not conversation:
            raise PermissionError('Conversation is not accessible')
        await self.service.authorize(identity, conversation['agent_id'])
        return {name: conversation[name] for name in ('id', 'agent_id', 'title', 'imported')} | {
            'messages': self.service.redact(self.service.store.open(conversation['messages'])),
            'runs': [{k: row[k] for k in ('id', 'status', 'tool', 'category')} | {
                'events': self.service.redact(self.service.store.open(row['events']))}
                for row in self.service.store.all('SELECT * FROM chat_runs WHERE conversation_id=? ORDER BY created',
                                                  (conversation_id,))],
        }

    async def _agent(self, identity, agent_id, budget, depth, emit):
        record = await self.service.authorize(identity, agent_id)
        provider = self.service.store.one('SELECT * FROM providers WHERE id=?', (record['provider_id'],))
        if not provider:
            raise ValueError('Select a model provider in this agent’s settings first')
        context = await self.service.context(record)
        instructions = self.service.redact(record['instructions'])
        agent = Agent(
            build_model(provider, record['model'] or provider['default_model'], self.service.store),
            instructions=(instructions + '\nAdministrative environment (informational; tools enforce access):\n'
                          + json.dumps(self.service.redact(context), ensure_ascii=False)),
            retries=1, model_settings={'max_tokens': 8192},
        )

        async def invoke(operation, *args, **kwargs):
            try:
                await self.service.authorize(identity, agent_id)
                return self.service.redact(await operation(*args, **kwargs))
            except (PermissionError, ValueError, RuntimeError) as exc:
                error = diagnose(exc, agent_id=agent_id, tool=operation.__name__)
                return {'error': str(error), 'category': error.category}

        @agent.tool_plain
        async def search_api(query: str) -> dict:
            """Search the live CloudStack API catalogue available to this agent."""
            return await invoke(self.service.search_api, agent_id, query)

        @agent.tool_plain
        async def describe_api(command: str) -> dict:
            """Describe a CloudStack command's actual parameters, outputs and async semantics."""
            return await invoke(self.service.describe_api, agent_id, command)

        @agent.tool_plain(sequential=True)
        async def execute_api(command: str, params: dict) -> dict:
            """Run a discovered CloudStack command using this agent's restricted runtime identity."""
            return await invoke(self.service.execute, agent_id, command, params)

        @agent.tool_plain(sequential=True)
        async def create_subgroup(name: str, model: str | None = None, instructions: str | None = None) -> dict:
            """Create a child administrative agent beneath this agent's current CloudStack domain."""
            return await invoke(self.service.create_subgroup, agent_id, name, model, instructions)

        @agent.tool_plain(sequential=True)
        async def run_vm_command(vm_id: str, command: str, timeout: int = 120) -> dict:  # noqa: ASYNC109
            """Execute inside an authorized guest VM with its managed SSH identity and pinned host key."""
            return await invoke(self.guest.run_vm_command, agent_id, vm_id, command, timeout)

        @agent.tool_plain(sequential=True)
        async def transfer_vm_file(vm_id: str, source: str, destination: str, direction: str) -> dict:
            """Upload/download an authorized guest file; local paths are agent-workspace filenames, max 8 MiB."""
            return await invoke(self.guest.transfer_vm_file, agent_id, vm_id, source, destination, direction)

        @agent.tool_plain(sequential=True)
        async def delegate(agent_id: str, task: str) -> dict:
            """Delegate to an authorized subordinate using the subordinate's model and own credentials."""
            target = agent_id
            if depth >= 3 or budget['remaining'] <= 0:
                return {'error': 'Delegation depth or execution limit reached'}
            if not await self.service.can_delegate(record['id'], target):
                return {'error': 'Delegation is not authorized'}
            await self.service.authorize(identity, target)
            budget['remaining'] -= 1
            child = await self._agent(identity, target, budget, depth + 1, emit)
            task = self.service.redact(task)
            conversation_id = str(uuid.uuid4())
            messages = [ModelRequest(parts=[UserPromptPart(task)]),
                        ModelResponse(parts=[TextPart('Delegation interrupted; retry the task if needed.')])]
            self.service.store.execute(
                'INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                (conversation_id, target, identity['userid'], 'Delegated: ' + task[:64],
                 time.time(), self.service.store.seal([])),
            )
            captured_child = []
            try:
                with capture_run_messages() as captured_child:
                    result = await child.run(task, usage=budget['usage'],
                                             usage_limits=UsageLimits(request_limit=20, tool_calls_limit=30))
                    messages = result.all_messages()
            finally:
                safe_messages = self.service.redact(json.loads(ModelMessagesTypeAdapter.dump_json(captured_child or messages)))
                self.service.store.execute('UPDATE conversations SET messages=? WHERE id=?',
                                           (self.service.store.seal(safe_messages), conversation_id))
            self.service.store.audit(record['id'], 'delegate', target)
            return {'agent_id': target, 'conversation_id': conversation_id,
                    'output': self.service.redact(result.output)}

        return agent

    async def chat(self, identity, agent_id, conversation_id, prompt, on_event=None):
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 32768:
            raise ValueError('Message must contain 1–32768 characters')
        await self.service.authorize(identity, agent_id)
        history_json = []
        if conversation_id:
            conversation = await self.restore(identity, conversation_id)
            if conversation['agent_id'] != agent_id:
                raise PermissionError('Conversation belongs to a different agent')
            if conversation['imported']:
                conversation_id = None
            else:
                history_json = conversation['messages']
        if not conversation_id:
            conversation_id = str(uuid.uuid4())
            self.service.store.execute(
                'INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                (conversation_id, agent_id, identity['userid'], self.service.redact(prompt[:80]),
                 time.time(), self.service.store.seal([])),
            )
        if conversation_id in self.running:
            raise ValueError('This conversation already has an execution in progress')
        if len(json.dumps(history_json)) > 2 * 1024 * 1024:
            raise ValueError('Conversation reached its context limit; start a new conversation')
        prompt = self.service.redact(prompt)
        history = load_history(history_json)
        operation_id = str(uuid.uuid4())
        events_log, started, targets = [], {}, {}
        last_checkpoint = 0
        active_tool = None
        partial_text, partial_message_index = '', None
        captured = []
        messages = history + [ModelRequest(parts=[UserPromptPart(prompt)])]
        self.service.store.execute(
            'INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
            (operation_id, conversation_id, 'running', agent_id, time.time(), time.time(),
             self.service.store.seal([])))
        self.running.add(conversation_id)

        def checkpoint():
            nonlocal last_checkpoint
            saved = list(captured or messages)
            if partial_text and partial_message_index is not None and len(saved) <= partial_message_index:
                saved.append(ModelResponse(parts=[TextPart(partial_text)]))
            safe = self.service.redact(json.loads(ModelMessagesTypeAdapter.dump_json(saved)))
            self.service.store.execute('UPDATE conversations SET messages=? WHERE id=?',
                                       (self.service.store.seal(safe), conversation_id))
            self.service.store.execute('UPDATE chat_runs SET events=?,tool=?,updated=? WHERE id=?',
                                       (self.service.store.seal(events_log), active_tool, time.time(), operation_id))
            last_checkpoint = time.monotonic()

        async def emit(event):
            nonlocal active_tool
            event = self.service.redact(event | {'operation_id': operation_id, 'agent_id': agent_id})
            if event['type'] in {'tool_call', 'tool_result'}:
                events_log.append(event)
                active_tool = event['name'] if event['type'] == 'tool_call' else None
            if event['type'] != 'text' or time.monotonic() - last_checkpoint > 1:
                checkpoint()
            if on_event:
                try:
                    await on_event(event)
                except Exception as exc:
                    # A disconnected browser cannot discard durable activity or stop tracking a mutation.
                    diagnose(exc, operation_id=operation_id, agent_id=agent_id, tool=active_tool)

        async def stream(_context, events):
            nonlocal partial_text, partial_message_index
            async for event in events:
                if isinstance(event, PartStartEvent) and isinstance(event.part, TextPart):
                    partial_text, partial_message_index = event.part.content, len(captured)
                    await emit({'type': 'text', 'text': event.part.content})
                elif isinstance(event, PartDeltaEvent) and isinstance(event.delta, TextPartDelta):
                    partial_text += event.delta.content_delta
                    await emit({'type': 'text', 'text': event.delta.content_delta})
                elif isinstance(event, FunctionToolCallEvent):
                    partial_text = ''
                    started[event.part.tool_call_id] = time.monotonic()
                    args = self.service.redact(event.part.args_as_dict())
                    targets[event.part.tool_call_id] = next((str(args[k])[:80] for k in
                                                            ('command', 'name', 'vm_id', 'agent_id') if args.get(k)), '')
                    await emit({'type': 'tool_call', 'name': event.part.tool_name,
                                'call_id': event.part.tool_call_id, 'target': targets[event.part.tool_call_id],
                                'content': args})
                elif isinstance(event, FunctionToolResultEvent) and event.part is not None:
                    content = self.service.redact(event.part.content)
                    count = len(content) if isinstance(content, list) else next(
                        (len(v) for v in content.values() if isinstance(v, list)), None) if isinstance(content, dict) else None
                    summary = (f'{count} results' if count is not None else
                               'Operation failed' if isinstance(content, dict) and 'error' in content else 'Finished')
                    await emit({'type': 'tool_result', 'name': event.part.tool_name,
                                'call_id': event.part.tool_call_id, 'target': targets.get(event.part.tool_call_id, ''),
                                'summary': summary,
                                'duration': round(time.monotonic() - started.get(event.part.tool_call_id,
                                                                               time.monotonic()), 2),
                                'failed': event.part.part_kind == 'retry-prompt' or isinstance(content, dict) and 'error' in content,
                                'content': str(content)[:16384] if not isinstance(content, dict)
                                else content if len(json.dumps(content, default=str)) <= 16384
                                else {'summary': str(content)[:16384], 'truncated': True}})

        status = 'failed'
        try:
            await emit({'type': 'run_started', 'conversation_id': conversation_id})
            async with self.slots, asyncio.timeout(360):
                budget = {'remaining': 8, 'usage': RunUsage()}
                agent = await self._agent(identity, agent_id, budget, 0, emit)
                with capture_run_messages() as captured:
                    result = await agent.run(prompt, message_history=history, usage=budget['usage'],
                                             event_stream_handler=stream,
                                             usage_limits=UsageLimits(request_limit=20, tool_calls_limit=30))
                    messages = result.all_messages()
                pending = self.service.store.one(
                    "SELECT id FROM provisioning WHERE parent_id=? AND phase<>'complete'", (agent_id,))
                status = 'reconciliation' if pending else 'completed'
                self.service.store.audit(identity['userid'], 'chat', operation_id)
                return {'conversation_id': conversation_id, 'operation_id': operation_id,
                        'status': status, 'output': self.service.redact(result.output)}
        except (Exception, asyncio.CancelledError) as exc:
            pending = self.service.store.one(
                "SELECT id FROM provisioning WHERE parent_id=? AND phase<>'complete'", (agent_id,))
            status = 'reconciliation' if pending else 'interrupted' if isinstance(exc, asyncio.CancelledError) else 'failed'
            error = diagnose(exc, operation_id=operation_id, agent_id=agent_id, tool=active_tool,
                             reconciliation=bool(pending))
            self.service.store.execute('UPDATE chat_runs SET category=? WHERE id=?', (error.category, operation_id))
            self.service.store.audit(identity['userid'], 'chat', operation_id, status)
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise error from None
        finally:
            try:
                checkpoint()
                self.service.store.execute('UPDATE chat_runs SET status=?,updated=? WHERE id=?',
                                           (status, time.time(), operation_id))
            finally:
                self.running.discard(conversation_id)
