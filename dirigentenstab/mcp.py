"""Human-managed remote tools; CloudStack remains the administrative scope boundary."""

import asyncio
import json
import re
import uuid
from urllib.parse import urlsplit

from pydantic_ai.mcp import MCPServerStreamableHTTP

from .limits import APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT, ancestry_reader_id
from .settings import endpoint


# shortcut: portable names leave room for a server prefix; add mapping if a server needs wider MCP names.
TOOL_NAME = re.compile(r'^[A-Za-z0-9_-]{1,48}$')


class MCP:
    def __init__(self, service):
        self.service = service
        self.store = service.store

    async def _can_manage_servers(self, identity):
        if identity.get('_agent_id'):
            return False
        try:
            await self.service.authorize(identity, APP_ROOT_AGENT)
            return True
        except PermissionError:
            return False

    async def _chain(self, agent):
        if agent['id'] in {APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT}:
            return [agent]
        root = await self.service.agent(ancestry_reader_id(self.service, agent))
        # This reader verifies ancestry only; execution uses the acting agent's keys.
        cloud = await self.service.cloud_client(root)
        chain, seen, previous_level = [], set(), None
        domain_id = agent['domain_id']
        while domain_id and len(seen) < 64:
            if domain_id in seen:
                break
            seen.add(domain_id)
            result = await cloud.raw('listDomains', {'id': domain_id, 'listall': True})
            domain = next((d for d in result.get('domain', []) if d.get('id') == domain_id), None)
            if not domain or type(domain.get('level')) is not int or domain['level'] < 0:
                break
            if previous_level is not None and domain['level'] != previous_level - 1:
                break
            member = self.store.one('SELECT * FROM agents WHERE domain_id=? AND enabled=1', (domain_id,))
            if not member:
                break
            chain.append(member)
            if member['id'] in {APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT}:
                return list(reversed(chain))
            previous_level = domain['level']
            domain_id = domain.get('parentdomainid')
        raise PermissionError('Cannot verify every ancestor MCP assignment')

    def _tools(self, agent_id, server_id):
        row = self.store.one('SELECT tools FROM mcp_assignments WHERE agent_id=? AND server_id=?',
                             (agent_id, server_id))
        return set(json.loads(row['tools'])) if row else ({'*'} if agent_id == GLOBAL_ADMIN_AGENT else set())

    def selected_servers(self, agent):
        return set(json.loads(agent['enabled_mcp_servers'])) if agent.get('enabled_mcp_servers') is not None else {
            row['id'] for row in self.store.all('SELECT id FROM mcp_servers')}

    def server_enabled(self, chain, server_id):
        return all(server_id in self.selected_servers(agent) for agent in chain)

    def _effective(self, chain, server_id):
        if not self.server_enabled(chain, server_id):
            return set()
        tools = self._tools(chain[0]['id'], server_id)
        for agent in chain[1:]:
            selected = self._tools(agent['id'], server_id)
            tools = selected if '*' in tools else tools if '*' in selected else tools & selected
        return tools

    async def configuration(self, identity, agent_id):
        agent = await self.service.authorize(identity, agent_id)
        can_manage = await self._can_manage_servers(identity)
        servers = self.store.all('SELECT id,name,url,enabled,version FROM mcp_servers ORDER BY name,id')
        chain = await self._chain(agent) if servers else []
        return {'can_manage_servers': can_manage, 'servers': [
            {**server, 'agent_enabled': server['id'] in self.selected_servers(agent),
             'server_allowed': self.server_enabled(chain[:-1], server['id']),
             'tools': sorted(self._tools(agent_id, server['id'])),
             'allowed_tools': (None if len(chain) == 1 or '*' in self._effective(chain[:-1], server['id'])
                               else sorted(self._effective(chain[:-1], server['id'])))}
            for server in servers]}

    async def save_server(self, identity, name, url, token=None, server_id=None, enabled=True):
        if identity.get('_agent_id'):
            raise PermissionError('MCP endpoint configuration requires a human administrator')
        await self.service.authorize(identity, APP_ROOT_AGENT)
        if not isinstance(name, str) or not name.strip() or len(name) > 100 or not name.isprintable():
            raise ValueError('Use a printable MCP server name of 1–100 characters')
        if not isinstance(url, str) or len(url) > 2048 or any(c.isspace() or ord(c) < 32 for c in url):
            raise ValueError('Use an HTTPS MCP endpoint without whitespace')
        endpoint(url)
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.port == 0:
            raise ValueError('MCP endpoints must use HTTPS')
        if type(enabled) is not bool:
            raise ValueError('Invalid MCP server enabled flag')
        if token is not None and (not isinstance(token, str) or token and not 8 <= len(token) <= 4096
                                  or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError('Use a bearer credential without whitespace or control characters')
        existing = self.store.one('SELECT token FROM mcp_servers WHERE id=?', (server_id,)) if server_id else None
        if server_id and not existing:
            raise ValueError('MCP server is unavailable')
        encrypted = existing['token'] if existing and token is None else self.store.seal(token or '')
        secret = self.store.open(encrypted)
        self.service._remember(secret)
        if secret:
            self.service._remember('Bearer ' + secret)
        server_id = server_id or str(uuid.uuid4())
        async with self.service.configuration_change([row['id'] for row in self.store.all('SELECT id FROM agents')]):
            self.store.execute('INSERT INTO mcp_servers(id,name,url,token,enabled) VALUES(?,?,?,?,?) '
                               'ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,'
                               'token=excluded.token,enabled=excluded.enabled,version=mcp_servers.version+1',
                               (server_id, name.strip(), url, encrypted, enabled))
        self.store.audit(identity['userid'], 'configure-mcp-server', server_id)
        return server_id

    async def discover(self, identity, agent_id, server_id):
        agent = await self.service.authorize(identity, agent_id)
        server = self.store.one('SELECT * FROM mcp_servers WHERE id=? AND enabled=1', (server_id,))
        if not server:
            raise ValueError('MCP server is unavailable')
        chain = await self._chain(agent)
        ceiling = self._effective(chain[:-1], server_id) if len(chain) > 1 else None
        if ceiling == set():
            return []
        token = self.store.open(server['token'])
        try:
            async with asyncio.timeout(30), MCPServerStreamableHTTP(
                server['url'], headers={'Authorization': 'Bearer ' + token} if token else {},
                allow_sampling=False, include_instructions=False, max_retries=0,
                timeout=10, read_timeout=60,
            ) as remote:
                catalogue = await remote.list_tools()
        except Exception:
            raise RuntimeError('MCP tool discovery failed; check the endpoint and credentials') from None
        if len(catalogue) > 1000:
            raise ValueError('MCP tool catalogue exceeds the size limit')
        agent = await self.service.authorize(identity, agent_id)
        current = self.store.one('SELECT version FROM mcp_servers WHERE id=? AND enabled=1', (server_id,))
        if not current or current['version'] != server['version']:
            raise PermissionError('MCP tool assignment or server configuration changed')
        chain = await self._chain(agent)
        ceiling = self._effective(chain[:-1], server_id) if len(chain) > 1 else None
        tools = {tool.name: {'name': tool.name, 'description': self.service.redact(tool.description or '')[:1000]}
                 for tool in catalogue if TOOL_NAME.fullmatch(tool.name)
                 and self.service.redact(tool.name) == tool.name
                 and (ceiling is None or '*' in ceiling or tool.name in ceiling)}
        self.store.audit(identity['userid'], 'discover-mcp-tools', agent_id + '/' + server_id)
        return [tools[name] for name in sorted(tools)]

    async def validate_assignment(self, identity, agent_id, server_id, tools):
        agent = await self.service.authorize(identity, agent_id)
        if (not isinstance(tools, list) or len(tools) > 100
                or any(not isinstance(name, str) or not TOOL_NAME.fullmatch(name) for name in tools)):
            raise ValueError('Assign at most 100 exact MCP tool names')
        if not self.store.one('SELECT id FROM mcp_servers WHERE id=?', (server_id,)):
            raise ValueError('MCP server is unavailable')
        chain = await self._chain(agent)
        if (len(chain) > 1 and '*' not in self._effective(chain[:-1], server_id)
                and not set(tools) - self._tools(agent_id, server_id) <= self._effective(chain[:-1], server_id)):
            raise PermissionError('MCP assignments cannot widen ancestor access')
        if identity.get('_agent_id'):
            actor_id = identity['_agent_id']
            if actor_id == agent_id or (actor_id != GLOBAL_ADMIN_AGENT and actor_id not in {member['id'] for member in chain[:-1]}):
                raise PermissionError('Only an ancestor agent may change enabled MCP tools')
            actor_chain = await self._chain(await self.service.agent(actor_id))
            if ('*' not in self._effective(actor_chain, server_id)
                    and not set(tools) - self._tools(agent_id, server_id) <= self._effective(actor_chain, server_id)):
                raise PermissionError('MCP assignments cannot widen actor access')

    async def assign(self, identity, agent_id, server_id, tools):
        await self.validate_assignment(identity, agent_id, server_id, tools)
        async with self.service.configuration_change(await self.service.affected_agents(agent_id)):
            self.store.execute('INSERT INTO mcp_assignments VALUES(?,?,?) '
                               'ON CONFLICT(agent_id,server_id) DO UPDATE SET tools=excluded.tools',
                               (agent_id, server_id, json.dumps(sorted(set(tools)))))
        self.store.audit(identity['userid'], 'assign-mcp-tools', agent_id + '/' + server_id)

    async def set_enabled(self, identity, agent_id, server_id, enabled):
        if type(enabled) is not bool:
            raise ValueError('Invalid MCP enabled flag')
        agent = await self.service.authorize(identity, agent_id)
        chain = await self._chain(agent)
        if not self.store.one('SELECT id FROM mcp_servers WHERE id=?', (server_id,)):
            raise ValueError('MCP server is unavailable')
        actor_id = identity.get('_agent_id')
        if actor_id and (actor_id == agent_id or (actor_id != GLOBAL_ADMIN_AGENT and actor_id not in {member['id'] for member in chain[:-1]})):
            raise PermissionError('Only an ancestor agent may change enabled MCP servers')
        selected = self.selected_servers(agent)
        if enabled and server_id not in selected:
            if not self.server_enabled(chain[:-1], server_id):
                raise PermissionError('MCP selections cannot widen ancestor access')
            if actor_id and not self.server_enabled(await self._chain(await self.service.agent(actor_id)), server_id):
                raise PermissionError('MCP selections cannot widen actor access')
        if enabled:
            selected.add(server_id)
        else:
            selected.discard(server_id)
        async with self.service.configuration_change(await self.service.affected_agents(agent_id)):
            self.store.execute('UPDATE agents SET enabled_mcp_servers=? WHERE id=?', (json.dumps(sorted(selected)), agent_id))
        self.store.audit(identity['userid'], 'enable-mcp-server' if enabled else 'disable-mcp-server', agent_id + '/' + server_id)

    async def bindings(self, identity, agent_id):
        agent = await self.service.authorize(identity, agent_id)
        servers = self.store.all('SELECT * FROM mcp_servers WHERE enabled=1 ORDER BY id')
        if not servers:
            return []
        chain = await self._chain(agent)
        return [{**server, 'tools': sorted(tools)} for server in servers
                if (tools := self._effective(chain, server['id']))]

    async def check(self, identity, agent_id, server_id, tool, version):
        server = next((row for row in await self.bindings(identity, agent_id) if row['id'] == server_id), None)
        if (not server or not TOOL_NAME.fullmatch(tool) or
                '*' not in server['tools'] and tool not in server['tools'] or server['version'] != version):
            raise PermissionError('MCP tool assignment or server configuration changed')
        return server
