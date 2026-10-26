import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.limits import APP_ROOT_AGENT
from dirigentenstab.mcp import MCP
from dirigentenstab.service import Service
from dirigentenstab.store import Store


@pytest.fixture
def environment(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for agent_id, domain_id in [(APP_ROOT_AGENT, 'main'), ('middle-agent', 'middle'),
                                ('leaf-agent', 'leaf'), ('other-agent', 'other')]:
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) '
                      'VALUES(?,?,?,?,?,?)',
                      (agent_id, agent_id, domain_id, 'account', 'user', store.seal({})))
    domains = {
        'main': {'id': 'main', 'level': 1, 'parentdomainid': 'native-root'},
        'middle': {'id': 'middle', 'level': 2, 'parentdomainid': 'main'},
        'leaf': {'id': 'leaf', 'level': 3, 'parentdomainid': 'middle'},
        'other': {'id': 'other', 'level': 1, 'parentdomainid': 'native-root'},
    }
    service = Service(store, SimpleNamespace())

    async def human_call(identity, command, params):
        assert command == 'listDomains'
        domain_id = params['id']
        return {'domain': [domains[domain_id]] if domain_id in identity['domains'] and domain_id in domains else []}

    class Cloud:
        async def raw(self, command, params):
            assert command == 'listDomains'
            domain = domains.get(params['id'])
            return {'domain': [domain] if domain else []}

    async def cloud_client(agent):
        assert agent['id'] == APP_ROOT_AGENT
        return Cloud()

    service.human_call, service.cloud_client = human_call, cloud_client
    return SimpleNamespace(store=store, service=service, mcp=MCP(service), domains=domains,
                           root={'userid': 'human-root', 'type': 1, 'domains': set(domains)},
                           child={'userid': 'human-child', 'type': 2, 'domains': {'middle', 'leaf'}},
                           key=key)


async def configured(environment):
    e = environment
    server = await e.mcp.save_server(e.root, 'Search', 'https://search.example/mcp', 'private-bearer-token')
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['search', 'fetch'])
    await e.mcp.assign(e.child, 'middle-agent', server, ['search'])
    await e.mcp.assign(e.child, 'leaf-agent', server, ['search'])
    return server


async def test_explicit_assignments_inherit_only_narrower_access(environment):
    e = environment
    server = await e.mcp.save_server(e.root, 'Search', 'https://search.example/mcp')
    assert await e.mcp.bindings(e.root, APP_ROOT_AGENT) == []
    with pytest.raises(PermissionError, match='cannot widen'):
        await e.mcp.assign(e.child, 'middle-agent', server, ['search'])
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['search', 'fetch'])
    assert await e.mcp.bindings(e.child, 'middle-agent') == []
    await e.mcp.assign(e.child, 'middle-agent', server, ['search'])
    with pytest.raises(PermissionError, match='cannot widen'):
        await e.mcp.assign(e.root, 'leaf-agent', server, ['fetch'])
    await e.mcp.assign(e.child, 'leaf-agent', server, ['search'])
    bindings = await e.mcp.bindings(e.child, 'leaf-agent')
    assert len(bindings) == 1 and bindings[0]['tools'] == ['search']
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, [])
    assert await e.mcp.bindings(e.child, 'leaf-agent') == []
    await e.mcp.assign(e.child, 'middle-agent', server, ['search'])
    assert await e.mcp.bindings(e.child, 'leaf-agent') == []


async def test_server_registration_and_configuration_are_human_domain_scoped(environment):
    e = environment
    server = await configured(e)
    for kwargs in ({}, {'server_id': server}):
        with pytest.raises(PermissionError, match='outside'):
            await e.mcp.save_server(e.child, 'Escape', 'https://escape.example/mcp', **kwargs)
    with pytest.raises(PermissionError, match='outside'):
        await e.mcp.assign(e.child, APP_ROOT_AGENT, server, [])
    with pytest.raises(PermissionError, match='outside'):
        await e.mcp.configuration(e.child, 'other-agent')
    with pytest.raises(PermissionError, match='outside'):
        await e.mcp.bindings(e.child, 'other-agent')
    with pytest.raises(PermissionError, match='administrator'):
        await e.mcp.configuration({**e.root, 'type': 0}, APP_ROOT_AGENT)
    config = await e.mcp.configuration(e.child, 'leaf-agent')
    assert config['can_manage_servers'] is False
    assert config['servers'][0]['tools'] == ['search']
    assert config['servers'][0]['allowed_tools'] == ['search']
    assert 'token' not in json.dumps(config)
    root_config = await e.mcp.configuration(e.root, APP_ROOT_AGENT)
    assert root_config['can_manage_servers'] is True
    assert root_config['servers'][0]['allowed_tools'] is None


async def test_dispatch_revalidates_grants_configuration_and_disabled_state(environment):
    e = environment
    server = await configured(e)
    binding = (await e.mcp.bindings(e.child, 'leaf-agent'))[0]
    version = binding['version']
    assert (await e.mcp.check(e.child, 'leaf-agent', server, 'search', version))['id'] == server
    for tool in ('fetch', '*', 'search_api', ''):
        with pytest.raises(PermissionError):
            await e.mcp.check(e.child, 'leaf-agent', server, tool, version)
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, [])
    with pytest.raises(PermissionError):
        await e.mcp.check(e.child, 'leaf-agent', server, 'search', version)
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['search'])
    await e.mcp.save_server(e.root, 'New endpoint', 'https://new.example/mcp', server_id=server)
    with pytest.raises(PermissionError):
        await e.mcp.check(e.child, 'leaf-agent', server, 'search', version)
    current = (await e.mcp.bindings(e.child, 'leaf-agent'))[0]
    assert current['version'] > version
    await e.mcp.save_server(e.root, 'Disabled', 'https://new.example/mcp', server_id=server, enabled=False)
    assert await e.mcp.bindings(e.child, 'leaf-agent') == []
    with pytest.raises(PermissionError):
        await e.mcp.check(e.child, 'leaf-agent', server, 'search', current['version'])


async def test_credentials_stay_encrypted_and_redacted_after_restart(environment):
    e = environment
    server = await configured(e)
    row = e.store.one('SELECT * FROM mcp_servers WHERE id=?', (server,))
    assert b'private-bearer-token' not in row['token']
    assert e.store.open(row['token']) == 'private-bearer-token'
    assert 'private-bearer-token' not in e.service.redact('Bearer private-bearer-token')
    restarted = Service(Store(str(e.store.path), str(e.key)), SimpleNamespace())
    assert restarted.redact({'output': 'private-bearer-token'}) == {'output': '[redacted]'}
    await e.mcp.save_server(e.root, 'Search renamed', row['url'], server_id=server)
    assert e.store.open(e.store.one('SELECT token FROM mcp_servers WHERE id=?', (server,))['token']) == 'private-bearer-token'
    await e.mcp.save_server(e.root, 'Search renamed', row['url'], token='', server_id=server)
    assert e.store.open(e.store.one('SELECT token FROM mcp_servers WHERE id=?', (server,))['token']) == ''
    audit = e.store.all('SELECT * FROM audit')
    assert 'private-bearer-token' not in str(audit)


@pytest.mark.parametrize('url', ['http://example.com/mcp', 'stdio://command', 'file:///secret',
                                'https://user:password@example.com/mcp', 'https://example.com/mcp?key=secret',
                                'https://example.com/mcp#fragment', 'https://example.com/\nmcp',
                                'https://example.com/ mcp', 'https://example.com:0/mcp',
                                'https://example.com:bad/mcp', 'https://example.com:65536/mcp'])
async def test_invalid_endpoints_are_rejected(environment, url):
    with pytest.raises(ValueError):
        await environment.mcp.save_server(environment.root, 'Invalid', url)
    assert environment.store.all('SELECT * FROM mcp_servers') == []


@pytest.mark.parametrize('token', ['short', 'secret\r\nHeader: value', 'nonascii-ä-token', 'x' * 4097, 123])
async def test_invalid_bearer_credentials_are_rejected(environment, token):
    with pytest.raises(ValueError):
        await environment.mcp.save_server(environment.root, 'Invalid', 'https://example.com/mcp', token)


@pytest.mark.parametrize('tools', ['search', ['*'], ['search.*'], ['search api'], ['x' * 49], [None],
                                  ['search'] * 101])
async def test_invalid_assignments_are_rejected(environment, tools):
    e = environment
    server = await e.mcp.save_server(e.root, 'Search', 'https://example.com/mcp')
    with pytest.raises(ValueError):
        await e.mcp.assign(e.root, APP_ROOT_AGENT, server, tools)


@pytest.mark.parametrize('damage', ['missing-domain', 'missing-agent', 'disabled-agent', 'cycle', 'wrong-level',
                                   'outside-root'])
async def test_unverifiable_ancestors_fail_closed(environment, damage):
    e = environment
    await configured(e)
    if damage == 'missing-domain':
        del e.domains['middle']
    elif damage == 'missing-agent':
        e.store.execute('DELETE FROM mcp_assignments WHERE agent_id=?', ('middle-agent',))
        e.store.execute('DELETE FROM agents WHERE id=?', ('middle-agent',))
    elif damage == 'disabled-agent':
        e.store.execute('UPDATE agents SET enabled=0 WHERE id=?', ('middle-agent',))
    elif damage == 'cycle':
        e.domains['middle']['parentdomainid'] = 'leaf'
    elif damage == 'wrong-level':
        e.domains['middle']['level'] = 30
    else:
        e.domains['middle']['parentdomainid'] = 'other'
    with pytest.raises(PermissionError, match='ancestor'):
        await e.mcp.bindings(e.child, 'leaf-agent')


async def test_empty_registry_does_not_require_hierarchy_reader(environment):
    e = environment
    del e.domains['main']
    assert await e.mcp.bindings(e.child, 'leaf-agent') == []


def test_migration_preserves_existing_agents(environment):
    e = environment
    original = {row['id']: row['credentials'] for row in e.store.all('SELECT id,credentials FROM agents')}
    old_provisioning = e.store.seal({'id': 'legacy-provisioning-key'})
    e.store.execute('DROP TABLE mcp_assignments')
    e.store.execute('DROP TABLE mcp_servers')
    e.store.execute('DROP TABLE legacy_agent_credentials')
    e.store.execute('ALTER TABLE agents RENAME COLUMN credentials TO runtime')
    e.store.execute('ALTER TABLE agents ADD COLUMN provisioning BLOB')
    e.store.execute('UPDATE agents SET provisioning=?', (old_provisioning,))
    e.store.execute('DROP TABLE conversation_compactions')
    for column in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window'):
        e.store.execute('ALTER TABLE agents DROP COLUMN ' + column)
    e.store.execute('ALTER TABLE agents DROP COLUMN thinking')
    e.store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    e.store.execute('ALTER TABLE agents DROP COLUMN enabled_providers')
    e.store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    e.store.execute('PRAGMA user_version=10')
    store = Store(str(e.store.path), str(e.key))
    assert {row['id']: row['credentials'] for row in store.all('SELECT id,credentials FROM agents')} == original
    assert {row['agent_id'] for row in store.all('SELECT agent_id FROM legacy_agent_credentials')} == original.keys()
    assert all(row['credentials'] == old_provisioning for row in store.all('SELECT credentials FROM legacy_agent_credentials'))
    assert store.all('SELECT * FROM mcp_servers') == []
    assert store.one('PRAGMA user_version')['user_version'] == 16
    assert all(row['owner_ssh_key_enabled'] == 1 for row in store.all('SELECT * FROM agents'))


@pytest.mark.parametrize('url', ['https://mcp.tavily.com/mcp', 'https://mcp.tavily.com/mcp/'])
async def test_tavily_api_key_uses_existing_encrypted_bearer_configuration(environment, url):
    e = environment
    api_key = 'tvly-dev-synthetic-key-for-tests-only'
    server = await e.mcp.save_server(e.root, 'Tavily', url, api_key)
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['tavily_search'])
    await e.mcp.assign(e.child, 'middle-agent', server, ['tavily_search'])
    binding = (await e.mcp.bindings(e.child, 'middle-agent'))[0]
    assert binding['url'] == url
    assert binding['tools'] == ['tavily_search']
    assert e.store.open(binding['token']) == api_key
    assert api_key.encode() not in binding['token']
    assert api_key not in json.dumps(await e.mcp.configuration(e.child, 'middle-agent'))
    assert api_key not in e.service.redact('Authorization: Bearer ' + api_key)
    with pytest.raises(PermissionError):
        await e.mcp.check(e.child, 'middle-agent', server, 'tavily_extract', binding['version'])


@pytest.fixture
def remote_catalogue(monkeypatch):
    from dirigentenstab import mcp as mcp_module

    state = SimpleNamespace(connections=[], on_list=None, tools=[
        SimpleNamespace(name='tavily_search', description='Search the web'),
        SimpleNamespace(name='tavily_extract', description='Read a web page')])

    class Remote:
        def __init__(self, url, **kwargs):
            state.connections.append({'url': url, **kwargs})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def list_tools(self):
            if state.on_list:
                await state.on_list()
            return state.tools

        async def direct_call_tool(self, *args):
            pytest.fail('Discovery must never invoke an MCP tool')

    monkeypatch.setattr(mcp_module, 'MCPServerStreamableHTTP', Remote)
    return state


async def test_discovery_bootstraps_main_agent_without_assigning_tools(environment, remote_catalogue):
    e = environment
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/', 'tvly-synthetic-secret')
    tools = await e.mcp.discover(e.root, APP_ROOT_AGENT, server)
    assert [t['name'] for t in tools] == ['tavily_extract', 'tavily_search']
    assert e.store.all('SELECT * FROM mcp_assignments') == []
    assert remote_catalogue.connections == [{
        'url': 'https://mcp.tavily.com/mcp/', 'headers': {'Authorization': 'Bearer tvly-synthetic-secret'},
        'allow_sampling': False, 'include_instructions': False, 'max_retries': 0, 'timeout': 10, 'read_timeout': 60}]
    assert 'tvly-synthetic-secret' not in json.dumps(tools)


async def test_discovery_filters_to_parent_ceiling_without_requiring_own_assignment(environment, remote_catalogue):
    e = environment
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/')
    assert await e.mcp.discover(e.child, 'middle-agent', server) == []
    assert remote_catalogue.connections == []
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['tavily_search'])
    assert await e.mcp.discover(e.child, 'middle-agent', server) == [
        {'name': 'tavily_search', 'description': 'Search the web'}]
    assert remote_catalogue.connections[0]['headers'] == {}
    assert e.store.one('SELECT * FROM mcp_assignments WHERE agent_id=?', ('middle-agent',)) is None


async def test_discovery_enforces_human_scope_and_enabled_server(environment, remote_catalogue):
    e = environment
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/')
    with pytest.raises(PermissionError):
        await e.mcp.discover(e.child, APP_ROOT_AGENT, server)
    with pytest.raises(ValueError, match='unavailable'):
        await e.mcp.discover(e.root, APP_ROOT_AGENT, 'missing-server')
    await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/', server_id=server, enabled=False)
    with pytest.raises(ValueError, match='unavailable'):
        await e.mcp.discover(e.root, APP_ROOT_AGENT, server)
    assert remote_catalogue.connections == []


async def test_discovery_rechecks_parent_revocation_after_network(environment, remote_catalogue):
    e = environment
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/')
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['tavily_search'])
    await e.mcp.assign(e.child, 'middle-agent', server, ['tavily_search'])

    async def revoke():
        await e.mcp.assign(e.root, APP_ROOT_AGENT, server, [])

    remote_catalogue.on_list = revoke
    assert await e.mcp.discover(e.child, 'leaf-agent', server) == []


@pytest.mark.parametrize('change', ['disable', 'version', 'identity', 'ancestry'])
async def test_discovery_revalidates_after_network(environment, remote_catalogue, change):
    e = environment
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/')
    await e.mcp.assign(e.root, APP_ROOT_AGENT, server, ['tavily_search'])

    async def alter():
        if change == 'disable':
            await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/', server_id=server, enabled=False)
        elif change == 'version':
            await e.mcp.save_server(e.root, 'Tavily', 'https://other.example/mcp', server_id=server)
        elif change == 'identity':
            e.child['domains'].remove('middle')
        else:
            del e.domains['main']

    remote_catalogue.on_list = alter
    with pytest.raises(PermissionError):
        await e.mcp.discover(e.child, 'middle-agent', server)


async def test_discovery_redacts_descriptions_and_filters_nonportable_names(environment, remote_catalogue):
    e = environment
    secret = 'tvly-synthetic-secret'
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/', secret)
    remote_catalogue.tools = [SimpleNamespace(name='tavily_search', description=secret + 'x' * 2000),
                              SimpleNamespace(name=secret, description='Do not expose credentials as names'),
                              SimpleNamespace(name='bad.tool.name', description='No mapping'),
                              SimpleNamespace(name='*', description='No wildcard'),
                              SimpleNamespace(name='z' * 49, description='Too long'),
                              SimpleNamespace(name='tavily_extract', description=None)]
    tools = await e.mcp.discover(e.root, APP_ROOT_AGENT, server)
    assert [t['name'] for t in tools] == ['tavily_extract', 'tavily_search']
    assert tools[0]['description'] == ''
    assert len(tools[1]['description']) == 1000
    assert secret not in str(tools)


@pytest.mark.parametrize('failure', ['authentication', 'timeout'])
async def test_discovery_failures_hide_endpoint_credentials_and_remote_payload(environment, remote_catalogue, failure):
    e = environment
    secret = 'tvly-synthetic-secret'
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/', secret)

    async def fail():
        if failure == 'authentication':
            raise RuntimeError('Remote rejected credential ' + secret)
        if failure == 'timeout':
            raise TimeoutError('Remote echoed ' + secret)

    remote_catalogue.on_list = fail
    with pytest.raises(RuntimeError, match='MCP tool discovery failed; check the endpoint and credentials') as error:
        await e.mcp.discover(e.root, APP_ROOT_AGENT, server)
    assert secret not in str(error.value)
    assert e.store.all('SELECT * FROM mcp_assignments') == []


async def test_discovery_rejects_oversized_catalogue_without_silent_truncation(environment, remote_catalogue):
    e = environment
    server = await e.mcp.save_server(e.root, 'Tavily', 'https://mcp.tavily.com/mcp/')
    remote_catalogue.tools = [SimpleNamespace(name='tavily_search', description='Search')] * 1001
    with pytest.raises(ValueError, match='MCP tool catalogue exceeds the size limit'):
        await e.mcp.discover(e.root, APP_ROOT_AGENT, server)
    assert e.store.all('SELECT * FROM mcp_assignments') == []


def native_actor_clients(e):
    """Native scope for accepted agent work; browser sessions are deliberately absent."""
    revoked = set()
    class Native:
        def __init__(self, agent):
            self.agent = agent
        async def raw(self, command, params):
            if self.agent['id'] in revoked:
                raise PermissionError('Native credential revoked')
            assert command == 'listDomains'
            visible = {self.agent['domain_id']}
            while children := {d['id'] for d in e.domains.values() if d.get('parentdomainid') in visible} - visible:
                visible |= children
            return {'domain': [d for d in e.domains.values() if d['id'] in visible
                               and (not params.get('id') or d['id'] == params['id'])]}
    async def client(agent):
        return Native(agent)
    e.service.cloud_client = client
    return revoked


async def test_provider_and_compaction_access_is_inherited_and_preserves_stored_selections(environment):
    e = environment
    native_actor_clients(e)
    for name in ('main-provider', 'summary-provider'):
        await e.service.save_provider(e.root, name, 'chat', 'http://localhost/v1', 'secret', provider_id=name)
    await e.service.update_agent(e.root, APP_ROOT_AGENT, 'main-provider', 'main-model', '',
                                 enabled_providers=['main-provider', 'summary-provider'])
    await e.service.update_agent(e.root, 'middle-agent', 'main-provider', 'main-model', '',
                                 enabled_providers=['main-provider', 'summary-provider'])
    await e.service.update_agent(e.root, 'leaf-agent', 'main-provider', 'main-model', '',
                                 compaction_provider_id='summary-provider', compaction_model='summary',
                                 auto_compact_percent=80, enabled_providers=['main-provider', 'summary-provider'])
    actor = await e.service.execution_identity('leaf-agent', 'human-root')
    assert {p['id'] for p in await e.service.providers(actor)} == {'main-provider', 'summary-provider'}
    await e.service.update_agent(e.root, APP_ROOT_AGENT, 'main-provider', 'main-model', '', enabled_providers=[])
    assert await e.service.providers(actor) == []
    # Saving an unchanged selection while its ancestor disables access retains that selection.
    await e.service.update_agent(e.root, 'leaf-agent', 'main-provider', 'main-model', 'Updated prompt',
                                 enabled_providers=['main-provider', 'summary-provider'])
    assert e.service.selected_providers(await e.service.agent('leaf-agent')) == {'main-provider', 'summary-provider'}
    await e.service.update_agent(e.root, APP_ROOT_AGENT, 'main-provider', 'main-model', '',
                                 enabled_providers=['main-provider', 'summary-provider'])
    assert {p['id'] for p in await e.service.providers(actor)} == {'main-provider', 'summary-provider'}


async def test_agent_configuration_enforces_self_parent_and_central_authority(environment):
    e = environment
    revoked = native_actor_clients(e)
    await e.service.save_provider(e.root, 'Local', 'chat', 'http://localhost/v1', '', provider_id='local')
    await e.service.configure_agent('middle-agent', 'middle-agent', {'instructions': 'Self-edited prompt'})
    assert (await e.service.agent('middle-agent'))['instructions'] == 'Self-edited prompt'
    for settings in ({'model': 'new-model'}, {'enabled_providers': []}, {'enabled_mcp_servers': []}, {'thinking': 'high'}):
        with pytest.raises(PermissionError, match='own system prompt'):
            await e.service.configure_agent('middle-agent', 'middle-agent', settings)
    await e.service.configure_agent('middle-agent', 'leaf-agent', {'provider_id': 'local', 'model': 'local-model'})
    assert (await e.service.agent('leaf-agent'))['model'] == 'local-model'
    actor = await e.service.execution_identity(APP_ROOT_AGENT, 'human-root')
    with pytest.raises(PermissionError):
        await e.service.save_provider(actor, 'Secret', 'chat', 'http://localhost/v1', 'credential')
    with pytest.raises(PermissionError):
        await e.mcp.save_server(actor, 'Secret', 'https://localhost/mcp', 'credential')
    with pytest.raises(PermissionError):
        await e.service.configure_agent('leaf-agent', 'middle-agent', {'instructions': 'Escape'})
    revoked.add('leaf-agent')
    with pytest.raises(PermissionError, match='revoked'):
        await e.service.execution_identity('leaf-agent', 'human-root')


async def test_agent_server_toggle_retains_tools_and_descendant_selections(environment):
    e = environment
    native_actor_clients(e)
    server = await configured(e)
    await e.mcp.set_enabled(e.root, APP_ROOT_AGENT, server, False)
    assert await e.mcp.bindings(e.child, 'leaf-agent') == []
    config = await e.mcp.configuration(e.child, 'leaf-agent')
    assert config['servers'][0]['tools'] == ['search']
    assert config['servers'][0]['agent_enabled'] is True
    assert config['servers'][0]['server_allowed'] is False
    await e.mcp.set_enabled(e.root, APP_ROOT_AGENT, server, True)
    assert (await e.mcp.bindings(e.child, 'leaf-agent'))[0]['tools'] == ['search']
    actor = await e.service.execution_identity('middle-agent', 'human-root')
    with pytest.raises(PermissionError, match='ancestor'):
        await e.mcp.set_enabled(actor, 'middle-agent', server, False)
    await e.mcp.set_enabled(actor, 'leaf-agent', server, False)
    assert e.mcp._tools('leaf-agent', server) == {'search'}
    await e.mcp.set_enabled(actor, 'leaf-agent', server, True)
    assert (await e.mcp.bindings(e.child, 'leaf-agent'))[0]['tools'] == ['search']


async def test_inherited_changes_pause_current_native_descendants_only(environment):
    e = environment
    native_actor_clients(e)
    calls = []
    class Runtime:
        async def pause_agents(self, ids):
            calls.append(('pause', set(ids)))
        async def resume_agents(self, ids):
            calls.append(('resume', set(ids)))
    e.service.runtime = Runtime()
    # The native hierarchy can change independently of the hub's provisioning history.
    e.domains['leaf']['parentdomainid'] = 'other'
    e.domains['leaf']['level'] = 2
    await e.service.update_agent(e.root, APP_ROOT_AGENT, None, '', 'New prompt', enabled_providers=[])
    assert calls == [('pause', {APP_ROOT_AGENT, 'middle-agent'}), ('resume', {APP_ROOT_AGENT, 'middle-agent'})]


async def test_agent_can_inspect_own_and_descendant_settings_without_exposing_credentials(environment):
    e = environment
    native_actor_clients(e)
    server = await configured(e)
    await e.service.save_provider(e.root, 'Local', 'chat', 'http://localhost/v1', 'provider-secret',
                                  default_model='local-default', provider_id='local')
    own = await e.service.configure_agent('middle-agent', 'middle-agent')
    child = await e.service.configure_agent('middle-agent', 'leaf-agent')
    assert own['agent']['id'] == 'middle-agent' and child['agent']['id'] == 'leaf-agent'
    assert child['providers'][0]['id'] == 'local' and child['providers'][0]['default_model'] == 'local-default'
    assert child['mcp_servers'][0]['id'] == server and child['mcp_servers'][0]['tools'] == ['search']
    assert not any(secret in json.dumps(child) for secret in ('private-bearer-token', 'provider-secret', 'credentials', 'api_key'))
    with pytest.raises(PermissionError):
        await e.service.configure_agent('leaf-agent', 'middle-agent')


async def test_owner_public_key_visibility_defaults_on_inherits_denial_and_requires_parent_configuration(environment):
    import asyncssh

    e = environment
    native_actor_clients(e)
    key = asyncssh.generate_private_key('ssh-ed25519')
    public = key.export_public_key().decode().strip()
    await e.service.save_owner_ssh_key(e.root, public)
    assert all(row['owner_ssh_key_enabled'] == 1 for row in e.store.all('SELECT * FROM agents'))
    own = await e.service.configure_agent('leaf-agent', 'leaf-agent')
    assert own['owner_ssh_public_key'] == public
    assert own['owner_ssh_key_access'] == {'selected': True, 'allowed': True, 'enabled': True}
    assert key.export_private_key().decode() not in json.dumps(own)

    await e.service.update_agent(e.root, 'middle-agent', None, '', '', owner_ssh_key_enabled=False)
    denied = await e.service.configure_agent('leaf-agent', 'leaf-agent')
    assert denied['owner_ssh_public_key'] is None
    assert public not in json.dumps(denied)
    assert denied['owner_ssh_key_access'] == {'selected': True, 'allowed': False, 'enabled': False}
    # Saving other settings retains the child's selection without overriding inherited denial.
    await e.service.update_agent(e.root, 'leaf-agent', None, '', 'Updated prompt')
    assert (await e.service.agent('leaf-agent'))['owner_ssh_key_enabled'] == 1
    with pytest.raises(PermissionError, match='ancestor access'):
        await e.service.update_agent(e.root, 'leaf-agent', None, '', '', owner_ssh_key_enabled=True)
    with pytest.raises(PermissionError, match='ancestor access'):
        await e.service.configure_agent('middle-agent', 'leaf-agent', {'owner_ssh_key_enabled': True})
    for enabled in (False, True):
        with pytest.raises(PermissionError, match='own system prompt'):
            await e.service.configure_agent('leaf-agent', 'leaf-agent', {'owner_ssh_key_enabled': enabled})
    with pytest.raises(PermissionError):
        await e.service.configure_agent('other-agent', 'leaf-agent', {'owner_ssh_key_enabled': False})
    with pytest.raises(ValueError, match='boolean'):
        await e.service.update_agent(e.root, 'leaf-agent', None, '', '', owner_ssh_key_enabled='yes')

    await e.service.update_agent(e.root, 'middle-agent', None, '', '', owner_ssh_key_enabled=True)
    assert (await e.service.configure_agent('leaf-agent', 'leaf-agent'))['owner_ssh_public_key'] == public
    await e.service.configure_agent('middle-agent', 'leaf-agent', {'owner_ssh_key_enabled': False})
    assert (await e.service.configure_agent('leaf-agent', 'leaf-agent'))['owner_ssh_public_key'] is None
    await e.service.configure_agent('middle-agent', 'leaf-agent', {'owner_ssh_key_enabled': True})
    assert (await e.service.configure_agent('middle-agent', 'leaf-agent'))['owner_ssh_public_key'] == public
