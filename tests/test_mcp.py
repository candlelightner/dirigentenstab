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
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning) '
                      'VALUES(?,?,?,?,?,?,?)',
                      (agent_id, agent_id, domain_id, 'account', 'user', store.seal({}), store.seal({})))
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
    with pytest.raises(PermissionError, match='cannot widen'):
        await e.mcp.assign(e.child, 'middle-agent', server, ['search'])


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
    e.store.execute('DROP TABLE mcp_assignments')
    e.store.execute('DROP TABLE mcp_servers')
    e.store.execute('PRAGMA user_version=10')
    store = Store(str(e.store.path), str(e.key))
    assert len(store.all('SELECT id FROM agents')) == 4
    assert store.all('SELECT * FROM mcp_servers') == []
    assert store.one('PRAGMA user_version')['user_version'] == 11


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
