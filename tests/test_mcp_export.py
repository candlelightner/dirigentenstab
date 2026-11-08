import json
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet
from starlette.applications import Starlette
from starlette.routing import Route

from dirigentenstab import mcp_export
from dirigentenstab.guest import Guest
from dirigentenstab.limits import GLOBAL_ADMIN_AGENT
from dirigentenstab.mcp_export import Exports
from dirigentenstab.runtime import CURRENT_RUN, Runtime
from dirigentenstab.service import Service
from dirigentenstab.store import Store

OWNER = {'userid': 'owner', 'type': 1}
HEADERS = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}


@pytest.fixture
async def e(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for agent_id in ('parent', 'child', 'other', GLOBAL_ADMIN_AGENT):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,escalation_requests_enabled) '
                      'VALUES(?,?,?,?,?,?,1)', (agent_id, agent_id, agent_id + '-d', 'a', 'u', store.seal({})))
    service = Service(store, SimpleNamespace(origin='https://hub.example', max_output=4096))
    calls = []

    async def chain(agent):
        return [await service.agent('parent'), agent] if agent['id'] == 'child' else [agent]

    async def authorize(identity, agent_id, **kwargs):
        if identity.get('type') == 2 and not identity.get('_agent_id') and agent_id == 'other':
            raise PermissionError('outside your domain')
        return await service.agent(agent_id)

    async def execute(agent_id, command, params, **kwargs):
        calls.append((agent_id, command, params))
        return {'success': True, 'secret': 'dsk-in-output'} if command == 'createTags' else {'ok': command}

    async def search_api(agent_id, query):
        return {'query': query, 'agent': agent_id}

    service.agent_chain, service.authorize = chain, authorize
    service.execute, service.search_api = execute, search_api
    runtime = Runtime(service)
    exports = Exports(service, runtime)
    await exports.start()
    app = Starlette(routes=[Route('/mcp', exports), Route('/mcp/{agent_id}', exports)])
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://hub.example')
    yield SimpleNamespace(store=store, service=service, runtime=runtime, client=client, calls=calls)
    await client.aclose()
    await exports.stop()


async def rpc(e, token, method, params=None, path='/mcp'):
    response = await e.client.post(path, headers=HEADERS | ({'Authorization': 'Bearer ' + token} if token else {}),
                                   json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})
    return response


async def call(e, token, name, arguments, path='/mcp'):
    response = await rpc(e, token, 'tools/call', {'name': name, 'arguments': arguments}, path)
    assert response.status_code == 200, response.text
    return response.json()['result']


async def test_missing_wrong_and_revoked_keys_are_rejected(e):
    token = await mcp_export.create_key(e.service, OWNER, 'child', 'laptop')
    assert (await rpc(e, None, 'tools/list')).status_code == 401
    assert (await rpc(e, token[:-1] + 'x', 'tools/list')).status_code == 401
    assert (await rpc(e, 'dsk_0000000000000000_' + 'a' * 43, 'tools/list')).status_code == 401
    assert (await rpc(e, token, 'tools/list')).status_code == 200
    row = e.store.one('SELECT * FROM mcp_export_keys')
    assert row['last_used'] and token.split('_')[2] not in json.dumps(row, default=str)
    await mcp_export.revoke_key(e.service, OWNER, row['id'])
    assert (await rpc(e, token, 'tools/list')).status_code == 401
    ops = [r['operation'] + ':' + r['target'] for r in e.store.all('SELECT operation,target FROM audit')]
    assert ops == [f'mcp-key-create:{row["id"]}', f'mcp-key-revoke:{row["id"]}']


async def test_agent_key_reaches_only_its_agent_and_descendants_and_global_key_any(e):
    parent = await mcp_export.create_key(e.service, OWNER, 'parent', 'p')
    child = await mcp_export.create_key(e.service, OWNER, 'child', 'c')
    glob = await mcp_export.create_key(e.service, OWNER, None, 'g')
    assert (await rpc(e, parent, 'tools/list', path='/mcp/child')).status_code == 200
    assert (await rpc(e, child, 'tools/list', path='/mcp/child')).status_code == 200
    assert (await rpc(e, child, 'tools/list', path='/mcp/parent')).status_code == 403
    assert (await rpc(e, parent, 'tools/list', path='/mcp/other')).status_code == 403
    assert (await call(e, glob, 'search_api', {'query': 'vm'}, '/mcp/other'))['content'][0]['text'].count('other')
    assert json.loads((await call(e, glob, 'search_api', {'query': 'vm'}))['content'][0]['text'])['agent'] == GLOBAL_ADMIN_AGENT
    assert json.loads((await call(e, child, 'search_api', {'query': 'vm'}))['content'][0]['text'])['agent'] == 'child'


async def test_key_management_authorization(e):
    with pytest.raises(PermissionError):
        await mcp_export.create_key(e.service, {'userid': 'domain', 'type': 2}, None, 'g')
    with pytest.raises(PermissionError):
        await mcp_export.create_key(e.service, {'userid': 'domain', 'type': 2}, 'other', 'x')
    with pytest.raises(PermissionError):
        await mcp_export.create_key(e.service, {'userid': 'child', 'type': 2, '_agent_id': 'child'}, 'child', 'x')
    await mcp_export.create_key(e.service, {'userid': 'domain', 'type': 2}, 'child', 'ok')
    assert [k['label'] for k in await mcp_export.list_keys(e.service, OWNER, 'child')] == ['ok']
    assert await mcp_export.list_keys(e.service, OWNER, None) == []


async def test_tools_list_matches_agent_enablement_and_excludes_pause_and_remote(e):
    token = await mcp_export.create_key(e.service, OWNER, 'child', 'laptop')
    names = {t['name'] for t in (await rpc(e, token, 'tools/list')).json()['result']['tools']}
    assert {'execute_api', 'search_api', 'describe_api', 'run_vm_command', 'write_vm_secret_file', 'transfer_vm_file',
            'list_skills', 'get_skill', 'save_skill', 'share_skill', 'configure_agent', 'create_subgroup',
            'request_escalation', 'platform_status', 'recover_operation', 'execution_state'} <= names
    assert 'pause_work' not in names
    e.store.execute('UPDATE agents SET escalation_requests_enabled=0 WHERE id=?', ('child',))
    names = {t['name'] for t in (await rpc(e, token, 'tools/list')).json()['result']['tools']}
    assert 'request_escalation' not in names and 'execute_api' in names


async def test_tool_call_is_durable_redacted_and_recorded_in_a_hub_conversation_without_llm(e):
    token = await mcp_export.create_key(e.service, OWNER, 'child', 'laptop')
    e.service._remember('dsk-in-output')
    result = await call(e, token, 'execute_api', {'command': 'createTags', 'params': {'k': 'v'}})
    assert 'dsk-in-output' not in result['content'][0]['text'] and not result.get('isError')
    assert e.calls == [('child', 'createTags', {'k': 'v'})]
    conversation = e.store.one('SELECT * FROM conversations')
    assert (conversation['title'], conversation['agent_id'], conversation['human_id'], conversation['imported']) == \
        ('MCP · laptop', 'child', 'owner', 1)
    run = e.store.one('SELECT * FROM chat_runs')
    assert run['status'] == 'completed'
    state = e.store.open(run['checkpoint'])
    assert [m['status'] for m in state['mutations'].values()] == ['complete']
    assert [ev['type'] for ev in e.store.open(run['events'])] == ['tool_call', 'tool_result']
    assert 'dsk-in-output' not in json.dumps(e.store.open(run['events']))
    await call(e, token, 'search_api', {'query': 'x'})
    assert e.store.one('SELECT COUNT(*) AS n FROM conversations')['n'] == 1  # one conversation per key and agent
    # An interrupted MCP run is never resumed as an LLM turn after restart.
    e.store.execute("UPDATE chat_runs SET status='running'")
    restarted = Runtime(e.service)
    started = []
    restarted._launch = lambda run, on_event=None: started.append(run)
    await restarted.start()
    assert started == []


async def test_escalation_request_over_mcp_is_queued_and_never_delivered_to_an_llm(e):
    token = await mcp_export.create_key(e.service, OWNER, 'child', 'laptop')
    result = await call(e, token, 'request_escalation', {
        'description': 'Create vGPU', 'reason': 'No permission', 'command': 'createTags', 'params': {'k': 'v'}})
    assert json.loads(result['content'][0]['text'])['status'] == 'pending'
    request = e.store.one('SELECT * FROM escalation_requests')
    conversation = e.store.one('SELECT * FROM conversations')
    assert (request['conversation_id'], request['human_id']) == (conversation['id'], 'owner')
    assert request['run_id'] == e.store.one('SELECT id FROM chat_runs')['id']
    e.store.execute("UPDATE escalation_requests SET status='approved',result=?", (e.store.seal({'id': 'done'}),))
    await e.runtime.deliver_escalation_decisions()
    assert e.store.one('SELECT delivery_run_id FROM escalation_requests')['delivery_run_id'] is None
    assert e.store.one('SELECT COUNT(*) AS n FROM chat_runs')['n'] == 1
    state = json.loads((await call(e, token, 'execution_state', {}))['content'][0]['text'])
    assert [(r['status'], r['result']) for r in state['escalation_requests']] == [('approved', {'id': 'done'})]


async def test_mcp_key_placeholder_is_per_agent_vm_reused_redacted_and_regenerated_after_revocation(e):
    e.store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                    ('c', 'child', 'owner', 't', 1, e.store.seal([])))
    e.store.execute("INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) "
                    "VALUES('r','c','running','child',1,1,?)", (e.store.seal([]),))
    CURRENT_RUN.set('r')
    first = await e.service.expand_secrets('child', 'K={{mcp_key}} U={{mcp_url}}', 'vm1')
    token = first.split()[0][2:]
    assert first.endswith('U=https://hub.example/mcp') and token.startswith('dsk_')
    assert await e.service.expand_secrets('child', '{{mcp_key}}', 'vm1') == token
    assert await e.service.expand_secrets('child', '{{mcp_key}}', 'vm2') != token
    assert e.service.redact({'out': 'token ' + token}) == {'out': 'token [redacted]'}
    key, acting = await mcp_export.authenticate(e.service, 'Bearer ' + token, None)
    assert (key['agent_id'], key['label'], acting) == ('child', 'vm:vm1', 'child')
    row = e.store.one("SELECT id FROM mcp_export_keys WHERE label='vm:vm1'")
    assert token.split('_')[2].encode() not in e.store.one('SELECT hash,sealed FROM mcp_export_keys WHERE id=?',
                                                         (row['id'],))['sealed']
    await mcp_export.revoke_key(e.service, OWNER, row['id'])
    assert await e.service.expand_secrets('child', '{{mcp_key}}', 'vm1') != token
    restarted = Service(e.store, e.service.settings)
    assert restarted.redact(token) == '[redacted]'
    assert Guest  # run_vm_command and write_vm_secret_file pass vm_id to expand_secrets


async def test_mcp_conversation_is_a_read_only_log_and_rejects_sends(e):
    token = await mcp_export.create_key(e.service, OWNER, 'child', 'laptop')
    await call(e, token, 'search_api', {'query': 'x'})
    conversation_id = e.store.one('SELECT id FROM conversations')['id']
    assert (await e.runtime.restore({'userid': 'owner', 'type': 1}, conversation_id))['mcp'] is True
    with pytest.raises(PermissionError, match='read-only'):
        await e.runtime.submit({'userid': 'owner', 'type': 1}, 'child', conversation_id, 'hello')
    assert e.store.one('SELECT COUNT(*) AS n FROM chat_runs')['n'] == 1


async def test_already_truncated_tool_result_is_shrunk_not_wrapped_again(e):
    token = await mcp_export.create_key(e.service, OWNER, 'child', 'laptop')

    async def search_api(agent_id, query):
        return {'truncated': True, 'preview': 'x"' * 4000}
    e.service.search_api = search_api
    text = (await call(e, token, 'search_api', {'query': 'x'}))['content'][0]['text']
    body = json.loads(text)
    assert len(text) <= 4096 and body['truncated'] is True and isinstance(body['preview'], str)
    assert 'truncated' not in body['preview']


async def test_mcp_hosts_placeholder_resolves_the_origin_hostname_and_is_empty_otherwise(e, monkeypatch):
    calls = []

    def resolve(host, port, family, kind):
        calls.append(family)
        if family == mcp_export.socket.AF_INET:
            raise OSError('no ipv4')
        return [(0, 0, 0, '', ('100.102.176.125', 0))]
    monkeypatch.setattr(mcp_export.socket, 'getaddrinfo', resolve)
    assert await e.service.expand_secrets('child', 'H={{mcp_hosts}}') == 'H=100.102.176.125 hub.example'
    assert len(calls) == 2  # IPv4 preferred, then any family
    monkeypatch.setattr(mcp_export.socket, 'getaddrinfo', lambda *a: (_ for _ in ()).throw(OSError('NXDOMAIN')))
    assert await e.service.expand_secrets('child', '[{{mcp_hosts}}]') == '[]'
    e.service.settings.origin = 'https://100.64.0.1:3001'
    monkeypatch.setattr(mcp_export.socket, 'getaddrinfo', resolve)
    assert await e.service.expand_secrets('child', '[{{mcp_hosts}}]') == '[]'
