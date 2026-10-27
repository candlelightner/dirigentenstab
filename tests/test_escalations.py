import asyncio
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.cloud import CloudError
from dirigentenstab.service import Service
from dirigentenstab.store import Store


@pytest.fixture
def environment(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for aid in ('parent', 'child'):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (aid, aid, aid + '-domain', 'account', 'user', store.seal({})))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'child', 'owner', 'Escalation', 1, store.seal([])))
    store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                  ('run', 'conversation', 'running', 'child', 1, 1, store.seal([])))
    private = {'userid': 'owner', 'account': 'admin', 'domainid': 'root', 'type': 1}
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)', ('session', 'csrf', store.seal(private), 99999999999))
    service, calls = Service(store, SimpleNamespace()), []

    async def chain(agent):
        return [await service.agent('parent'), agent] if agent['id'] == 'child' else [agent]

    async def human_call(identity, command, params):
        assert identity['userid'] == 'owner' and identity['_session'] == 'session'
        calls.append((command, params))
        if command == 'listUsers':
            return {'user': [{'id': 'owner', 'state': 'enabled'}]}
        if command == 'listAccounts':
            return {'account': [{'name': 'admin', 'domainid': 'root', 'accounttype': 1, 'state': 'enabled'}]}
        if command == 'listDomains':
            return {'domain': [{'id': 'child-domain'}, {'id': 'parent-domain'}]}
        if command == 'listApis':
            return {'api': [{'name': params['name'], 'params': [{'name': 'name', 'type': 'string'},
                    {'name': 'domainid', 'type': 'string'}, {'name': 'gpucardid', 'type': 'string'},
                    {'name': 'videoram', 'type': 'integer'}, {'name': 'password', 'type': 'string'}]}]}
        await asyncio.sleep(0)
        return {'success': True, 'id': 'created-id'}

    service.agent_chain, service.human_call = chain, human_call
    return SimpleNamespace(store=store, service=service, calls=calls,
                           owner={**private, '_session': 'session'})


async def request(e, params=None, command='createVgpuProfile', **changes):
    context = {'conversation_id': 'conversation', 'run_id': 'run', 'call_id': 'call', **changes}
    return await e.service.request_escalation('child', 'Prepare the requested GPU profile',
        'This account cannot register global GPU profiles', command,
        params if params is not None else {'name': 'GRID P40-12Q', 'gpucardid': 'card', 'videoram': 12288}, **context)


async def test_restricted_agent_can_queue_exact_native_api_without_discovery_or_mutation(environment):
    e = environment
    row = await request(e)
    assert row['status'] == 'pending' and row['command'] == 'createVgpuProfile'
    assert row['params'] == {'name': 'GRID P40-12Q', 'gpucardid': 'card', 'videoram': 12288}
    assert e.calls == []
    assert (await request(e))['id'] == row['id']
    assert b'GRID' not in e.store.one('SELECT params FROM escalation_requests')['params']
    with pytest.raises(ValueError, match='different escalation'):
        await request(e, {'name': 'other'})


@pytest.mark.parametrize('params,command', [({'sessionkey': 'override'}, 'listAccounts'),
                                          ({'name': '@local'}, 'createVgpuProfile'),
                                          ({'name': 'x' * 65536}, 'createVgpuProfile'),
                                          ({}, 'listAccounts;rm'), ({}, 'ListAccounts')])
async def test_request_rejects_auth_file_and_invalid_native_command_inputs(environment, params, command):
    with pytest.raises(ValueError):
        await request(environment, params, command)
    assert not environment.store.all('SELECT * FROM escalation_requests')


async def test_queue_checks_active_owned_conversation_and_inheritance(environment):
    e = environment
    with pytest.raises(PermissionError, match='conversation'):
        await request(e, conversation_id='foreign')
    e.store.execute("UPDATE chat_runs SET status='completed' WHERE id='run'")
    with pytest.raises(PermissionError, match='conversation'):
        await request(e)
    e.store.execute("UPDATE chat_runs SET status='running' WHERE id='run'")
    e.store.execute("UPDATE agents SET escalation_requests_enabled=0 WHERE id='parent'")
    assert await e.service.escalation_access(await e.service.agent('child')) == {'selected': True, 'allowed': False, 'enabled': False}
    with pytest.raises(PermissionError, match='disabled'):
        await request(e)
    e.store.execute("UPDATE agents SET escalation_requests_enabled=1 WHERE id='parent'")
    assert (await e.service.escalation_access(await e.service.agent('child')))['enabled']


@pytest.mark.parametrize('command,params', [('createVgpuProfile', {'name': 'GRID P40-12Q', 'gpucardid': 'card', 'videoram': 12288}),
                                          ('updateVirtualMachine', {'name': 'renamed'})])
async def test_owner_approval_executes_exact_request_once_without_domain_rewrite(environment, command, params):
    e = environment
    row = await request(e, params, command)
    results = await asyncio.gather(*(e.service.decide_escalation(e.owner, row['id'], True) for _ in range(2)))
    assert 'approved' in {result['status'] for result in results}
    assert [values for name, values in e.calls if name == command] == [params]
    assert (await e.service.decide_escalation(e.owner, row['id'], True))['result']['id'] == 'created-id'
    assert [values for name, values in e.calls if name == command] == [params]


async def test_dismissal_never_executes_native_request_or_starts_model(environment):
    e = environment
    row = await request(e)
    assert (await e.service.decide_escalation(e.owner, row['id'], False))['status'] == 'deferred'
    assert (await e.service.decide_escalation(e.owner, row['id'], True))['status'] == 'deferred'
    assert not any(command == 'createVgpuProfile' for command, _ in e.calls)
    assert len(e.store.all('SELECT * FROM chat_runs')) == 1


async def test_approval_revalidates_current_root_session_and_request_ownership(environment):
    e = environment
    row = await request(e)
    for identity in ({'type': 2}, {**e.owner, '_agent_id': 'parent'}, {**e.owner, 'userid': 'other'}):
        with pytest.raises(PermissionError):
            await e.service.decide_escalation(identity, row['id'], True)
    e.store.execute("UPDATE sessions SET expires=0 WHERE token_hash='session'")
    with pytest.raises(PermissionError, match='expired'):
        await e.service.decide_escalation(e.owner, row['id'], True)
    assert e.store.one('SELECT status FROM escalation_requests')['status'] == 'pending'


async def test_approval_rechecks_native_metadata_and_revoked_request_access(environment):
    e = environment
    row = await request(e, {'videoram': 'bad'})
    with pytest.raises(ValueError, match='integer'):
        await e.service.decide_escalation(e.owner, row['id'], True)
    e.store.execute("UPDATE agents SET escalation_requests_enabled=0 WHERE id='parent'")
    with pytest.raises(PermissionError, match='disabled'):
        await e.service.decide_escalation(e.owner, row['id'], True)
    assert e.store.one('SELECT status FROM escalation_requests')['status'] == 'pending'


@pytest.mark.parametrize('outcome,status', [('success', 'approved'), ('lost', 'uncertain'), ('failed', 'failed')])
async def test_async_job_id_is_durable_before_poll_and_command_never_replayed(environment, outcome, status):
    e = environment
    row = await request(e)
    original = e.service.human_call
    mutations = 0

    async def human_call(identity, command, params):
        nonlocal mutations
        if command == 'createVgpuProfile':
            mutations += 1
            return {'jobid': 'native-job'}
        if command == 'queryAsyncJobResult':
            saved = e.store.one('SELECT status,result FROM escalation_requests')
            assert saved['status'] == 'applying' and e.store.open(saved['result']) == {'jobid': 'native-job'}
            if outcome == 'lost':
                raise PermissionError('Session expired')
            if outcome == 'failed':
                return {'jobstatus': 2, 'jobresult': {'errorcode': 530, 'errortext': 'Native task failed'}}
            return {'jobstatus': 1, 'jobresult': {'id': 'created-id'}}
        return await original(identity, command, params)

    e.service.human_call = human_call
    decided = await e.service.decide_escalation(e.owner, row['id'], True)
    assert decided['status'] == status
    assert decided['result'].get('jobid') == ('native-job' if outcome != 'success' else None)
    if outcome == 'failed':
        assert decided['result']['jobstatus'] == 2
        assert decided['result']['jobresult'] == {'errorcode': 530, 'errortext': 'Native task failed'}
    await e.service.decide_escalation(e.owner, row['id'], True)
    assert mutations == 1


async def test_native_rejection_is_failed_and_sensitive_result_and_error_are_redacted(environment):
    e = environment
    row = await request(e, {'password': 'tiny-secret'})
    original = e.service.human_call

    async def human_call(identity, command, params):
        if command == 'createVgpuProfile':
            raise CloudError('Rejected password tiny-secret', rejected=True)
        return await original(identity, command, params)

    e.service.human_call = human_call
    decided = await e.service.decide_escalation(e.owner, row['id'], True)
    assert decided['status'] == 'failed' and 'tiny-secret' not in str(decided)
    assert 'tiny-secret' not in str(e.store.open(e.store.one('SELECT result FROM escalation_requests')['result']))


async def test_open_request_limit_is_atomic_per_agent_and_idempotent_at_capacity(environment):
    e = environment
    assert e.service.escalation_request_limit() == 3
    results = await asyncio.gather(*(asyncio.to_thread(asyncio.run, request(e, call_id=f'call-{index}'))
                                     for index in range(8)), return_exceptions=True)
    accepted = [result for result in results if isinstance(result, dict)]
    assert len(accepted) == 3
    assert all('limit 3' in str(result) for result in results if isinstance(result, Exception))
    assert (await request(e, call_id=accepted[0]['call_id']))['id'] == accepted[0]['id']
    e.store.execute("UPDATE escalation_requests SET status='applying' WHERE id=?", (accepted[0]['id'],))
    with pytest.raises(ValueError, match='limit 3'):
        await request(e, call_id='new')
    e.store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('parent-conversation', 'parent', 'owner', 'Other agent', 2, e.store.seal([])))
    e.store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                  ('parent-run', 'parent-conversation', 'running', 'parent', 2, 2, e.store.seal([])))
    assert (await e.service.request_escalation('parent', 'Independent', 'Other account', 'createVgpuProfile', {},
            conversation_id='parent-conversation', run_id='parent-run', call_id='parent-call'))['status'] == 'pending'
    e.service.save_escalation_request_limit(e.owner, 4)
    assert (await request(e, call_id='fourth'))['status'] == 'pending'
    e.service.save_escalation_request_limit(e.owner, 3)
    with pytest.raises(ValueError, match='limit 3'):
        await request(e, call_id='new')
    e.store.execute("UPDATE escalation_requests SET status='approved' WHERE id=?", (accepted[0]['id'],))
    with pytest.raises(ValueError, match='limit 3'):
        await request(e, call_id='new')
    await e.service.decide_escalation(e.owner, accepted[1]['id'], False)
    assert (await request(e, call_id='released'))['status'] == 'pending'


@pytest.mark.parametrize('value', [0, -1, True, 1.5, '3', None])
def test_request_limit_requires_positive_integer_and_human_admin(environment, value):
    e = environment
    with pytest.raises(ValueError, match='positive whole number'):
        e.service.save_escalation_request_limit(e.owner, value)
    with pytest.raises(PermissionError):
        e.service.save_escalation_request_limit({**e.owner, '_agent_id': 'parent'}, 5)
    with pytest.raises(PermissionError):
        e.service.save_escalation_request_limit({'type': 2}, 5)
    assert e.service.escalation_request_limit() == 3


async def test_escalation_owner_identity_rejection_revokes_session_without_dispatch(environment):
    e = environment
    row = await request(e)
    original = e.service.human_call

    async def human_call(identity, command, params):
        if command == 'listUsers':
            raise CloudError('Native identity request rejected', rejected=True)
        return await original(identity, command, params)

    e.service.human_call = human_call
    with pytest.raises(PermissionError, match='no longer valid'):
        await e.service.decide_escalation(e.owner, row['id'], True)
    assert not e.store.one('SELECT * FROM sessions')
    assert e.store.one('SELECT status FROM escalation_requests')['status'] == 'pending'


async def test_owner_session_transport_classifies_native_rejection_and_hides_secrets(environment, monkeypatch):
    import httpx
    from dirigentenstab import service as service_module
    e = environment
    private = e.store.open(e.store.one('SELECT identity FROM sessions')['identity'])
    private.update(sessionkey='session-private', cookies={'JSESSIONID': 'cookie-private'})
    e.store.execute('UPDATE sessions SET identity=?', (e.store.seal(private),))
    e.service.settings.cloudstack_url = 'https://cloud.example/client/api'
    original_client = httpx.AsyncClient

    def handler(request):
        return httpx.Response(400, json={'errorresponse': {'errorcode': 431,
            'errortext': 'Rejected tiny-secret session-private cookie-private'}})

    monkeypatch.setattr(service_module.httpx, 'AsyncClient',
                        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs))
    with pytest.raises(CloudError) as failure:
        await Service.human_call(e.service, e.owner, 'createVgpuProfile', {'password': 'tiny-secret'})
    assert failure.value.rejected
    assert '431' in str(failure.value)
    assert all(secret not in str(failure.value) for secret in ('tiny-secret', 'session-private', 'cookie-private'))
