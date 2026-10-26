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
    for agent_id in ('parent', 'child'):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (agent_id, agent_id, agent_id + '-domain', 'account', 'user', store.seal({})))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'child', 'owner', 'Compute', 1, store.seal([])))
    store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                  ('run', 'conversation', 'running', 'child', 1, 1, store.seal([])))
    service = Service(store, SimpleNamespace())
    calls = []

    async def chain(agent):
        return [await service.agent('parent'), agent] if agent['id'] == 'child' else [agent]

    async def human_call(identity, command, params):
        assert identity == owner
        calls.append((command, params))
        if command == 'listDomains':
            return {'domain': [{'id': 'child-domain'}, {'id': 'parent-domain'}]}
        if command == 'listApis':
            return {'api': [{'name': 'createServiceOffering', 'params': [
                {'name': 'name', 'type': 'string', 'required': True},
                {'name': 'memory', 'type': 'integer'}, {'name': 'domainid', 'type': 'string'},
                {'name': 'details', 'type': 'map'}]}]}
        assert command == 'createServiceOffering'
        await asyncio.sleep(0)
        return {'serviceoffering': {'id': 'created-offering'}}

    owner = {'type': 1, 'userid': 'owner', '_session': 'session'}
    service.agent_chain, service.human_call = chain, human_call
    return SimpleNamespace(store=store, service=service, calls=calls, owner=owner)


async def request(e, params=None, **changes):
    args = {'conversation_id': 'conversation', 'run_id': 'run', 'call_id': 'call', **changes}
    return await e.service.request_compute_offering('child', params or {'name': 'Large', 'memory': 4096}, **args)


async def test_request_is_durable_idempotent_and_never_calls_native_creation(environment):
    e = environment
    first = await request(e)
    assert (await request(e))['id'] == first['id']
    assert first['status'] == 'pending' and first['params']['domainid'] == 'child-domain'
    assert e.calls == []
    raw = e.store.one('SELECT params FROM compute_offering_requests')['params']
    assert b'Large' not in raw
    with pytest.raises(ValueError, match='different offering'):
        await request(e, {'name': 'Other'})
    assert (await e.service.list_compute_offering_requests(e.owner))[0]['agent_name'] == 'child'


@pytest.mark.parametrize('params', [{'name': 'Bad', 'sessionkey': 'stolen'}, {'name': 'Bad', 'domainid': 'parent-domain'},
                                    {'name': 'Bad', 'details[0].x': '@local-file'}, {'name': 'Bad', 'x': 'x' * 65536}])
async def test_request_rejects_auth_scope_and_unbounded_parameters(environment, params):
    with pytest.raises((ValueError, PermissionError)):
        await request(environment, params)
    assert not environment.store.all('SELECT * FROM compute_offering_requests')


async def test_request_validates_conversation_and_inherited_access(environment):
    e = environment
    with pytest.raises(PermissionError, match='conversation'):
        await request(e, conversation_id='other')
    e.store.execute("UPDATE agents SET compute_offering_requests_enabled=0 WHERE id='parent'")
    assert await e.service.compute_offering_access(await e.service.agent('child')) == {
        'selected': True, 'allowed': False, 'enabled': False}
    with pytest.raises(PermissionError, match='disabled'):
        await request(e)
    e.store.execute("UPDATE agents SET compute_offering_requests_enabled=1 WHERE id='parent'")
    assert (await e.service.compute_offering_access(await e.service.agent('child')))['enabled']


async def test_only_explicit_owner_approval_creates_once_with_native_scope(environment):
    e = environment
    row = await request(e, {'name': 'Map', 'details[0].key': 'value'})
    results = await asyncio.gather(*(e.service.decide_compute_offering(e.owner, row['id'], True) for _ in range(2)))
    assert 'approved' in {result['status'] for result in results}
    creates = [params for command, params in e.calls if command == 'createServiceOffering']
    assert creates == [{'name': 'Map', 'details[0].key': 'value', 'domainid': 'child-domain'}]
    approved = await e.service.decide_compute_offering(e.owner, row['id'], True)
    assert approved['result']['serviceoffering']['id'] == 'created-offering'
    assert len([1 for command, _ in e.calls if command == 'createServiceOffering']) == 1
    for identity in ({'type': 2}, {'type': 1, '_agent_id': 'parent'}):
        with pytest.raises(PermissionError, match='human owner'):
            await e.service.decide_compute_offering(identity, row['id'], True)


async def test_decline_dismisses_without_native_creation_or_agent_invocation(environment):
    e = environment
    row = await request(e)
    assert (await e.service.decide_compute_offering(e.owner, row['id'], False))['status'] == 'deferred'
    assert (await e.service.decide_compute_offering(e.owner, row['id'], True))['status'] == 'deferred'
    assert not any(command == 'createServiceOffering' for command, _ in e.calls)
    assert len(e.store.all('SELECT * FROM chat_runs')) == 1


async def test_approval_revalidates_native_parameters_and_inherited_access(environment):
    e = environment
    row = await request(e, {'name': 'Bad', 'memory': 'string'})
    with pytest.raises(ValueError, match='integer'):
        await e.service.decide_compute_offering(e.owner, row['id'], True)
    e.store.execute("UPDATE agents SET compute_offering_requests_enabled=0 WHERE id='parent'")
    with pytest.raises(PermissionError, match='disabled'):
        await e.service.decide_compute_offering(e.owner, row['id'], True)
    assert e.store.one('SELECT status FROM compute_offering_requests')['status'] == 'pending'


@pytest.mark.parametrize('error,status', [(TimeoutError('lost response'), 'uncertain'),
                                        (CloudError('rejected', rejected=True), 'failed')])
async def test_unknown_creation_outcome_never_replays(environment, error, status):
    e = environment
    row = await request(e)
    human_call = e.service.human_call
    attempts = 0

    async def failing(identity, command, params):
        nonlocal attempts
        if command == 'createServiceOffering':
            attempts += 1
            raise error
        return await human_call(identity, command, params)

    e.service.human_call = failing
    assert (await e.service.decide_compute_offering(e.owner, row['id'], True))['status'] == status
    assert (await e.service.decide_compute_offering(e.owner, row['id'], True))['status'] == status
    assert attempts == 1


async def test_requests_are_private_to_owner_and_only_active_runs_can_request(environment):
    e = environment
    row = await request(e)
    other = {**e.owner, 'userid': 'other'}
    original = e.service.human_call

    async def human_call(identity, command, params):
        return await original(e.owner, command, params)

    e.service.human_call = human_call
    assert await e.service.list_compute_offering_requests(other) == []
    with pytest.raises(PermissionError, match='owner'):
        await e.service.decide_compute_offering(other, row['id'], False)
    e.store.execute("UPDATE chat_runs SET status='completed' WHERE id='run'")
    with pytest.raises(PermissionError, match='conversation'):
        await request(e, call_id='another')


async def test_inherited_request_setting_cannot_be_self_enabled_or_widened(environment):
    e = environment

    async def authorize(identity, agent_id):
        return await e.service.agent(agent_id)

    e.service.authorize = authorize
    await e.service.update_agent(e.owner, 'child', None, '', '', compute_offering_requests_enabled=False)
    assert not (await e.service.agent('child'))['compute_offering_requests_enabled']
    await e.service.update_agent(e.owner, 'child', None, '', 'other prompt')
    assert not (await e.service.agent('child'))['compute_offering_requests_enabled']
    with pytest.raises(PermissionError, match='own system prompt'):
        await e.service.update_agent({'type': 2, 'userid': 'owner', '_agent_id': 'child'},
                                     'child', None, '', '', compute_offering_requests_enabled=True)
    e.store.execute("UPDATE agents SET compute_offering_requests_enabled=0 WHERE id='parent'")
    with pytest.raises(PermissionError, match='ancestor access'):
        await e.service.update_agent(e.owner, 'child', None, '', '', compute_offering_requests_enabled=True)
    with pytest.raises(ValueError, match='boolean'):
        await e.service.update_agent(e.owner, 'child', None, '', '', compute_offering_requests_enabled=1)


async def test_approval_requires_native_created_offering_id(environment):
    e = environment
    row = await request(e)
    original = e.service.human_call

    async def human_call(identity, command, params):
        return {'serviceoffering': {'name': 'Missing ID'}} if command == 'createServiceOffering' else await original(identity, command, params)

    e.service.human_call = human_call
    assert (await e.service.decide_compute_offering(e.owner, row['id'], True))['status'] == 'uncertain'


@pytest.mark.parametrize('params', [{'name': 'Legacy', 'details[0].pcidevice': 'gpu'},
                                    {'name': 'Legacy', 'details[0].key': 'vgpuType', 'details[0].value': 'profile'},
                                    {'name': 'Physical', 'gpucardid': 'card', 'gpucount': 1},
                                    {'name': 'Fractional', 'vgpuprofileid': 'profile', 'gpucount': 1.5},
                                    {'name': 'Boolean', 'vgpuprofileid': 'profile', 'gpucount': True}])
async def test_gpu_offering_rejects_legacy_passthrough_and_noninteger_count(environment, params):
    with pytest.raises(PermissionError):
        await request(environment, params)
    assert not environment.store.all('SELECT * FROM compute_offering_requests')


async def test_gpu_offering_rechecks_permission_when_approved(environment, monkeypatch):
    from dirigentenstab import service as service_module
    e = environment
    checks = []
    permitted = True

    async def helper(settings, action, **payload):
        checks.append(payload)
        assert action == 'validate_offering' and payload['session'] is None
        if not permitted:
            raise PermissionError('GPU policy revoked')
        return {'gpucount': 1}

    monkeypatch.setattr(service_module, 'helper_call', helper)
    params = {'name': 'GPU', 'vgpuprofileid': 'native-profile', 'gpucount': 1}
    row = await request(e, params)
    original = e.service.human_call

    async def human_call(identity, command, params):
        result = await original(identity, command, params)
        if command == 'listApis':
            result['api'][0]['params'] += [{'name': 'vgpuprofileid', 'type': 'string'}, {'name': 'gpucount', 'type': 'integer'}]
        return result

    e.service.human_call = human_call
    permitted = False
    with pytest.raises(PermissionError, match='revoked'):
        await e.service.decide_compute_offering(e.owner, row['id'], True)
    assert len(checks) == 2 and checks[0]['run_id'] == 'run'
    assert e.store.one('SELECT status FROM compute_offering_requests')['status'] == 'pending'
    assert not any(command == 'createServiceOffering' for command, _ in e.calls)
    permitted = True
    approved = await e.service.decide_compute_offering(e.owner, row['id'], True)
    assert approved['status'] == 'approved'
    assert approved['result']['serviceoffering']['id'] == 'created-offering'
    assert len(checks) == 3
    assert next(params for command, params in e.calls if command == 'createServiceOffering') == {
        'name': 'GPU', 'vgpuprofileid': 'native-profile', 'gpucount': 1, 'domainid': 'child-domain'}
