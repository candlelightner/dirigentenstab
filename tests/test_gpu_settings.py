from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.gpu import describe_plan, validate_policy
from dirigentenstab.service import Service
from dirigentenstab.store import Store

PROFILES = [{'id': 'nvidia-51', 'name': 'GRID P40-8Q'}, {'id': 'nvidia-53', 'name': 'GRID P40-24Q'}]
DOMAINS = [{'id': 'root', 'name': 'ROOT', 'path': 'ROOT', 'level': 0},
           {'id': 'unmanaged', 'name': 'Unmanaged', 'path': 'ROOT/Unmanaged', 'level': 1, 'parentdomainid': 'root'},
           {'id': 'main', 'name': 'Main', 'path': 'ROOT/Unmanaged/Main', 'level': 2, 'parentdomainid': 'unmanaged'},
           {'id': 'child', 'name': 'Child', 'path': 'ROOT/Unmanaged/Main/Child', 'level': 3, 'parentdomainid': 'main'},
           {'id': 'sibling', 'name': 'Sibling', 'path': 'ROOT/Unmanaged/Main/Sibling', 'level': 3, 'parentdomainid': 'main'}]


def policy(profiles=(), maximum=0, **flags):
    return {'profiles': list(profiles), 'max_allocations': maximum,
            **{flag: flags.get(flag, False) for flag in ('release_on_stop', 'reconfigure_unused', 'subgroup_requests')}}


@pytest.fixture
def environment(tmp_path, monkeypatch):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for aid, domain in (('main', 'main'), ('child', 'child'), ('sibling', 'sibling')):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (aid, aid.title() + ' Agent', domain, 'account', 'user', store.seal({})))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'child', 'owner', 'GPU', 1, store.seal([])))
    store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                  ('run', 'conversation', 'running', 'child', 1, 1, store.seal([])))
    private = {'userid': 'owner', 'account': 'admin', 'domainid': 'root', 'type': 1}
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)', ('session', 'csrf', store.seal(private), 99999999999))
    service = Service(store, SimpleNamespace(gpu_helper_socket='/gpu'))
    policies, calls = {}, []

    async def helper_call(settings, action, **payload):
        calls.append((action, payload))
        if action == 'status':
            return {'domains': DOMAINS, 'profiles': PROFILES, 'policies': {k: dict(v) for k, v in policies.items()},
                    'pools': [{'uuid': 'gpu-1', 'domain_id': 'child', 'profile': 'nvidia-51'}],
                    'devices': [{'busaddress': 'gpu-2', 'state': 'Free', 'vgpuprofilename': 'P40'}], 'operations': []}
        if action == 'profiles':
            return PROFILES
        policies[payload['domain_id']] = validate_policy(payload['policy'], ['nvidia-51', 'nvidia-53'])
        return {'saved': True}

    async def human_call(identity, command, params):
        return {'listUsers': {'user': [{'id': 'owner', 'state': 'enabled'}]},
                'listAccounts': {'account': [{'name': 'admin', 'domainid': 'root', 'accounttype': 1, 'state': 'enabled'}]},
                'listDomains': {'domain': DOMAINS}}[command]

    async def chain(agent):
        return [await service.agent('main'), agent] if agent['id'] == 'child' else [agent]

    monkeypatch.setattr('dirigentenstab.service.helper_call', helper_call)
    service.human_call, service.agent_chain = human_call, chain
    return SimpleNamespace(store=store, service=service, policies=policies, calls=calls,
                           owner={**private, '_session': 'session'})


def saved_order(e):
    return [payload['domain_id'] for action, payload in e.calls if action == 'set_policy']


async def test_plan_without_widening_saves_only_the_agent(environment):
    e = environment
    e.policies.update(root=policy(['nvidia-51'], -1, subgroup_requests=True), unmanaged=policy(['nvidia-51'], 4, subgroup_requests=True),
                      main=policy(['nvidia-51'], 2, subgroup_requests=True))
    wanted = policy(['nvidia-51'], 1, subgroup_requests=True)
    plan = await e.service.gpu_policy_plan(e.owner, 'child', wanted)
    assert plan['changes'] == [] and plan['activated'] == [] and describe_plan(plan) == []
    await e.service.gpu_apply_policy(e.owner, plan)
    assert saved_order(e) == ['child'] and e.policies['child'] == wanted


async def test_plan_widens_profiles_max_and_flags_in_two_ancestors_top_down(environment):
    e = environment
    e.policies.update(root=policy(['nvidia-51'], -1), unmanaged=policy(['nvidia-51'], 1), main=policy(['nvidia-51'], 2))
    wanted = policy(['nvidia-51', 'nvidia-53'], 3, release_on_stop=True)
    plan = await e.service.gpu_policy_plan(e.owner, 'child', wanted)
    by_domain = {c['domain_id']: c for c in plan['changes']}
    assert list(by_domain) == ['root', 'unmanaged', 'main']  # missing managed ancestors included, ROOT first
    assert by_domain['root']['profiles'] == ['GRID P40-24Q'] and by_domain['root']['max'] is None
    assert by_domain['unmanaged']['max'] == [1, 3] and by_domain['main']['max'] == [2, 3]
    assert by_domain['main']['flags'] == ['release_on_stop'] and by_domain['main']['name'] == 'Main Agent'
    assert by_domain['unmanaged']['name'] == 'ROOT/Unmanaged'  # no hub agent: domain path
    assert 'Main Agent: allow GRID P40-24Q; max 2 to 3; enable "Release GPU when its VM stops"' in describe_plan(plan)
    await e.service.gpu_apply_policy(e.owner, plan)
    assert saved_order(e) == ['root', 'unmanaged', 'main', 'child']
    assert e.policies['main']['max_allocations'] == 3 and e.policies['child'] == wanted


async def test_plan_lists_explicit_sibling_policies_that_become_effective(environment):
    e = environment
    e.policies.update(root=policy(['nvidia-51'], -1), unmanaged=policy(['nvidia-51'], 5), main=policy(['nvidia-51'], 5),
                      sibling=policy(['nvidia-51', 'nvidia-53'], 5))
    plan = await e.service.gpu_policy_plan(e.owner, 'child', policy(['nvidia-53'], 1))
    assert plan['activated'] == [{'domain_id': 'sibling', 'name': 'Sibling Agent', 'profiles': ['GRID P40-24Q'],
                                  'max': None, 'flags': []}]
    assert 'Also becomes more effective for Sibling Agent: allow GRID P40-24Q' in describe_plan(plan)


async def test_plan_rejects_invalid_quota_before_any_save(environment):
    e = environment
    with pytest.raises(ValueError, match='explicit quota'):
        await e.service.gpu_policy_plan(e.owner, 'child', policy(['nvidia-51'], -1))
    assert saved_order(e) == []


async def request(e, profiles=('GRID P40-24Q',), maximum=None, call_id='call'):
    return await e.service.request_gpu_profiles('child', list(profiles), 'Need a bigger vGPU', maximum,
                                                conversation_id='conversation', run_id='run', call_id=call_id)


async def test_gpu_request_is_validated_idempotent_and_limited(environment):
    e = environment
    row = await request(e, ['GRID P40-24Q', 'nvidia-51'], 3)
    assert row['status'] == 'pending' and row['command'] == 'grantGpuPolicy'
    assert row['params'] == {'profiles': [{'id': 'nvidia-51', 'name': 'GRID P40-8Q'}, {'id': 'nvidia-53', 'name': 'GRID P40-24Q'}],
                             'max_allocations': 3}
    assert (await request(e, ['GRID P40-24Q', 'nvidia-51'], 3))['id'] == row['id']
    with pytest.raises(ValueError, match='Unknown host vGPU profile'):
        await request(e, ['GRID nothing'], call_id='other')
    forged = {'profiles': [{'id': 'nvidia-53', 'name': 'Anything'}], 'max_allocations': None}
    with pytest.raises(ValueError, match='exact host vGPU profiles'):
        await e.service.request_escalation('child', 'Forged', 'Forged', 'grantGpuPolicy', forged,
                                           conversation_id='conversation', run_id='run', call_id='forged')
    for index in range(2):
        await request(e, call_id=f'fill-{index}')
    with pytest.raises(Exception, match='open escalation requests'):
        await request(e, call_id='over')
    assert e.policies == {}  # requesting never changes policy


async def test_approval_applies_the_plan_top_down_and_stores_it(environment):
    e = environment
    e.policies.update(root=policy(['nvidia-51'], -1), unmanaged=policy(['nvidia-51'], 5), main=policy(['nvidia-51'], 1),
                      child=policy(['nvidia-51'], 1))
    row = await request(e, maximum=2)
    decided = await e.service.decide_escalation(e.owner, row['id'], True)
    assert decided['status'] == 'approved'
    assert saved_order(e) == ['root', 'unmanaged', 'main', 'child']
    assert e.policies['unmanaged']['max_allocations'] == 5  # only raised as far as needed
    assert e.policies['child']['profiles'] == ['nvidia-51', 'nvidia-53'] and e.policies['child']['max_allocations'] == 2
    assert e.policies['main']['max_allocations'] == 2
    assert [c['domain_id'] for c in decided['result']['applied']] == ['root', 'unmanaged', 'main', 'child']


async def test_denial_changes_nothing_and_approval_revalidates(environment):
    e = environment
    denied = await e.service.decide_escalation(e.owner, (await request(e))['id'], False)
    assert denied['status'] == 'deferred' and saved_order(e) == []
    row = await request(e, call_id='second')
    # The host no longer offers the profile when the human decides: the request fails without any change.
    import dirigentenstab.service as module
    original = module.helper_call

    async def gone(settings, action, **payload):
        result = await original(settings, action, **payload)
        if action == 'status':
            result['profiles'] = PROFILES[:1]
        return result
    module.helper_call = gone
    try:
        failed = await e.service.decide_escalation(e.owner, row['id'], True)
    finally:
        module.helper_call = original
    assert failed['status'] == 'failed' and saved_order(e) == []


async def test_grant_for_a_subagent_is_usable_max_one_and_capacity_requests_on_its_chain(environment):
    e = environment
    row = await request(e)
    plan = await e.service.gpu_grant_plan(e.owner, row['id'])
    assert [c['domain_id'] for c in plan['changes']] == ['root', 'unmanaged', 'main']
    assert plan['target']['policy'] == policy(['nvidia-53'], 1, subgroup_requests=True)
    assert all(c['policy']['subgroup_requests'] and c['policy']['max_allocations'] in {1, -1} for c in plan['changes'])
    assert 'enable "GPU capacity requests"' in describe_plan(plan)[0]


async def test_grant_for_main_agent_does_not_add_capacity_requests(environment):
    from dirigentenstab.limits import APP_ROOT_AGENT
    e = environment
    e.store.execute('UPDATE agents SET id=? WHERE id=?', (APP_ROOT_AGENT, 'main'))
    e.store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                    ('main-conversation', APP_ROOT_AGENT, 'owner', 'GPU', 1, e.store.seal([])))
    e.store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                    ('main-run', 'main-conversation', 'running', APP_ROOT_AGENT, 1, 1, e.store.seal([])))
    row = await e.service.request_gpu_profiles(APP_ROOT_AGENT, ['GRID P40-8Q'], 'Need it', None, conversation_id='main-conversation',
                                               run_id='main-run', call_id='main-call')
    plan = await e.service.gpu_grant_plan(e.owner, row['id'])
    assert plan['target']['policy'] == policy(['nvidia-51'], 1)
