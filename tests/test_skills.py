from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.service import Service
from dirigentenstab.store import Store


@pytest.fixture
def env(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    paths = {'root': ['root'], 'creator': ['root', 'creator'],
             'child': ['root', 'creator', 'child'], 'grandchild': ['root', 'creator', 'child', 'grandchild'],
             'sibling': ['root', 'sibling']}
    for aid in paths:
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (aid, aid, aid + '-domain', 'account', 'user', store.seal({})))
    service = Service(store, SimpleNamespace())
    domains = [{'id': aid + '-domain', 'level': len(path)-1,
                'parentdomainid': path[-2] + '-domain' if len(path)>1 else None}
               for aid,path in paths.items()]
    calls = []

    async def chain(agent):
        return [await service.agent(aid) for aid in paths[agent['id']]]

    async def human_call(identity, command, params):
        assert identity['userid'] == 'owner'
        if command == 'listUsers':
            return {'user': [{'id': 'owner', 'state': 'enabled'}]}
        if command == 'listAccounts':
            return {'account': [{'name': 'admin', 'domainid': 'root-domain', 'accounttype': 1, 'state': 'enabled'}]}
        if command == 'listDomains':
            calls.append(('human', command, params))
            return {'domain': domains}
        raise AssertionError('Skill approval must never execute a native command')

    async def cloud_client(agent):
        async def raw(command, params):
            assert command == 'listDomains'
            calls.append((agent['id'], command, params))
            return {'domain': domains}
        return SimpleNamespace(raw=raw)

    service.agent_chain, service.human_call, service.cloud_client = chain, human_call, cloud_client
    owner = {'userid': 'owner', 'account': 'admin', 'domainid': 'root-domain', 'type': 1}
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)', ('session', 'csrf', store.seal(owner), 99999999999))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'creator', 'owner', 'Skill', 1, store.seal([])))
    store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                  ('run', 'conversation', 'running', 'creator', 1, 1, store.seal([])))
    return SimpleNamespace(store=store, service=service, domains=domains, calls=calls, owner={**owner, '_session': 'session'},
                           creator={'_agent_id': 'creator'}, child={'_agent_id': 'child'}, sibling={'_agent_id': 'sibling'})


async def create(e, **changes):
    values = {'name': 'Guest setup', 'description': 'Configure guest access', 'text': '@literal full text secret'} | changes
    return await e.service.save_skill(e.creator, 'creator', **values)


async def request(e, skill_id, **changes):
    return await e.service.request_skill_global('creator', skill_id, 'Useful to all agents',
        **({'conversation_id': 'conversation', 'run_id': 'run', 'call_id': 'call'} | changes))


async def test_metadata_is_lazy_encrypted_and_visible_to_creator_and_ancestors_only(env):
    e = env
    skill = await create(e)
    assert 'text' not in str(skill) and 'literal' not in str(skill)
    assert b'literal' not in e.store.one('SELECT text FROM skills')['text']
    assert [s['id'] for s in await e.service.list_skills({'_agent_id': 'root'})] == [skill['id']]
    assert (await e.service.get_skill(e.creator, skill['id']))['text'] == '@literal full text secret'
    for who in (e.child, e.sibling):
        assert await e.service.list_skills(who) == []
        with pytest.raises(PermissionError):
            await e.service.get_skill(who, skill['id'])
    with pytest.raises(PermissionError):
        await e.service.list_skills({'type': 0, 'userid': 'owner'})


async def test_selected_descendants_can_read_but_never_edit_share_or_publish(env):
    e = env
    skill = await create(e)
    await e.service.share_skill(e.creator, skill['id'], ['child'])
    assert (await e.service.get_skill(e.child, skill['id']))['can_edit'] is False
    assert await e.service.list_skills({'_agent_id': 'grandchild'}) == []
    for operation in (
        e.service.save_skill(e.child, 'creator', 'Changed', 'Changed', 'Changed', skill['id']),
        e.service.share_skill(e.child, skill['id'], ['grandchild']),
        e.service.request_skill_global('child', skill['id'], 'Publish'),
        e.service.share_skill(e.creator, skill['id'], ['sibling']),
        e.service.approve_skill_global(e.child, skill['id'], 1),
        e.service.save_skill(e.creator, 'sibling', 'Spoof', 'Spoof', 'Spoof'),
    ):
        with pytest.raises(PermissionError):
            await operation
    await e.service.share_skill({'_agent_id': 'root'}, skill['id'], [])
    assert await e.service.list_skills(e.child) == []


async def test_owner_approval_and_edit_reapproval_bind_exact_revision(env):
    e = env
    skill = await create(e)
    assert await e.service.list_skills(e.sibling) == []
    await e.service.approve_skill_global(e.owner, skill['id'], 1)
    assert (await e.service.get_skill(e.sibling, skill['id']))['global_shared']
    edited = await e.service.save_skill({'_agent_id': 'root'}, 'creator', 'Updated', 'Updated', 'New full text', skill['id'])
    assert edited['creator_agent_id'] == 'creator' and edited['revision'] == 2 and not edited['global_shared']
    assert await e.service.list_skills(e.sibling) == []
    with pytest.raises(ValueError, match='changed'):
        await e.service.approve_skill_global(e.owner, skill['id'], 1)
    await e.service.approve_skill_global(e.owner, skill['id'], 2)
    e.store.execute("UPDATE sessions SET expires=0 WHERE token_hash='session'")
    with pytest.raises(PermissionError, match='expired'):
        await e.service.approve_skill_global(e.owner, skill['id'], 2)


async def test_global_queue_reuses_owner_approval_exact_snapshot_and_dismissal(env):
    e = env
    skill = await create(e)
    row = await request(e, skill['id'])
    assert row['params'] == {'id': skill['id'], 'revision': 1, 'name': 'Guest setup',
                            'description': 'Configure guest access', 'text': '@literal full text secret'}
    assert row['status'] == 'pending' and await e.service.list_skills(e.sibling) == []
    assert (await request(e, skill['id']))['id'] == row['id']
    await e.service.decide_escalation(e.owner, row['id'], False)
    assert await e.service.list_skills(e.sibling) == []
    second = await request(e, skill['id'], call_id='second')
    await e.service.decide_escalation(e.owner, second['id'], True)
    assert (await e.service.get_skill(e.sibling, skill['id']))['global_shared']
    assert (await e.service.decide_escalation(e.owner, second['id'], True))['status'] == 'approved'


async def test_stale_forged_and_unauthorized_global_queue_requests_are_rejected(env):
    e = env
    skill = await create(e)
    row = await request(e, skill['id'])
    forged = row['params'] | {'text': 'Unreviewed text'}
    with pytest.raises(ValueError, match='exact current'):
        await e.service.request_escalation('creator', 'Publish', 'Useful', 'shareSkillGlobally', forged,
                                          conversation_id='conversation', run_id='run', call_id='forged')
    await e.service.save_skill(e.creator, 'creator', 'Changed', 'Changed', 'Changed', skill['id'])
    with pytest.raises(ValueError, match='changed'):
        await e.service.decide_escalation(e.owner, row['id'], True)
    assert await e.service.list_skills(e.sibling) == []
    assert e.store.one('SELECT status FROM escalation_requests')['status'] == 'pending'
    e.store.execute("UPDATE agents SET escalation_requests_enabled=0 WHERE id='root'")
    with pytest.raises(PermissionError, match='disabled'):
        await request(e, skill['id'], call_id='disabled')


@pytest.mark.parametrize('changes', [{'name': ''}, {'description': ''}, {'text': ''}, {'name': 'x'*101},
                                     {'description': 'x'*501}, {'text': 'x'*60001}, {'text': 'bad\x00text'}])
async def test_required_bounded_skill_fields(env, changes):
    with pytest.raises(ValueError):
        await create(env, **changes)
    assert not env.store.all('SELECT * FROM skills')


async def test_noop_save_and_recipient_changes_preserve_approved_revision(env):
    e = env
    skill = await create(e)
    await e.service.approve_skill_global(e.owner, skill['id'], 1)
    saved = await e.service.save_skill(e.creator, 'creator', ' Guest setup ', ' Configure guest access ',
                                      '@literal full text secret', skill['id'])
    assert saved['revision'] == 1 and saved['global_shared']
    await e.service.share_skill(e.creator, skill['id'], ['child'])
    assert (await e.service.get_skill(e.sibling, skill['id']))['global_shared']


async def test_body_is_never_loaded_under_an_older_global_revision(env, monkeypatch):
    e = env
    skill = await create(e)
    await e.service.approve_skill_global(e.owner, skill['id'], 1)
    original = e.service.list_skills

    async def list_then_edit(identity):
        result = await original(identity)
        e.store.execute('UPDATE skills SET text=?,revision=revision+1,global_revision=NULL WHERE id=?',
                        (e.store.seal('Unapproved revision secret'), skill['id']))
        return result

    monkeypatch.setattr(e.service, 'list_skills', list_then_edit)
    with pytest.raises(PermissionError, match='changed'):
        await e.service.get_skill(e.sibling, skill['id'])


async def test_selected_recipient_loses_access_when_moved_out_of_creator_subtree(env, monkeypatch):
    e = env
    skill = await create(e)
    await e.service.share_skill(e.creator, skill['id'], ['child'])
    original = e.service.agent_chain

    async def moved(agent):
        return [await e.service.agent('root'), agent] if agent['id'] == 'child' else await original(agent)

    monkeypatch.setattr(e.service, 'agent_chain', moved)
    assert await e.service.list_skills(e.child) == []


@pytest.mark.parametrize('human', [False, True])
async def test_editor_descendants_use_one_native_snapshot_for_many_agents(env, monkeypatch, human):
    e = env
    skill = await create(e)
    for index in range(40):
        aid = f'extra-{index}'
        e.store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                        (aid, aid, aid+'-domain', 'account', 'user', e.store.seal({})))
        e.domains.append({'id': aid+'-domain', 'parentdomainid': 'creator-domain', 'level': 2})
    original = e.service.agent_chain
    checked = []

    async def chain(agent):
        checked.append(agent['id'])
        return await original(agent)

    monkeypatch.setattr(e.service, 'agent_chain', chain)
    e.calls.clear()
    result = await e.service.get_skill(e.owner if human else e.creator, skill['id'])
    assert len(result['shareable_agents']) == 42
    snapshots = [call for call in e.calls if 'id' not in call[2]]
    assert len(snapshots) == 1
    assert snapshots[0][0] == ('human' if human else 'creator')
    assert set(checked) <= {'creator'}


@pytest.mark.parametrize('fault', ['disabled', 'missing', 'level', 'cycle'])
async def test_batched_descendants_require_complete_enabled_managed_ancestry(env, fault):
    e = env
    skill = await create(e)
    child = next(d for d in e.domains if d['id'] == 'child-domain')
    if fault == 'disabled':
        e.store.execute("UPDATE agents SET enabled=0 WHERE id='child'")
    elif fault == 'missing':
        e.domains.remove(child)
    elif fault == 'level':
        child['level'] = 9
    else:
        child['parentdomainid'] = 'grandchild-domain'
    available = await e.service.get_skill(e.creator, skill['id'])
    assert not {'child', 'grandchild'} & {a['id'] for a in available['shareable_agents']}
    with pytest.raises(PermissionError, match='descendants'):
        await e.service.share_skill(e.creator, skill['id'], ['grandchild'])


async def test_share_rechecks_native_snapshot_after_domain_move(env):
    e = env
    skill = await create(e)
    assert 'child' in {a['id'] for a in (await e.service.get_skill(e.creator, skill['id']))['shareable_agents']}
    child = next(d for d in e.domains if d['id'] == 'child-domain')
    child['parentdomainid'] = 'sibling-domain'
    with pytest.raises(PermissionError, match='descendants'):
        await e.service.share_skill(e.creator, skill['id'], ['child'])


async def test_global_skill_sharing_keeps_main_agent_as_a_separate_root(env):
    from dirigentenstab.limits import APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT
    e = env
    e.store.execute("DELETE FROM agents WHERE id='root'")
    for aid,domain in [(GLOBAL_ADMIN_AGENT, 'root-domain'), (APP_ROOT_AGENT, 'main-domain'),
                       ('main-child', 'main-child-domain')]:
        e.store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                        (aid, aid, domain, 'account', 'user', e.store.seal({})))
    e.domains.extend([{'id': 'main-domain', 'parentdomainid': 'root-domain', 'level': 1},
                      {'id': 'main-child-domain', 'parentdomainid': 'main-domain', 'level': 2}])
    skill = await e.service.save_skill(e.owner, GLOBAL_ADMIN_AGENT, 'Global setup', 'Setup notes', 'Full text')
    loaded = await e.service.get_skill(e.owner, skill['id'])
    assert not {APP_ROOT_AGENT, 'main-child'} & {a['id'] for a in loaded['shareable_agents']}
