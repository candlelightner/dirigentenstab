import asyncio
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab import shell_image
from dirigentenstab.service import Service
from dirigentenstab.store import Store
from tests.test_agent_shell import CONFIG, FakeConn

OWNER = {'userid': 'owner', 'type': 1}
SHA = 'ab' * 32
REPO = {'name': 'docker', 'uri': 'https://download.docker.com/linux/ubuntu', 'suite': 'noble', 'components': ['stable'],
        'key_url': 'https://download.docker.com/linux/ubuntu/gpg'}


# ---- validation and rendering -------------------------------------------------------------------------------

@pytest.mark.parametrize('field,bad', [
    ('apt', 'Upper'), ('apt', '-x'), ('apt', 'a b'), ('apt', 'a;rm -rf /'), ('apt', '$(id)'), ('apt', 'a' * 64), ('apt', 'x\ny'),
    ('npm', 'left pad'), ('npm', 'a;b'), ('npm', '`id`'), ('npm', 'pkg@$(id)'), ('npm', 'https://evil/x.tgz'), ('npm', 'git+ssh://x'),
    ('pip', 'a b'), ('pip', 'x&&id'), ('pip', 'git+https://x/y'), ('pip', '-r/etc/passwd'), ('pip', 'x==1;id'),
    ('harnesses', 'rm'), ('harnesses', 'claude'),
])
def test_bad_names_are_rejected(field, bad):
    with pytest.raises(ValueError):
        shell_image.normalize({field: [bad]})


@pytest.mark.parametrize('url', ['http://x.example/a', 'ftp://x/a', 'https://x/a b', "https://x/a'b", 'https://x/$(id)', 'https://x/a;id',
                                 'https://x/a\nRUN id', 'https://x/a#frag', 'https://', 'https://user:pw@x/a', 'https://x/' + 'a' * 600])
def test_urls_must_be_plain_https(url):
    with pytest.raises(ValueError):
        shell_image.normalize({'urls': [{'name': 'tool', 'url': url, 'sha256': SHA}]})
    with pytest.raises(ValueError):
        shell_image.normalize({'apt_repos': [{**REPO, 'key_url': url}]})


def test_shapes_and_limits_are_strict():
    for bad in ({'run': ['id']}, {'apt': 'git'}, {'apt': [1]}, {'urls': [{'name': 'x', 'url': 'https://x/y'}]}, {'urls': [{'name': 'x', 'url': 'https://x/y', 'sha256': 'ABCD'}]}, {'urls': [{'name': 'x', 'url': 'https://x/y', 'sha256': 'a' * 63}]}, {'urls': [{'name': 'x', 'url': 'https://x/y', 'sha256': ('a' * 63) + ';'}]}, {'urls': [{'name': '../x', 'url': 'https://x/y', 'sha256': SHA}]},
                {'urls': [{'name': 'x', 'url': 'https://x/y', 'sha256': SHA, 'extra': 1}]}, {'apt_repos': [{**REPO, 'components': []}]},
                {'apt_repos': [{**REPO, 'suite': 'no ble;'}]}, {'apt_repos': [{**REPO, 'name': 'A b'}]}, {'apt': [f'p{i}' for i in range(51)]}, []):
        with pytest.raises(ValueError):
            shell_image.normalize(bad)
    assert shell_image.normalize({'apt': ['git', 'git', 'curl'], 'npm': [], 'harnesses': ['qwen', 'gemini']}) == {
        'apt': ['curl', 'git'], 'harnesses': ['gemini', 'qwen']}
    assert shell_image.normalize({'npm': ['typescript@5.4.0', '@scope/pkg'], 'pip': ['httpie==3.2.2', 'ruff']})


def test_empty_spec_renders_nothing_and_full_spec_renders_fixed_template():
    assert shell_image.render({}) == ''
    text = shell_image.render({'harnesses': ['gemini', 'aider'], 'apt': ['ripgrep', 'jq'], 'apt_repos': [REPO], 'npm': ['typescript'],
                              'pip': ['httpie'], 'urls': [{'name': 'tool', 'url': 'https://example.com/a/tool?x=1&y=2', 'sha256': SHA}]})
    lines = text.splitlines()
    assert lines[:3] == ['FROM dirigentenstab-shell:latest', 'USER root', 'ENV DEBIAN_FRONTEND=noninteractive'] and lines[-1] == 'USER dev'
    assert all(line.startswith(('RUN ', 'FROM ', 'USER ', 'ENV ')) for line in lines)
    assert text.count('apt-get install') == 1 and 'jq pipx python3-venv ripgrep' in text
    assert "signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" in text
    assert "npm install -g '@google/gemini-cli' typescript" not in text and 'npm install -g @google/gemini-cli typescript' in text
    assert 'pipx install aider-chat' in text and 'pipx install httpie' in text
    assert "curl -fsSL 'https://example.com/a/tool?x=1&y=2' -o /opt/extra/tool" in text
    assert f"echo '{SHA}  /opt/extra/tool' | sha256sum -c - && chmod 755 /opt/extra/tool" in text


def test_renderer_quotes_even_if_validation_were_bypassed(monkeypatch):
    # Defence in depth: values reach the shell only through shlex.quote.
    hostile = {'npm': ['x; touch /pwned'], 'urls': [{'name': 'a b', 'url': "https://x/y';id;'", 'sha256': SHA}]}
    monkeypatch.setattr(shell_image, 'normalize', lambda spec: spec)
    lines = shell_image.steps(hostile)
    assert "'x; touch /pwned'" in lines[0] and "-o '/opt/extra/a b'" in lines[1] and "'https://x/y'\"'\"';id;'\"'\"''" in lines[1]


def test_hash_covers_dockerfile_and_base_image_id():
    df = shell_image.render({'apt': ['git']})
    first = shell_image.tag('AbC-1', df, 'sha256:aaa')
    assert first.startswith('dirigentenstab-shell-abc-1:') and len(first.split(':')[1]) == 12
    assert shell_image.tag('AbC-1', df, 'sha256:aaa') == first
    assert shell_image.tag('AbC-1', df, 'sha256:bbb') != first
    assert shell_image.tag('AbC-1', shell_image.render({'apt': ['jq']}), 'sha256:aaa') != first


def test_text_editor_round_trip():
    spec = shell_image.normalize({'harnesses': ['qwen'], 'apt': ['git'], 'apt_repos': [REPO], 'npm': ['a'], 'pip': ['b'],
                                  'urls': [{'name': 't', 'url': 'https://x.example/t', 'sha256': SHA}]})
    assert shell_image.from_text(spec['harnesses'], shell_image.to_text(spec)) == spec
    with pytest.raises(ValueError):
        shell_image.from_text([], {'urls': 'only-one-token'})


# ---- service: inheritance, tools, approvals -----------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for aid in ('main', 'child', 'grand', 'sibling'):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (aid, aid.title(), aid, 'account', 'user', store.seal({})))
    for aid in ('main', 'child', 'sibling'):
        store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                      ('c-' + aid, aid, 'owner', 'x', 1, store.seal([])))
        store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                      ('r-' + aid, 'c-' + aid, 'running', aid, 1, 1, store.seal([])))
    private = {'userid': 'owner', 'account': 'admin', 'domainid': 'root', 'type': 1}
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)', ('session', 'csrf', store.seal(private), 99999999999))
    service = Service(store, SimpleNamespace(max_output=4096))
    parents = {'child': 'main', 'grand': 'child', 'sibling': 'main'}

    async def chain(agent):
        out, current = [agent], agent['id']
        while current in parents:
            current = parents[current]
            out.insert(0, store.one('SELECT * FROM agents WHERE id=?', (current,)))
        return out

    async def authorize(identity, agent_id, **kwargs):
        return await service.agent(agent_id)

    async def human_call(identity, command, params):
        return {'listUsers': {'user': [{'id': 'owner', 'state': 'enabled'}]},
                'listAccounts': {'account': [{'name': 'admin', 'domainid': 'root', 'accounttype': 1, 'state': 'enabled'}]},
                'listDomains': {'domain': []}}[command]

    service.agent_chain, service.authorize, service.human_call = chain, authorize, human_call
    return SimpleNamespace(store=store, service=service, owner={**private, '_session': 'session'})


def set_image(e, actor, target, changes, reason='Need it', call='call'):
    return e.service.set_shell_image(actor, target, changes, reason, conversation_id='c-' + actor, run_id='r-' + actor, call_id=call)


async def view(e, agent_id):
    return await e.service.get_shell_image(agent_id)


async def test_inheritance_own_then_nearest_ancestor_then_default(env):
    assert (await view(env, 'grand'))['source'] == 'default' and (await view(env, 'grand'))['spec'] == {}
    await set_image(env, 'main', 'main', {'apt': ['git']})
    got = await view(env, 'grand')
    assert got['source'] == 'inherited' and got['from']['id'] == 'main' and got['spec'] == {'apt': ['git']}
    await set_image(env, 'main', 'child', {'apt': ['jq']})
    got = await view(env, 'grand')
    assert got['from']['id'] == 'child' and got['spec'] == {'apt': ['jq']}
    assert (await view(env, 'child'))['source'] == 'own' and (await view(env, 'sibling'))['from']['id'] == 'main'


async def test_authorization_self_and_descendants_only(env):
    await set_image(env, 'child', 'child', {'apt': ['git']})
    await set_image(env, 'main', 'grand', {'apt': ['jq']})  # ancestor, two levels down
    for actor, target in (('child', 'main'), ('child', 'sibling'), ('grand', 'child'), ('sibling', 'child')):
        with pytest.raises(PermissionError):
            await set_image(env, actor, target, {'apt': ['x']})
        with pytest.raises(PermissionError):
            await env.service.get_shell_image(actor, target)
    assert (await view(env, 'sibling'))['spec'] == {}


async def test_approval_free_fields_apply_at_once_without_escalation(env):
    result = await set_image(env, 'child', None, {'harnesses': ['gemini'], 'apt': ['ripgrep']})
    assert result['request'] is None and result['spec'] == {'apt': ['ripgrep'], 'harnesses': ['gemini']}
    assert env.store.all('SELECT * FROM escalation_requests') == []
    again = await set_image(env, 'child', 'child', {'apt': []})  # removal
    assert again['spec'] == {'harnesses': ['gemini']}
    with pytest.raises(ValueError):
        await set_image(env, 'child', 'child', {})
    with pytest.raises(ValueError):
        await set_image(env, 'child', 'child', {'apt': ['bad;name']})


async def test_approval_fields_create_one_escalation_and_change_nothing_until_approved(env):
    result = await set_image(env, 'child', 'grand', {'apt': ['git'], 'npm': ['typescript'], 'pip': ['httpie'], 'apt_repos': [REPO]})
    assert result['request']['status'] == 'pending' and result['spec'] == {'apt': ['git']}
    rows = env.store.all('SELECT * FROM escalation_requests')
    assert len(rows) == 1 and rows[0]['command'] == 'setShellImage' and rows[0]['agent_id'] == 'child'
    params = env.store.open(rows[0]['params'])
    assert params['agent_id'] == 'grand' and set(params['additions']) == {'npm', 'pip', 'apt_repos'}
    assert any('npm install -g typescript' in line for line in params['rendered'])
    assert 'typescript' in rows[0]['description'] and 'docker' in rows[0]['description']
    pending = (await view(env, 'grand'))['pending']
    assert [p['request_id'] for p in pending] == [rows[0]['id']] and 'npm' not in (await view(env, 'grand'))['spec']
    with pytest.raises(ValueError, match='reason'):
        await set_image(env, 'child', 'grand', {'npm': ['left-pad']}, reason='', call='noreason')


async def test_approve_merges_dismiss_does_not_and_reapplying_known_entries_needs_no_request(env):
    first = await set_image(env, 'child', 'child', {'npm': ['typescript']})
    done = await env.service.decide_escalation(env.owner, first['request']['request_id'], True)
    assert done['status'] == 'approved' and (await view(env, 'child'))['spec'] == {'npm': ['typescript']}
    second = await set_image(env, 'child', 'child', {'npm': ['typescript', 'eslint']}, call='two')
    assert (await view(env, 'child'))['spec'] == {'npm': ['typescript']}  # eslint still pending
    dismissed = await env.service.decide_escalation(env.owner, second['request']['request_id'], False)
    assert dismissed['status'] == 'deferred' and (await view(env, 'child'))['spec'] == {'npm': ['typescript']}
    third = await set_image(env, 'child', 'child', {'npm': ['typescript'], 'apt': ['git']}, call='three')
    assert third['request'] is None and (await view(env, 'child'))['spec'] == {'apt': ['git'], 'npm': ['typescript']}


async def test_inherited_spec_is_the_base_when_an_agent_sets_its_own(env):
    env.service.save_shell_image(env.owner, 'main', {'apt': ['git'], 'npm': ['typescript']})
    result = await set_image(env, 'child', 'child', {'harnesses': ['qwen']})
    assert result['spec'] == {'apt': ['git'], 'harnesses': ['qwen'], 'npm': ['typescript']} and result['request'] is None
    # the same npm entry inherited is already approved: no new request
    assert (await view(env, 'child'))['source'] == 'own'


async def test_approval_revalidates_authority_and_escalation_access(env):
    row = await set_image(env, 'child', 'grand', {'pip': ['httpie']})
    env.store.execute('UPDATE agents SET escalation_requests_enabled=0 WHERE id=?', ('child',))
    failed = await env.service.decide_escalation(env.owner, row['request']['request_id'], True)
    assert failed['status'] == 'failed' and (await view(env, 'grand'))['spec'] == {}
    env.store.execute('UPDATE agents SET escalation_requests_enabled=1 WHERE id=?', ('child',))
    with pytest.raises(ValueError):  # forged request params are refused
        await env.service.request_escalation('child', 'x', 'y', 'setShellImage', {'agent_id': 'grand', 'additions': {'apt': ['git']}, 'rendered': []},
                                             conversation_id='c-child', run_id='r-child', call_id='forged')
    with pytest.raises(PermissionError):
        await env.service.request_escalation('child', 'x', 'y', 'setShellImage', {'agent_id': 'sibling', 'additions': {'pip': ['x']},
                                             'rendered': shell_image.steps({'pip': ['x']}, False)},
                                             conversation_id='c-child', run_id='r-child', call_id='forged2')


async def test_owner_edit_needs_no_approval_and_clearing_inherits(env):
    await set_image(env, 'main', 'main', {'apt': ['git']})
    env.service.save_shell_image(env.owner, 'child', {'npm': ['typescript'], 'apt_repos': [REPO]})
    assert (await view(env, 'child'))['source'] == 'own' and 'apt_repos' in (await view(env, 'child'))['spec']
    env.service.save_shell_image(env.owner, 'child', {})
    assert (await view(env, 'child'))['source'] == 'inherited'
    for identity in ({'userid': 'x', 'type': 2}, {'userid': 'x', 'type': 1, '_agent_id': 'child'}):
        with pytest.raises(PermissionError):
            env.service.save_shell_image(identity, 'child', {})
    with pytest.raises(ValueError):
        env.service.save_shell_image(env.owner, 'child', {'npm': ['a;b']})


# ---- ensure_agent_shell: build, recreate, prune, lock ------------------------------------------------------

AGENT = 'a' * 32


async def shell_env(env):
    env.store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (AGENT, 'Team', AGENT, 'a', 'u', env.store.seal({})))
    return await env.service.agent(AGENT)


async def test_empty_spec_uses_base_image_with_no_build(env):
    agent = await shell_env(env)
    conn = FakeConn()
    await env.service.ensure_agent_shell(conn, agent, 'k', 't')
    assert not any('docker build' in c for c in conn.commands)
    assert any(c.startswith('sudo -n docker run') and c.endswith(' dirigentenstab-shell:latest') for c in conn.commands)


async def test_build_recreate_prune_sequence_and_progress(env):
    agent = await shell_env(env)
    env.service._write_shell_spec(AGENT, {'apt': ['git']})
    tag = shell_image.tag(AGENT, shell_image.render({'apt': ['git']}), 'sha256:base')
    conn = FakeConn('true key1 sha256:old ' + CONFIG)
    conn.missing_images = {tag}
    conn.tags = [f'dirigentenstab-shell-{AGENT}:oldoldoldold', tag]

    real = conn.run

    async def run(command, input=None, check=True):
        out = await real(command, input, check)
        if 'docker build' in command:
            conn.missing_images.discard(tag)
            conn.image_ids[tag] = 'sha256:new'
        if "'{{.Id}}'" in command and command.endswith(tag):
            pass
        return out
    conn.run = run
    progress = []
    await env.service.ensure_agent_shell(conn, agent, 'key1', 't', progress=progress.append)
    cmds = conn.commands
    build = next(i for i, c in enumerate(cmds) if 'docker build' in c)
    assert cmds[build] == f'sudo -n timeout 900 docker build -t {tag} -' and conn.inputs[0] == shell_image.render({'apt': ['git']})
    remove = next(i for i, c in enumerate(cmds) if c.startswith('sudo -n docker rm -f'))
    start = next(i for i, c in enumerate(cmds) if c.startswith('sudo -n docker run'))
    prune = next(i for i, c in enumerate(cmds) if 'docker image rm' in c)
    assert build < remove < start < prune and cmds[start].endswith(' ' + tag)
    assert cmds[prune].endswith(f'dirigentenstab-shell-{AGENT}:oldoldoldold') and not any(c.endswith(tag) and 'image rm' in c for c in cmds)
    assert progress[0] == 'Building image…'


async def test_matching_image_and_key_needs_no_build_or_recreate(env):
    agent = await shell_env(env)
    env.service._write_shell_spec(AGENT, {'apt': ['git']})
    conn = FakeConn('true key1 sha256:base ' + CONFIG)
    await env.service.ensure_agent_shell(conn, agent, 'key1', 't')
    assert not any(' build ' in c or ' rm ' in c or ' run ' in c for c in conn.commands)


async def test_base_rebuild_recreates_the_container(env):
    agent = await shell_env(env)
    conn = FakeConn('true key1 sha256:oldbase ' + CONFIG)
    await env.service.ensure_agent_shell(conn, agent, 'key1', 't')
    assert any(c.startswith('sudo -n docker rm -f') for c in conn.commands) and any(c.startswith('sudo -n docker run') for c in conn.commands)


async def test_build_failure_is_bounded_and_leaves_the_container(env):
    agent = await shell_env(env)
    env.service._write_shell_spec(AGENT, {'apt': ['git']})
    conn = FakeConn('true key1 sha256:old ' + CONFIG)
    tag = shell_image.tag(AGENT, shell_image.render({'apt': ['git']}), 'sha256:base')
    conn.missing_images = {tag}
    conn.build_result = (1, 'x' * 5000 + 'E: Unable to locate package git')
    with pytest.raises(RuntimeError, match='Image build failed') as caught:
        await env.service.ensure_agent_shell(conn, agent, 'key1', 't')
    assert len(str(caught.value)) < 700 and str(caught.value).endswith('git')
    assert not any('rm -f' in c for c in conn.commands)


async def test_builds_are_serialized_per_agent(env):
    agent = await shell_env(env)
    env.service._write_shell_spec(AGENT, {'apt': ['git']})
    tag = shell_image.tag(AGENT, shell_image.render({'apt': ['git']}), 'sha256:base')
    missing, builds = {tag}, []

    class Conn(FakeConn):
        async def run(self, command, input=None, check=True):
            self.missing_images = set(missing)
            if 'docker build' in command:
                builds.append(command)
                await asyncio.sleep(0.05)
                missing.clear()
            return await super().run(command, input, check)

    waiting = []
    await asyncio.gather(env.service.ensure_agent_shell(Conn(), agent, 'k', 't'),
                         env.service.ensure_agent_shell(Conn(), agent, 'k', 't', progress=waiting.append))
    assert len(builds) == 1 and waiting[0].startswith('Waiting')


async def test_url_approval_shows_sha256_and_requires_it(env):
    entry = {'name': 'tool', 'url': 'https://x.example/t', 'sha256': SHA}
    result = await set_image(env, 'child', 'child', {'urls': [entry]})
    row = env.store.one('SELECT description,params FROM escalation_requests')
    assert SHA in row['description'] and any(SHA in line for line in env.store.open(row['params'])['rendered'])
    assert result['request']['status'] == 'pending'
    with pytest.raises(ValueError):
        await set_image(env, 'child', 'child', {'urls': [{'name': 'tool', 'url': 'https://x.example/t'}]}, call='nosha')
