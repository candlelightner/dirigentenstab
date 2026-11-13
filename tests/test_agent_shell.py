from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab import mcp_export
from dirigentenstab.limits import APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT
from dirigentenstab.service import SHELL_TAG, Service
from dirigentenstab.store import Store
from dirigentenstab.web_vm import Mods, arrow, modified

OWNER = {'userid': 'owner', 'type': 1}
AGENT = 'a' * 32


@pytest.fixture
def svc(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    for agent_id in (APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT, 'lower', AGENT):
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (agent_id, 'Team Alpha' if agent_id == AGENT else agent_id, agent_id + '-d', 'a', 'u', store.seal({})))
    for vm_id, owner in (('vm-main', APP_ROOT_AGENT), ('vm-global', GLOBAL_ADMIN_AGENT), ('vm-lower', 'lower')):
        store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
                      (vm_id, owner, 'dirigent', store.seal('k'), 'ssh-ed25519 AAAA', 22))
    service = Service(store, SimpleNamespace(origin='https://hub.example', max_output=64))
    service.tags = []

    async def raw(command, params):
        assert command == 'listTags' and params['key'] == SHELL_TAG
        return {'tag': [{'key': SHELL_TAG, 'resourceid': vm} for vm in service.tags]}

    async def cloud_client(agent):
        return SimpleNamespace(raw=raw)

    service.cloud_client = cloud_client
    service.parents = {}

    async def agent_chain(agent):  # root first, the agent itself last
        chain, current = [agent], agent['id']
        while current in service.parents:
            current = service.parents[current]
            chain.insert(0, store.one('SELECT * FROM agents WHERE id=?', (current,)))
        return chain

    service.agent_chain = agent_chain
    return service


def test_host_candidates_are_only_global_admin_or_root_main_agent_vms(svc):
    assert sorted(svc.agent_shell_hosts()) == ['vm-global', 'vm-main']
    svc.save_agent_shell_host(OWNER, 'vm-main')
    with pytest.raises(ValueError):
        svc.save_agent_shell_host(OWNER, 'vm-lower')
    with pytest.raises(PermissionError):
        svc.save_agent_shell_host({'userid': 'x', 'type': 2}, 'vm-main')
    with pytest.raises(PermissionError):
        svc.save_agent_shell_host({'userid': 'x', 'type': 1, '_agent_id': 'lower'}, '')


async def test_setting_is_revalidated_and_tag_path_resolves(svc):
    assert await svc.agent_shell_host(fresh=True) == ''
    svc.save_agent_shell_host(OWNER, 'vm-main')
    assert await svc.agent_shell_host() == 'vm-main'
    svc.store.execute("UPDATE vm_access SET owner_agent='lower' WHERE vm_id='vm-main'")  # stale setting must not be trusted
    assert await svc.agent_shell_host(fresh=True) == ''
    svc.tags = ['vm-global', 'vm-lower']  # a tag on a lower agent's VM never qualifies
    assert await svc.agent_shell_host(fresh=True) == 'vm-global'
    svc.save_agent_shell_host(OWNER, '')
    svc.tags = ['vm-global', 'vm-lower', 'vm-main']
    svc.store.execute("UPDATE vm_access SET owner_agent=? WHERE vm_id='vm-main'", (APP_ROOT_AGENT,))
    with pytest.raises(ValueError, match='Several agent shell hosts tagged'):
        await svc.agent_shell_host(fresh=True)
    svc.save_agent_shell_host(OWNER, 'vm-main')  # the Platform setting wins over ambiguous tags
    assert await svc.agent_shell_host(fresh=True) == 'vm-main'


async def test_open_agent_shell_rejects_bad_ids_and_missing_host(svc):
    for bad in ('', 'x y', 'a;rm -rf /', '$(id)', 'a' * 65, None):
        with pytest.raises(ValueError, match='Invalid agent'):
            await svc.open_agent_shell(OWNER, bad)

    async def authorize(identity, agent_id, **kwargs):
        return await svc.agent(agent_id)

    svc.authorize = authorize
    with pytest.raises(ValueError, match='No agent shell host'):
        await svc.open_agent_shell(OWNER, AGENT)


class FakeConn:
    def __init__(self, existing=None, ready=True):
        self.commands, self.inputs, self.existing, self.ready = [], [], existing, ready
        self.missing_images, self.image_ids, self.build_result, self.tags = set(), {}, (0, ''), []

    async def run(self, command, input=None, check=True):
        self.commands.append(command)
        if input is not None:
            self.inputs.append(input)
        out = SimpleNamespace(returncode=0, stdout='', stderr='')
        if not self.ready and ('image inspect' in command or 'network inspect' in command):
            out.returncode = 1
        if 'image inspect -f' in command and not out.returncode:
            tag = command.split()[-1]
            if tag in self.missing_images:
                out.returncode = 1
            else:
                out.stdout = self.image_ids.get(tag, 'sha256:base') + '\n'
        if 'docker build' in command:
            out.returncode, out.stderr = self.build_result
        if "image ls" in command:
            out.stdout = '\n'.join(self.tags)
        if 'docker inspect -f' in command:
            if self.existing is None:
                out.returncode = 1
            else:
                out.stdout = self.existing + '\n'
        return out


async def test_ensure_creates_container_with_env_file_over_stdin_only(svc):
    agent = await svc.agent(AGENT)
    conn = FakeConn()
    await svc.ensure_agent_shell(conn, agent, 'key1', f'https://hub.example/mcp/{AGENT}', 'dsk_secret', '10.0.0.5 hub.example')
    joined = '\n'.join(conn.commands)
    assert 'dsk_secret' not in joined and conn.inputs == [
        f'DIRIGENTENSTAB_MCP_URL=https://hub.example/mcp/{AGENT}\nDIRIGENTENSTAB_MCP_KEY=dsk_secret\n']
    install = next(c for c in conn.commands if 'install' in c)
    assert install == f'sudo -n install -D -m 600 /dev/stdin /var/lib/dirigentenstab-shells/{AGENT}.env'
    run = next(c for c in conn.commands if c.startswith('sudo -n docker run'))
    assert run.startswith('sudo -n docker run -d --name ws-' + AGENT)
    for part in ('--hostname team-alpha', '--restart unless-stopped', '--network dirigentenstab-shells',
                 '--label dirigentenstab.key=key1', f'-v ws-home-{AGENT}:/home/dev', '--add-host hub.example:10.0.0.5',
                 'dirigentenstab-shell:latest'):
        assert part in run
    for forbidden in ('privileged', 'cap-add', 'docker.sock', '--pid', '--net=host'):
        assert forbidden not in run


async def test_ensure_starts_stopped_reuses_running_recreates_on_new_key_and_requires_setup(svc):
    agent = await svc.agent(AGENT)
    stopped = FakeConn('false key1 sha256:base')
    await svc.ensure_agent_shell(stopped, agent, 'key1', 'u', 't')
    assert stopped.commands[-1] == f'sudo -n docker start ws-{AGENT}' and not stopped.inputs
    running = FakeConn('true key1 sha256:base')
    await svc.ensure_agent_shell(running, agent, 'key1', 'u', 't')
    assert not any(' start ' in c or ' run ' in c for c in running.commands)
    rotated = FakeConn('true oldkey sha256:base')
    await svc.ensure_agent_shell(rotated, agent, 'key2', 'u', 't')
    assert any(c.startswith('sudo -n docker rm -f') for c in rotated.commands) and rotated.inputs
    assert any(c.startswith('sudo -n docker run') for c in rotated.commands)
    with pytest.raises(RuntimeError, match='run the agent-shell-host skill'):
        await svc.ensure_agent_shell(FakeConn(ready=False), agent, 'key1', 'u', 't')


def test_shell_key_is_minted_once_reused_and_reminted_after_revocation(svc):
    first = mcp_export.shell_key(svc, AGENT, 'owner')
    assert mcp_export.shell_key(svc, AGENT, 'owner') == first
    token = first[1]
    row = svc.store.one('SELECT label,hash FROM mcp_export_keys WHERE id=?', (first[0],))
    assert row['label'] == 'shell' and token not in str(row)
    svc.store.execute('UPDATE mcp_export_keys SET revoked=1 WHERE id=?', (first[0],))
    second = mcp_export.shell_key(svc, AGENT, 'owner')
    assert second[0] != first[0] and second[1] != token


def test_ctrl_alt_transform_and_arrows():
    assert modified('c', True, False) == '\x03'
    assert modified('C', True, False) == '\x03'
    assert modified('[', True, False) == '\x1b'
    assert modified('1', True, False) == '1'
    assert modified('x', False, True) == '\x1bx'
    assert modified('d', True, True) == '\x1b\x04'
    assert modified('hello', True, False) == 'hello'
    assert modified('c', False, False) == 'c'
    assert arrow('D', False, False) == '\x1b[D'
    assert arrow('A', True, False) == '\x1b[1;5A'
    assert arrow('C', True, True) == '\x1b[1;7C'


async def test_install_skill_is_idempotent_and_updates_outdated_text(svc):
    async def authorize(identity, agent_id, **kwargs):
        return await svc.agent(agent_id)

    async def human_call(identity, command, params=None):
        return {'domain': []}

    svc.authorize, svc.human_call = authorize, human_call
    first = await svc.install_agent_shell_skill(OWNER)
    again = await svc.install_agent_shell_skill(OWNER)
    assert again['id'] == first['id'] and again['revision'] == first['revision']
    svc.store.execute('UPDATE skills SET text=? WHERE id=?', (svc.store.seal('old'), first['id']))
    assert (await svc.install_agent_shell_skill(OWNER))['revision'] == first['revision'] + 1
    assert len(svc.store.all('SELECT id FROM skills')) == 1
    with pytest.raises(PermissionError):
        await svc.install_agent_shell_skill({'userid': 'x', 'type': 2})


async def test_ensure_treats_concurrent_creation_as_success(svc):
    agent = await svc.agent(AGENT)

    class Racing(FakeConn):
        async def run(self, command, input=None, check=True):
            out = await super().run(command, input, check)
            if 'docker run' in command:
                out.returncode, out.stderr = 125, 'name already in use'
                self.existing = 'true key1 sha256:base'
            return out

    conn = Racing()
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    with pytest.raises(RuntimeError, match='Could not create'):
        class Wrong(Racing):
            async def run(self, command, input=None, check=True):
                out = await FakeConn.run(self, command, input, check)
                if 'docker run' in command:
                    out.returncode, out.stderr = 125, 'boom'
                    self.existing = 'true otherkey sha256:base'
                return out
        await svc.ensure_agent_shell(Wrong(), agent, 'key1', 'u', 't')


def test_mods_one_shot_double_tap_lock():
    m = Mods()
    m.tap('Ctrl', 0)
    assert m.state['Ctrl'] == 'armed' and m.active('Ctrl')
    assert m.release() == ['Ctrl'] and not m.active('Ctrl')
    m.tap('Ctrl', 10)
    m.tap('Ctrl', 10.2)
    assert m.state['Ctrl'] == 'locked'
    assert m.release() == [] and m.active('Ctrl')
    assert m.release() == [] and m.active('Ctrl')
    m.tap('Ctrl', 20)
    assert m.state['Ctrl'] == 'off'
    m.tap('Alt', 30)
    m.tap('Alt', 30.5)  # too slow: unarms
    assert m.state['Alt'] == 'off'
