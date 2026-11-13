import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
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
CONFIG = hashlib.sha256(json.dumps([[], True, 5]).encode()).hexdigest()[:32]  # no secrets, sharing on, 5 GiB


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
        self.volumes, self.files, self.subuid, self.fail = {}, {}, '', ()  # volume name -> device option; image path -> bytes

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
        if any(part in command for part in self.fail):
            out.returncode, out.stderr = 1, 'boom'
            return out
        if 'volume inspect' in command:
            name = command.split()[-1]
            out.returncode, out.stdout = (0, self.volumes[name] + '\n') if name in self.volumes else (1, '')
        if ' test -f ' in command:
            out.returncode = 0 if command.split()[-1] in self.files else 1
        if ' stat -c ' in command:
            out.stdout = str(self.files.get(command.split()[-1], 0)) + '\n'
        if 'awk' in command:
            out.stdout = self.subuid
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
    install = next(c for c in conn.commands if 'install -D' in c)
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
    stopped = FakeConn('false key1 sha256:base ' + CONFIG)
    stopped.volumes = {f'ws-home-{AGENT}': SRC}
    await svc.ensure_agent_shell(stopped, agent, 'key1', 'u', 't')
    assert stopped.commands[-1] == f'sudo -n docker start ws-{AGENT}' and not stopped.inputs
    running = FakeConn('true key1 sha256:base ' + CONFIG)
    await svc.ensure_agent_shell(running, agent, 'key1', 'u', 't')
    assert not any(' start ' in c or ' run ' in c for c in running.commands)
    rotated = FakeConn('true oldkey sha256:base ' + CONFIG)
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


class Fresh:
    """Re-reads the agent row on every use so a grant made mid-test is seen."""
    def __init__(self, svc):
        self.svc = svc

    def __getitem__(self, key):
        return self.svc.store.one('SELECT * FROM agents WHERE id=?', (AGENT,))[key]

    def get(self, key, default=None):
        return self.svc.store.one('SELECT * FROM agents WHERE id=?', (AGENT,)).get(key, default)


@pytest.fixture
def agent(svc):
    return Fresh(svc)


def run_cmd(conn, prefix):
    return next(c for c in conn.commands if c.startswith(prefix))


def grant(svc, names):
    svc.store.execute('UPDATE agents SET enabled_secrets=? WHERE id=?', (json.dumps(names), AGENT))


async def test_granted_secrets_go_into_env_file_only_over_stdin_and_bad_ones_are_skipped(svc, agent):
    for name, value in (('CLAUDE_CODE_OAUTH_TOKEN', 'sk-ant-oat-secret'), ('PATH', 'evilpath-value'), ('DIRIGENTENSTAB_MCP_KEY', 'override-key'),
                        ('MULTI', 'line1\nline2-value'), ('UNGRANTED', 'not-granted-value'), ('GH_TOKEN', 'ghp_abcdefgh')):
        svc.save_secret(OWNER, name, value)
    grant(svc, ['CLAUDE_CODE_OAUTH_TOKEN', 'PATH', 'DIRIGENTENSTAB_MCP_KEY', 'MULTI', 'GH_TOKEN'])
    seen = []
    conn = FakeConn()
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 'tok', progress=seen.append)
    assert conn.inputs[0] == ('DIRIGENTENSTAB_MCP_URL=u\nDIRIGENTENSTAB_MCP_KEY=tok\n'
                              'CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat-secret\nGH_TOKEN=ghp_abcdefgh\n')
    joined = '\n'.join(conn.commands)
    assert not any(v in joined for v in ('sk-ant-oat-secret', 'ghp_abcdefgh', 'line1'))
    assert 'DIRIGENTENSTAB_SHARED_LOGINS=1' in joined
    assert 'MULTI' in seen[-1] and 'PATH' in seen[-1] and 'UNGRANTED' not in seen[-1]


async def test_config_label_changes_on_grant_value_or_setting_and_holds_no_values(svc, agent):
    async def label(conn_existing=None):
        conn = FakeConn(conn_existing)
        await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
        run = run_cmd(conn, 'sudo -n docker run')
        return run, run.split('dirigentenstab.config=')[1].split()[0] if 'dirigentenstab.config=' in run else None
    svc.save_secret(OWNER, 'GH_TOKEN', 'ghp_abcdefgh')
    _, none = await label()
    grant(svc, ['GH_TOKEN'])
    run, granted = await label()
    assert 'ghp_abcdefgh' not in run and len(granted) == 32 and granted != none
    assert (await label())[1] == granted
    svc.store.execute("UPDATE secrets SET updated=updated+1 WHERE name='GH_TOKEN'")  # value replaced
    changed = (await label())[1]
    assert changed != granted
    svc.save_agent_shell_storage(OWNER, False, 5)
    assert (await label())[1] != changed
    # matching label: container kept; differing label or none (phase-1/2 container): recreated
    svc.save_agent_shell_storage(OWNER, True, 5)
    stale = FakeConn(f'true key1 sha256:base {granted}')
    await svc.ensure_agent_shell(stale, agent, 'key1', 'u', 't')
    assert any(c.startswith('sudo -n docker rm -f') for c in stale.commands)
    legacy = FakeConn('true key1 sha256:base ' + CONFIG)
    await svc.ensure_agent_shell(legacy, agent, 'key1', 'u', 't')
    assert any(c.startswith('sudo -n docker rm -f') for c in legacy.commands)
    current = (await label())[1]
    keep = FakeConn(f'true key1 sha256:base {current}')
    await svc.ensure_agent_shell(keep, agent, 'key1', 'u', 't')
    assert not any(' rm ' in c or ' run ' in c for c in keep.commands)


async def test_logins_volume_follows_the_setting(svc, agent):
    on = FakeConn()
    await svc.ensure_agent_shell(on, agent, 'key1', 'u', 't')
    assert '-v ws-logins:/home/dev/.logins' in run_cmd(on, 'sudo -n docker run')
    svc.save_agent_shell_storage(OWNER, False, 5)
    off = FakeConn()
    await svc.ensure_agent_shell(off, agent, 'key1', 'u', 't')
    run = run_cmd(off, 'sudo -n docker run')
    assert 'ws-logins' not in run and 'SHARED_LOGINS' not in run


def test_storage_settings_validate_and_need_platform_admin(svc):
    assert svc.shell_share_logins() and svc.shell_home_gib() == 5
    svc.save_agent_shell_storage(OWNER, False, 12)
    assert not svc.shell_share_logins() and svc.shell_home_gib() == 12
    for bad in (0, 51, 2.5, '5', True, None):
        with pytest.raises(ValueError):
            svc.save_agent_shell_storage(OWNER, True, bad)
    with pytest.raises(PermissionError):
        svc.save_agent_shell_storage({'userid': 'x', 'type': 2}, True, 5)


IMG = f'/var/lib/dirigentenstab-shells/homes/{AGENT}.img'
MNT = f'/var/lib/dirigentenstab-shells/homes/{AGENT}.mnt'
SRC = MNT + '/.dshome'  # bind source inside the filesystem: an unmounted image leaves it missing
BIND = f'--driver local --opt type=none --opt o=bind --opt device={SRC}'


async def test_new_home_is_a_sparse_ext4_image_owned_by_the_remapped_dev_user(svc, agent):
    conn = FakeConn()
    conn.subuid = '100000\n'
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    cmds = conn.commands
    steps = [next(i for i, c in enumerate(cmds) if marker in c) for marker in (
        f'truncate -s 5G {IMG}', 'mkfs.ext4 -q -F -E root_owner=101000:101000 ' + IMG, 'docker volume create', 'docker run -d')]
    assert steps == sorted(steps)
    assert f'sudo -n docker volume create {BIND} ws-home-{AGENT}' in cmds
    assert any(c.startswith('sudo -n sh -c') and 'loop,nofail' in c and c.endswith(f'{IMG} {MNT}') for c in cmds)
    assert f'sudo -n chmod 600 {IMG}' in cmds


async def test_home_without_remap_uses_uid_1000_and_format_failure_removes_image(svc, agent):
    conn = FakeConn()
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    assert any('root_owner=1000:1000' in c for c in conn.commands)
    bad = FakeConn()
    bad.fail = ('mkfs.ext4',)
    with pytest.raises(RuntimeError, match='e2fsprogs'):
        await svc.ensure_agent_shell(bad, agent, 'key1', 'u', 't')
    assert f'sudo -n rm -f {IMG}' == bad.commands[-1] and not any('docker run' in c for c in bad.commands)


async def test_plain_volume_is_copied_before_the_old_one_is_removed(svc, agent):
    conn = FakeConn()
    conn.volumes = {f'ws-home-{AGENT}': '<no value>'}
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    cmds = conn.commands

    def index(marker):
        return next(i for i, c in enumerate(cmds) if marker in c)
    copy = index('--entrypoint cp')
    assert f'-v ws-home-{AGENT}:/from -v ws-home-{AGENT}-new:/to dirigentenstab-shell:latest -a /from/. /to/' in cmds[copy]
    assert '--user 0' in cmds[copy] and '--network none' in cmds[copy]
    old_rm = next(i for i, c in enumerate(cmds) if c == f'sudo -n docker volume rm ws-home-{AGENT}')
    recreate = max(i for i, c in enumerate(cmds) if 'docker volume create' in c)
    assert copy < old_rm < recreate < index('docker run -d')
    assert f'sudo -n mv -f {IMG}.new {IMG}' in cmds and cmds.index(f'sudo -n mv -f {IMG}.new {IMG}') < old_rm
    assert f'device={SRC} ws-home-{AGENT}' in cmds[recreate]


async def test_failed_copy_keeps_the_old_volume(svc, agent):
    conn = FakeConn()
    conn.volumes = {f'ws-home-{AGENT}': ''}
    conn.fail = ('--entrypoint cp',)
    with pytest.raises(RuntimeError, match='Could not copy the old home'):
        await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    assert f'sudo -n docker volume rm ws-home-{AGENT}' not in conn.commands
    assert f'sudo -n docker volume rm ws-home-{AGENT}-new' in conn.commands and not any('docker run -d' in c for c in conn.commands)


async def test_migration_resumes_when_only_the_image_is_left(svc, agent):
    conn = FakeConn()
    conn.files = {IMG: 5 << 30}
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    assert not any('mkfs' in c or 'truncate' in c for c in conn.commands)  # existing image reused, volume re-attached
    assert any(c.endswith(f'ws-home-{AGENT}') and 'volume create' in c for c in conn.commands)


async def test_home_grows_on_recreation_and_never_shrinks(svc, agent):
    svc.save_agent_shell_storage(OWNER, True, 8)
    conn = FakeConn()
    conn.volumes, conn.files = {f'ws-home-{AGENT}': SRC}, {IMG: 5 << 30}
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    cmds = conn.commands
    grow = [cmds.index(c) for c in (f'sudo -n truncate -s 8G {IMG}', f'sudo -n e2fsck -fy {IMG}', f'sudo -n resize2fs {IMG}')]
    assert grow == sorted(grow) and grow[-1] < next(i for i, c in enumerate(cmds) if 'docker run -d' in c)
    assert not any('volume create' in c or 'mkfs' in c for c in cmds)
    assert any('mountpoint' in c and 'mount "$1"' in c for c in cmds)
    svc.save_agent_shell_storage(OWNER, True, 2)
    smaller = FakeConn()
    smaller.volumes, smaller.files = {f'ws-home-{AGENT}': SRC}, {IMG: 8 << 30}
    await svc.ensure_agent_shell(smaller, agent, 'key1', 'u', 't')
    assert not any('truncate' in c or 'resize2fs' in c for c in smaller.commands)
    failing = FakeConn()
    failing.volumes, failing.files, failing.fail = {f'ws-home-{AGENT}': SRC}, {IMG: 1 << 30}, ('resize2fs',)
    with pytest.raises(RuntimeError, match='Could not resize'):
        await svc.ensure_agent_shell(failing, agent, 'key1', 'u', 't')
    assert f'sudo -n truncate -s {1 << 30} {IMG}' in failing.commands  # rolled back


def test_login_script_links_heals_and_never_touches_configs(tmp_path):
    script = Path(__file__).parent.parent / 'docker' / 'agent-shell' / 'dirigentenstab.sh'
    home = tmp_path / 'home'
    store = home / '.logins'
    (store / 'codex').mkdir(parents=True)
    (home / '.codex').mkdir()
    (home / '.config/gh').mkdir(parents=True)
    (home / '.gemini').mkdir()
    (home / '.codex/config.toml').write_text('keep')
    (home / '.gemini/settings.json').write_text('keep')
    (store / 'codex/auth.json').write_text('stored')
    (home / '.config/gh/hosts.yml').write_text('local-gh')  # logged in before the link existed, store empty
    (home / '.gemini/oauth_creds.json').write_text('old-gemini')
    (store / 'gemini').mkdir()
    (store / 'gemini/oauth_creds.json').write_text('new-gemini')
    os.utime(home / '.gemini/oauth_creds.json', (1, 1))  # older than the stored one: discarded

    def login(shared='1'):
        env = {'HOME': str(home), 'PATH': os.environ['PATH'], 'DIRIGENTENSTAB_SHARED_LOGINS': shared}
        if not shared:
            del env['DIRIGENTENSTAB_SHARED_LOGINS']
        subprocess.run(['bash', '-c', f'. {script}'], env=env, check=True, capture_output=True)
    login()
    codex, gh, gemini = home / '.codex/auth.json', home / '.config/gh/hosts.yml', home / '.gemini/oauth_creds.json'
    assert codex.is_symlink() and codex.resolve() == store / 'codex/auth.json' and codex.read_text() == 'stored'
    assert gh.is_symlink() and (store / 'gh/hosts.yml').read_text() == 'local-gh'
    assert gemini.is_symlink() and gemini.read_text() == 'new-gemini'
    assert not (home / '.gemini/google_accounts.json').exists() and not (home / '.local').exists()
    assert (home / '.codex/config.toml').read_text() == 'keep' and not (home / '.codex/config.toml').is_symlink()
    assert not (store / 'codex/config.toml').exists() and not (store / 'gemini/settings.json').exists()
    assert stat.S_IMODE((store / 'gh/hosts.yml').stat().st_mode) == 0o600
    # atomic rename replaced the link with a newer real file: moved into the store and re-linked
    codex.unlink()
    codex.write_text('refreshed')
    os.utime(store / 'codex/auth.json', (1, 1))
    login()
    assert codex.is_symlink() and (store / 'codex/auth.json').read_text() == 'refreshed'
    # an older real file never overwrites the store
    codex.unlink()
    codex.write_text('stale')
    os.utime(codex, (1, 1))
    login()
    assert codex.is_symlink() and (store / 'codex/auth.json').read_text() == 'refreshed'
    login()  # idempotent
    assert (store / 'codex/auth.json').read_text() == 'refreshed'
    # sharing off: links into the store that would dangle are removed, real files untouched
    shutil.rmtree(store)
    login(shared='')
    assert not codex.is_symlink() and not codex.exists()


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
                self.existing = 'true key1 sha256:base ' + CONFIG
            return out

    conn = Racing()
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    with pytest.raises(RuntimeError, match='Could not create'):
        class Wrong(Racing):
            async def run(self, command, input=None, check=True):
                out = await FakeConn.run(self, command, input, check)
                if 'docker run' in command:
                    out.returncode, out.stderr = 125, 'boom'
                    self.existing = 'true otherkey sha256:base ' + CONFIG
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


def is_mount(command):
    return command.startswith('sudo -n sh -c') and 'mountpoint -q' in command and 'mount "$1"' in command


async def test_home_directory_is_created_after_every_mount_and_before_the_volume_binds(svc, agent):
    conn = FakeConn()
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    cmds = conn.commands
    mount = next(i for i, c in enumerate(cmds) if is_mount(c))
    prepare = next(i for i, c in enumerate(cmds) if '.dshome.tmp' in c and c.endswith(MNT))
    assert 'lost+found' in cmds[prepare] and '[ -d "$d" ]' in cmds[prepare]  # idempotent, skips lost+found
    assert mount < prepare < next(i for i, c in enumerate(cmds) if 'docker volume create' in c) < next(
        i for i, c in enumerate(cmds) if 'docker run -d' in c)


async def test_first_layout_volume_bound_to_the_root_is_replaced_by_the_subdirectory_volume(svc, agent):
    conn = FakeConn()
    conn.volumes, conn.files = {f'ws-home-{AGENT}': MNT}, {IMG: 5 << 30}
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    cmds = conn.commands
    assert cmds.index(f'sudo -n docker volume rm ws-home-{AGENT}') < next(i for i, c in enumerate(cmds) if f'device={SRC}' in c)


async def test_stopped_container_gets_its_mount_back_before_docker_starts_it(svc, agent):
    stopped = FakeConn('false key1 sha256:base ' + CONFIG)
    stopped.volumes = {f'ws-home-{AGENT}': SRC}
    await svc.ensure_agent_shell(stopped, agent, 'key1', 'u', 't')
    cmds = stopped.commands
    mount = next(i for i, c in enumerate(cmds) if is_mount(c))
    assert mount < cmds.index(f'sudo -n docker start ws-{AGENT}')
    assert any('.dshome.tmp' in c for c in cmds[mount:])
    running = FakeConn('true key1 sha256:base ' + CONFIG)  # nothing to mount for a container that is already running
    await svc.ensure_agent_shell(running, agent, 'key1', 'u', 't')
    assert not any(is_mount(c) for c in running.commands)
    broken = FakeConn('false key1 sha256:base ' + CONFIG)
    broken.volumes = {f'ws-home-{AGENT}': SRC}
    broken.fail = ('mount "$1"',)
    with pytest.raises(RuntimeError, match='Could not mount the home image'):
        await svc.ensure_agent_shell(broken, agent, 'key1', 'u', 't')
    assert f'sudo -n docker start ws-{AGENT}' not in broken.commands  # fails closed: never starts on a bare mount point


async def test_stopped_container_on_a_legacy_home_is_recreated_and_migrated(svc, agent):
    legacy = FakeConn('false key1 sha256:base ' + CONFIG)
    legacy.volumes, legacy.files = {f'ws-home-{AGENT}': MNT}, {IMG: 5 << 30}
    await svc.ensure_agent_shell(legacy, agent, 'key1', 'u', 't')
    cmds = legacy.commands
    assert f'sudo -n docker rm -f ws-{AGENT}' in cmds and f'sudo -n docker volume rm ws-home-{AGENT}' in cmds
    assert cmds.index(f'sudo -n docker rm -f ws-{AGENT}') < next(i for i, c in enumerate(cmds) if '.dshome.tmp' in c)


async def test_second_ensure_on_a_migrated_home_changes_nothing(svc, agent):
    conn = FakeConn()
    conn.volumes, conn.files = {f'ws-home-{AGENT}': SRC}, {IMG: 5 << 30}
    await svc.ensure_agent_shell(conn, agent, 'key1', 'u', 't')
    assert not any('volume create' in c or 'volume rm' in c or 'mkfs' in c for c in conn.commands)
