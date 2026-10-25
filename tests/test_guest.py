import asyncio
import json
import os
from types import SimpleNamespace

import asyncssh
import pytest
from cryptography.fernet import Fernet

from dirigentenstab.guest import Guest
from dirigentenstab import guest as guest_module
from dirigentenstab.store import Store


@pytest.fixture
def guest(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning) '
                  'VALUES(?,?,?,?,?,?,?)', ('agent', 'Agent', 'domain', 'account', 'user',
                                           store.seal({}), store.seal({})))

    class Service:
        settings = SimpleNamespace(workspace=str(tmp_path / 'transfers'), max_output=64,
                                   ssh_networks='10.50.0.0/24')

        def __init__(self):
            self.store = store
            self.vm = {'id': 'vm', 'state': 'Running', 'nic': [{'isdefault': True, 'ipaddress': '10.50.0.2'}]}

        async def execute(self, agent_id, command, params):
            assert agent_id == 'agent' and command == 'listVirtualMachines'
            return {'virtualmachine': [self.vm]} if params['id'] == 'vm' else {}

        async def agent(self, agent_id):
            assert agent_id == 'agent'
            return {'id': 'agent'}

        def redact(self, result):
            return result

    return Guest(Service())


async def test_managed_config_unique_nonroot_credentials_and_hostkey_pin(guest):
    config, record = await guest.prepare_vm_config('agent')
    second_config, second = await guest.prepare_vm_config('agent')
    cloudinit = json.loads(config.split('\n', 1)[1])
    assert cloudinit['users'][0]['name'] == 'dirigent'
    assert not cloudinit['ssh_pwauth'] and cloudinit['disable_root']
    assert 'sudo' not in cloudinit['users'][0]
    assert record['private_key'] != second['private_key']
    assert record['host_key'] != second['host_key'] and config != second_config
    assert record['private_key'].startswith(b'gAAAA')
    guest.persist_vm_access('agent', 'vm', record)
    address, found = await guest._target('agent', 'vm')
    assert address == '10.50.0.2' and found['host_key'] == record['host_key']
    with pytest.raises(PermissionError, match='not accessible'):
        await guest.run_vm_command('agent', 'other-domain-vm', 'id')
    guest.service.vm['nic'][0]['ipaddress'] = '127.0.0.1'
    with pytest.raises(PermissionError, match='outside approved'):
        await guest._target('agent', 'vm')


async def test_backend_workspace_setup_only_initializes_the_new_guest_data_disk(guest):
    text, _ = await guest.prepare_vm_config('agent', workspace_disk=True)
    config = json.loads(text.split('\n', 1)[1])
    assert config['disk_setup'] == {'/dev/vdb': {'table_type': 'gpt', 'layout': True, 'overwrite': False}}
    assert config['fs_setup'][0]['device'] == '/dev/vdb1'
    assert not config['fs_setup'][0]['overwrite']
    assert config['mounts'] == [['LABEL=workspace', '/home/dirigent/workspace', 'ext4', 'defaults,nofail', '0', '2']]
    assert config['runcmd'] == [['chown', 'dirigent:dirigent', '/home/dirigent/workspace']]
    assert 'sudo' not in config['users'][0]


async def test_missing_hostkey_fails_closed_and_paths_never_escape_workspace(guest, tmp_path):
    await guest.prepare_vm_access('agent', 'vm')
    with pytest.raises(ValueError, match='trusted host key'):
        await guest.run_vm_command('agent', 'vm', 'id')
    for path in ('/etc/passwd', '../private', 'a/b', '..', 'a\\b'):
        with pytest.raises(ValueError, match='filename'):
            await guest.transfer_vm_file('agent', 'vm', path, '/tmp/file', 'upload')
    with pytest.raises(ValueError, match='Direction'):
        await guest.transfer_vm_file('agent', 'vm', 'file', '/tmp/file', 'sideways')
    workspace = guest._workspace('agent')
    os.symlink(tmp_path / 'outside', workspace / 'file')
    with pytest.raises(OSError):
        os.open(workspace / 'file', os.O_RDONLY | os.O_NOFOLLOW)


async def test_real_asyncssh_client_pins_host_key_and_bounds_output(guest, monkeypatch):
    client_key = asyncssh.generate_private_key('ssh-ed25519')
    host_key = asyncssh.generate_private_key('ssh-ed25519')

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def public_key_auth_supported(self):
            return True

        def validate_public_key(self, username, key):
            return username == 'dirigent' and key == client_key.convert_to_public()

    async def process_handler(process):
        if process.command == 'failing-test':
            process.stderr.write('assert 1 == 2\n')
            process.exit(1)
        elif process.command == 'many-output':
            process.stdout.write('x' * 1024)
            process.exit(0)
        elif process.command == 'slow':
            await asyncio.sleep(2)
            process.exit(0)
        else:
            process.stdout.write('python result: 42\n')
            process.exit(0)

    async with asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[host_key],
                                     process_factory=process_handler) as server:
        record = {'username': 'dirigent', 'private_key': guest.service.store.seal(client_key.export_private_key().decode()),
                  'host_key': host_key.export_public_key().decode(), 'port': server.get_port()}

        async def target(*args):
            return '127.0.0.1', record

        monkeypatch.setattr(guest, '_target', target)
        result = await guest.run_vm_command('agent', 'vm', 'python-program')
        assert result['exit_code'] == 0 and result['stdout'] == 'python result: 42\n'
        result = await guest.run_vm_command('agent', 'vm', 'failing-test')
        assert result['exit_code'] == 1 and result['stderr'] == 'assert 1 == 2\n'
        result = await guest.run_vm_command('agent', 'vm', 'many-output')
        assert len(result['stdout']) <= 64 and 'size limit' in result['error']
        result = await guest.run_vm_command('agent', 'vm', 'slow', timeout=1)
        assert result['timeout']
        record['host_key'] = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
        result = await guest.run_vm_command('agent', 'vm', 'python-program')
        assert result['exit_code'] is None and result['error']


async def test_real_sftp_roundtrip_rejects_symlinks_and_preserves_file_on_oversize(guest, tmp_path, monkeypatch):
    host_key = asyncssh.generate_private_key('ssh-ed25519')
    remote_root = tmp_path / 'guest-files'
    remote_root.mkdir()

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return False

    async with asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[host_key],
                                     sftp_factory=lambda channel: asyncssh.SFTPServer(channel, chroot=str(remote_root))
                                     ) as server:
        _, record = await guest.prepare_vm_config('agent')
        record.update(host_key=host_key.export_public_key().decode(), port=server.get_port())

        async def target(*args):
            return '127.0.0.1', record

        monkeypatch.setattr(guest, '_target', target)
        workspace = guest._workspace('agent')
        (workspace / 'example.py').write_text('print(6 * 7)\n')
        uploaded = await guest.transfer_vm_file('agent', 'vm', 'example.py', '/example.py', 'upload')
        assert uploaded['bytes'] == 13
        downloaded = await guest.transfer_vm_file('agent', 'vm', '/example.py', 'retrieved.py', 'download')
        assert downloaded['bytes'] == 13
        assert (workspace / 'retrieved.py').read_bytes() == (workspace / 'example.py').read_bytes()
        os.symlink(tmp_path / 'state.db', workspace / 'database-link')
        with pytest.raises(ValueError, match='Guest transfer failed'):
            await guest.transfer_vm_file('agent', 'vm', 'database-link', '/leaked.db', 'upload')
        assert not (remote_root / 'leaked.db').exists()
        os.mkfifo(workspace / 'pipe')
        with pytest.raises(ValueError, match='regular file'):
            await asyncio.wait_for(guest.transfer_vm_file('agent', 'vm', 'pipe', '/pipe', 'upload'), timeout=1)
        monkeypatch.setattr(guest_module, 'MAX_FILE', 8)
        with pytest.raises(ValueError, match='transfer limit'):
            await guest.transfer_vm_file('agent', 'vm', '/example.py', 'retrieved.py', 'download')
        assert (workspace / 'retrieved.py').read_text() == 'print(6 * 7)\n'
        assert not list(workspace.glob('.download-*'))
