import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import asyncssh
import pytest
from cryptography.fernet import Fernet

from dirigentenstab.auth import Auth
from dirigentenstab.service import Service
from dirigentenstab.store import Store
from dirigentenstab.web import hierarchy_nodes, TerminalSession, XtermSSHSession


@pytest.fixture
def service_and_store(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    db_path = tmp_path / 'state.db'
    store = Store(str(db_path), str(key))
    settings = SimpleNamespace(
        workspace=str(tmp_path / 'transfers'),
        max_output=64,
        ssh_networks='10.50.0.0/24',
        cloudstack_url='https://cloud.invalid/client/api',
        session_seconds=3600,
    )
    store.execute(
        'INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) '
        'VALUES(?,?,?,?,?,?)',
        ('agent-1', 'Test Agent', 'domain-1', 'account-1', 'user-1', store.seal({'apikey': 'agent-key'})),
    )
    store.execute(
        'INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) '
        'VALUES(?,?,?,?,?,?)',
        ('agent-2', 'Other Agent', 'domain-2', 'account-2', 'user-2', store.seal({'apikey': 'other-key'})),
    )
    srv = Service(store, settings)
    return srv, store


def test_migration_drops_stored_owner_private_keys(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    path = tmp_path / 'old.db'
    conn = sqlite3.connect(path)
    for n in range(1, 21):
        conn.executescript((Path(__file__).parent.parent / 'dirigentenstab/migrations' / f'{n:03}.sql').read_text())
    conn.execute("INSERT INTO user_ssh_keys(user_id,private_key,public_key,created,updated) VALUES('u',x'00','p',0,0)")
    conn.execute('PRAGMA user_version=20')
    conn.commit()
    conn.close()
    store = Store(str(path), str(key))
    assert store.one("SELECT name FROM sqlite_master WHERE name='user_ssh_keys'") is None


async def test_target_vm_authorization_and_ownership_enforcement(service_and_store, monkeypatch):
    service, store = service_and_store
    identity = {'userid': 'owner', 'type': 2, '_session': 'sess'}

    # Authorize mock: only domain-1 is visible
    async def human_call(ident, command, params=None):
        if command == 'listDomains':
            return {'domain': [{'id': 'domain-1'}]}
        return {}

    monkeypatch.setattr(service, 'human_call', human_call)

    # Managed VM belonging to agent-1 (domain-1)
    host_key = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
    store.execute(
        'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
        ('vm-1', 'agent-1', 'dirigent', store.seal('agent-priv'), host_key, 22),
    )
    # Managed VM belonging to agent-2 (domain-2 - unauthorized)
    store.execute(
        'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
        ('vm-2', 'agent-2', 'dirigent', store.seal('agent-priv'), host_key, 22),
    )

    # Mock cloud client for agent-1
    vm_state = {'state': 'Running'}

    class MockCloud:
        async def raw(self, command, params):
            if command == 'listVirtualMachines' and params.get('id') == 'vm-1':
                return {'virtualmachine': [{
                    'id': 'vm-1',
                    'name': 'test-vm',
                    'state': vm_state['state'],
                    'nic': [{'isdefault': True, 'ipaddress': '10.50.0.10'}],
                }]}
            return {'virtualmachine': []}

    async def cloud_client(agent):
        return MockCloud()

    monkeypatch.setattr(service, 'cloud_client', cloud_client)

    # Authorized access to vm-1 succeeds
    addr, record, vm = await service.target_vm(identity, 'vm-1')
    assert addr == '10.50.0.10'
    assert record['username'] == 'dirigent'
    assert vm['name'] == 'test-vm'

    # Unauthorized access to vm-2 (agent-2 in domain-2) fails
    with pytest.raises(PermissionError, match='outside your CloudStack domain'):
        await service.target_vm(identity, 'vm-2')

    # VM stopped fails
    vm_state['state'] = 'Stopped'
    with pytest.raises(ValueError, match='Stopped'):
        await service.target_vm(identity, 'vm-1')

    # VM not in vm_access fails
    with pytest.raises(ValueError, match='trusted host key are required'):
        await service.target_vm(identity, 'non-existent-vm')

    # VM in vm_access but deleted / absent from CloudStack fails
    store.execute(
        'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
        ('vm-deleted', 'agent-1', 'dirigent', store.seal('agent-priv'), host_key, 22),
    )
    with pytest.raises(PermissionError, match='not accessible or does not exist'):
        await service.target_vm(identity, 'vm-deleted')

    # Missing host key fails
    store.execute('UPDATE vm_access SET host_key=NULL WHERE vm_id=?', ('vm-1',))
    with pytest.raises(ValueError, match='trusted host key are required'):
        await service.target_vm(identity, 'vm-1')


async def test_host_key_pinning_and_terminal_interactive_lifecycle(service_and_store, monkeypatch):
    service, store = service_and_store
    identity = {'userid': 'owner', 'type': 1, '_session': 'sess'}

    user_key = asyncssh.generate_private_key('ssh-ed25519')

    server_host_key = asyncssh.generate_private_key('ssh-ed25519')

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def public_key_auth_supported(self):
            return True

        def validate_public_key(self, username, key):
            return username == 'dirigent' and key == user_key.convert_to_public()

    async def process_handler(process):
        data = await process.stdin.read(1024)
        process.stdout.write(b'echo:' + (data.encode() if isinstance(data, str) else data))
        await process.stdout.drain()
        process.exit(0)

    async with asyncssh.create_server(Server, '127.0.0.1', 0, server_host_keys=[server_host_key],
                                     process_factory=process_handler) as server:
        port = server.get_port()

        # Target VM configured with pinned host key matching the server
        record = {
            'username': 'dirigent',
            'private_key': store.seal(user_key.export_private_key().decode()),
            'host_key': server_host_key.export_public_key().decode(),
            'port': port,
            'owner_agent': 'agent-1',
        }
        vm = {'id': 'vm-1', 'name': 'echo-vm'}

        async def target_vm(ident, vm_id):
            return '127.0.0.1', record, vm

        monkeypatch.setattr(service, 'target_vm', target_vm)

        # 1. Successful connection with pinned host key
        conn, connected_vm = await service.open_vm_terminal_connection(identity, 'vm-1')
        assert connected_vm['name'] == 'echo-vm'
        assert store.one("SELECT 1 FROM audit WHERE actor='owner' AND operation='open-vm-terminal'")

        # Establish session with dummy terminal
        received_data = []

        class DummyTerm:
            def write(self, data):
                received_data.append(data)

        disconnected_events = []
        term = DummyTerm()
        chan, ssh_sess = await conn.create_session(
            lambda: XtermSSHSession(term, lambda err: disconnected_events.append(err)),
            term_type='xterm-256color',
            term_size=(80, 24),
            encoding=None,
        )

        session = TerminalSession('owner', 'vm-1', conn, chan, term)
        service.register_terminal_session(session)
        assert id(session) in service._terminal_sessions

        # Test sending data and receiving echo
        chan.write(b'hello-vm\n')
        await asyncio.sleep(0.3)
        assert any(b'hello-vm' in chunk for chunk in received_data)

        # Test session closure
        session.close()
        assert chan.is_closing()
        service.unregister_terminal_session(session)

        # 2. Host key mismatch rejection
        wrong_host_key = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
        record['host_key'] = wrong_host_key
        with pytest.raises((asyncssh.Error, OSError)):
            await service.open_vm_terminal_connection(identity, 'vm-1')


async def test_terminal_fails_closed_without_authorization_or_access(service_and_store, monkeypatch):
    service, store = service_and_store
    identity = {'userid': 'owner', 'type': 2, '_session': 'sess'}
    host_key = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
    store.execute(
        'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
        ('vm-1', 'agent-1', 'dirigent', store.seal('k'), host_key, 22),
    )
    store.execute(
        'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
        ('vm-nohost', 'agent-1', 'dirigent', store.seal('k'), None, 22),
    )

    async def human_call(ident, command, params=None):
        return {'domain': []}

    connects = []

    async def connect(*args, **kwargs):
        connects.append(args)

    monkeypatch.setattr(service, 'human_call', human_call)
    monkeypatch.setattr(asyncssh, 'connect', connect)
    with pytest.raises(PermissionError):
        await service.open_vm_terminal_connection(identity, 'vm-1')
    with pytest.raises(ValueError, match='trusted host key'):
        await service.open_vm_terminal_connection(identity, 'vm-nohost')
    with pytest.raises(ValueError, match='trusted host key'):
        await service.open_vm_terminal_connection(identity, 'missing')
    assert not connects


async def test_auth_logout_closes_terminal_sessions(service_and_store, monkeypatch):
    service, store = service_and_store
    auth = Auth(service)

    token = 'test-token'
    hashed = auth.digest(token)
    store.execute(
        'INSERT INTO sessions(token_hash,csrf,identity,expires) VALUES(?,?,?,?)',
        (hashed, 'csrf', store.seal({'userid': 'user-42', 'sessionkey': 'sk', 'cookies': {}}), 9999999999),
    )

    closed = []
    dummy_session = SimpleNamespace(
        user_id='user-42',
        close=lambda: closed.append('closed-session'),
    )
    service.register_terminal_session(dummy_session)

    # Revoke (logout)
    await auth.revoke(token)
    assert 'closed-session' in closed
    assert id(dummy_session) not in service._terminal_sessions


def test_hierarchy_nodes_modes():
    data = {
        'domains': [
            {'id': 'root', 'name': 'ROOT', 'level': 0},
            {'id': 'sub-domain', 'name': 'Engineering', 'parentdomainid': 'root'},
            {'id': 'other-domain', 'name': 'Marketing', 'parentdomainid': 'root'},
        ],
        'agents': [
            {'id': 'eng-agent', 'name': 'Eng Admin', 'domain_id': 'sub-domain'},
            {'id': 'mkt-agent', 'name': 'Mkt Admin', 'domain_id': 'other-domain'},
        ],
        'vms': [
            {'id': 'vm-eng-1', 'name': 'build-server', 'owner_agent': 'eng-agent'},
        ],
    }

    # Agents only
    agents_nodes = hierarchy_nodes(data, mode='Agents')
    assert len(agents_nodes) == 2
    assert 'build-server' not in str(agents_nodes)
    assert not any('selectable' in str(node) and not node.get('selectable', True) for node in agents_nodes)

    # Agents and VMs
    both_nodes = hierarchy_nodes(data, mode='Agents and VMs')
    eng_node = next(n for n in both_nodes if n['id'] == 'agent:eng-agent')
    assert any(c['id'] == 'vm:vm-eng-1' and c['label'] == 'build-server' for c in eng_node['children'])
    mkt_node = next(n for n in both_nodes if n['id'] == 'agent:mkt-agent')
    assert len(mkt_node['children']) == 0

    # VMs only: Engineering branch kept (with non-clickable ancestor labels), Marketing pruned
    vm_nodes = hierarchy_nodes(data, mode='VMs')
    assert len(vm_nodes) == 1
    assert vm_nodes[0]['id'] == 'agent:eng-agent'
    assert vm_nodes[0]['selectable'] is False
    assert vm_nodes[0]['children'][0]['id'] == 'vm:vm-eng-1'
    assert vm_nodes[0]['children'][0]['label'] == 'build-server'
    assert 'Marketing' not in str(vm_nodes)


@pytest.mark.parametrize('url', [
    'https://console.example:8443/?ticket=secret', 'http://10.0.0.1/console',
    'https:///missing-host', 'javascript:alert(1)', '//console.example/',
    'https://@console.example/', 'https://user:password@console.example/', 'https://console.example:bad/',
    'https://console.example:0/', 'https://console.example/\nattack',
    'https://console.example\\@evil.example/', None,
])
async def test_vm_console_url_validation_and_native_identity(service_and_store, monkeypatch, url):
    service, _ = service_and_store
    identity = {'userid': 'human'}

    async def call(actor, command, params):
        assert actor is identity
        assert command == 'createConsoleEndpoint'
        assert params == {'virtualmachineid': 'vm-1'}
        return {'consoleendpoint': {'success': True, 'url': url}}

    monkeypatch.setattr(service, 'human_call', call)
    if url in ('https://console.example:8443/?ticket=secret', 'http://10.0.0.1/console'):
        assert await service.vm_console_url(identity, 'vm-1') == url
    else:
        with pytest.raises(ValueError, match='Console unavailable'):
            await service.vm_console_url(identity, 'vm-1')


async def test_vm_console_error(service_and_store, monkeypatch):
    service, _ = service_and_store

    async def call(*args):
        return {'consoleendpoint': {'success': False, 'details': 'VM stopped'}}

    monkeypatch.setattr(service, 'human_call', call)
    with pytest.raises(ValueError, match='VM stopped'):
        await service.vm_console_url({'userid': 'human'}, 'vm-1')
