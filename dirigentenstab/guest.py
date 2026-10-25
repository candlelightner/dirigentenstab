"""Guest-only SSH; neither commands nor model paths reach a host shell."""

import asyncio
import ipaddress
import json
import os
import re
import secrets
import stat
from pathlib import Path

import asyncssh


MAX_FILE = 8 * 1024 * 1024


class OutputLimit(Exception):
    pass


class Guest:
    def __init__(self, service):
        self.service = service
        self.slots = asyncio.Semaphore(4)

    async def _target(self, agent_id, vm_id):
        response = await self.service.execute(agent_id, 'listVirtualMachines', {'id': vm_id})
        machines = response.get('virtualmachine', [])
        vm = next((item for item in machines if item.get('id') == vm_id), None)
        if not vm:
            raise PermissionError('VM is not accessible to this agent')
        if vm.get('state', '').lower() != 'running':
            raise ValueError('VM must be running')
        record = self.service.store.one('SELECT * FROM vm_access WHERE vm_id=?', (vm_id,))
        if not record or not record['host_key']:
            raise ValueError('Managed SSH credentials and a trusted host key are required')
        if record['username'] == 'root':
            raise ValueError('Root SSH identities are forbidden')
        nics = vm.get('nic', [])
        nic = next((item for item in nics if item.get('isdefault')), nics[0] if nics else {})
        address = ipaddress.ip_address(nic.get('ipaddress', ''))
        networks = [ipaddress.ip_network(value.strip())
                    for value in self.service.settings.ssh_networks.split(',') if value.strip()]
        if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified
                or not any(address in network for network in networks)):
            raise PermissionError('VM address is outside approved guest networks')
        # The VM-specific host-key pin also prevents connecting to a host with a reused guest IP.
        local_routes = Path('/proc/net/fib_trie')
        try:
            local_ips = re.findall(r'\|-- ([0-9.]+)\n\s+/32 host LOCAL',
                                   await asyncio.to_thread(local_routes.read_text))
            if str(address) in local_ips:
                raise PermissionError('Host addresses cannot be guest SSH targets')
        except FileNotFoundError:
            pass
        return str(address), record

    def _connection(self, address, record):
        key = asyncssh.import_public_key(record['host_key'])
        known_hosts = ([key], [], [])
        return asyncssh.connect(
            address, port=record['port'], username=record['username'],
            client_keys=[asyncssh.import_private_key(self.service.store.open(record['private_key']))],
            known_hosts=known_hosts, config=None, agent_path=None,
            preferred_auth=['publickey'], connect_timeout=10, login_timeout=10,
        )

    async def run_vm_command(self, agent_id: str, vm_id: str, command: str, timeout: int = 120):  # noqa: ASYNC109
        if not isinstance(command, str) or not command.strip() or len(command) > 32768 or '\0' in command:
            raise ValueError('Command must contain 1–32768 characters without NUL')
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise ValueError('Timeout must be between 1 and 600 seconds')
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        result = {'exit_code': None, 'stdout': '', 'stderr': '', 'timeout': False, 'error': None}
        limit = self.service.settings.max_output

        async def drain(reader, name):
            while data := await reader.read(8192):
                remaining = limit - len(output[name])
                output[name].extend(data[:remaining])
                if len(data) > remaining:
                    raise OutputLimit()

        try:
            async with self.slots, asyncio.timeout(timeout):
                address, record = await self._target(agent_id, vm_id)
                async with self._connection(address, record) as connection:
                    async with connection.create_process(command, encoding=None) as process:
                        tasks = [asyncio.create_task(drain(process.stdout, 'stdout')),
                                 asyncio.create_task(drain(process.stderr, 'stderr')),
                                 asyncio.create_task(process.wait_closed())]
                        try:
                            await asyncio.gather(*tasks)
                            result['exit_code'] = process.exit_status
                        finally:
                            for task in tasks:
                                task.cancel()
                            await asyncio.gather(*tasks, return_exceptions=True)
                            if process.exit_status is None:
                                process.terminate()
                                process.close()
        except TimeoutError:
            result.update(timeout=True, error='Guest command timed out')
        except OutputLimit:
            result['error'] = 'Guest output exceeded the size limit; command stopped'
        except (PermissionError, ValueError):
            self.service.store.audit(agent_id, 'run_vm_command', vm_id, 'denied')
            raise
        except (asyncssh.Error, OSError):
            result['error'] = 'SSH connection or guest execution failed; verify access and host key'
        result.update({name: value.decode('utf-8', errors='replace') for name, value in output.items()})
        self.service.store.audit(agent_id, 'run_vm_command', vm_id, 'error' if result['error'] else 'ok')
        return self.service.redact(result)

    def _workspace(self, agent_id):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', agent_id):
            raise ValueError('Invalid agent identifier')
        base = Path(self.service.settings.workspace)
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = base / agent_id
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink():
            raise PermissionError('Transfer workspace must not be a symlink')
        return path

    @staticmethod
    def _filename(value):
        if (not isinstance(value, str) or not value or value in {'.', '..'}
                or '/' in value or '\\' in value or '\0' in value or len(value) > 255):
            raise ValueError('Local transfer path must be a filename in the agent transfer workspace')
        return value

    async def transfer_vm_file(self, agent_id: str, vm_id: str, source: str,
                               destination: str, direction: str):
        if direction not in {'upload', 'download'}:
            raise ValueError('Direction must be upload or download')
        for value in (source, destination):
            if not isinstance(value, str) or not value or '\0' in value or len(value) > 4096:
                raise ValueError('Invalid file path')
        local_name = self._filename(source if direction == 'upload' else destination)
        workspace = self._workspace(agent_id)
        transferred = 0
        temporary = '.download-' + secrets.token_hex(16)
        directory = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            async with self.slots, asyncio.timeout(120):
                address, record = await self._target(agent_id, vm_id)
                async with self._connection(address, record) as connection:
                    async with connection.start_sftp_client() as sftp:
                        if direction == 'upload':
                            descriptor = os.open(local_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                                 dir_fd=directory)
                            with os.fdopen(descriptor, 'rb') as local:
                                if not stat.S_ISREG(os.fstat(local.fileno()).st_mode):
                                    raise ValueError('Upload source must be a regular file')
                                if os.fstat(local.fileno()).st_size > MAX_FILE:
                                    raise ValueError('File exceeds the 8 MiB transfer limit')
                                async with sftp.open(destination, 'wb') as remote:
                                    while data := local.read(65536):
                                        transferred += len(data)
                                        if transferred > MAX_FILE:
                                            raise ValueError('File exceeds the 8 MiB transfer limit')
                                        await remote.write(data)
                        else:
                            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                                 | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                            with os.fdopen(descriptor, 'wb') as local:
                                async with sftp.open(source, 'rb') as remote:
                                    while data := await remote.read(65536):
                                        transferred += len(data)
                                        if transferred > MAX_FILE:
                                            raise ValueError('File exceeds the 8 MiB transfer limit')
                                        local.write(data)
                                local.flush()
                                os.fsync(local.fileno())
                            os.replace(temporary, local_name, src_dir_fd=directory, dst_dir_fd=directory)
            self.service.store.audit(agent_id, 'transfer_vm_file', vm_id)
            return {'direction': direction, 'bytes': transferred, 'file': local_name}
        except (asyncssh.Error, OSError, TimeoutError):
            self.service.store.audit(agent_id, 'transfer_vm_file', vm_id, 'error')
            raise ValueError('Guest transfer failed; verify access, paths and host key') from None
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    async def prepare_vm_access(self, agent_id: str, vm_id: str):
        """Backend-only: inject the returned public-key cloud-init before the VM's first boot."""
        await self.service.agent(agent_id)
        key = asyncssh.generate_private_key('ssh-ed25519')
        public_key = key.export_public_key().decode().strip()
        self.service.store.execute(
            'INSERT INTO vm_access(vm_id,owner_agent,username,private_key) VALUES(?,?,?,?)',
            (vm_id, agent_id, 'dirigent', self.service.store.seal(key.export_private_key().decode())),
        )
        return '#cloud-config\n' + json.dumps({
            'users': [{'name': 'dirigent', 'shell': '/bin/bash', 'lock_passwd': True,
                       'ssh_authorized_keys': [public_key]}],
            'ssh_pwauth': False, 'disable_root': True,
        })

    async def prepare_vm_config(self, agent_id: str, *, workspace_disk=False):
        """Backend-only: user-data contains the generated guest host private key, never expose it."""
        await self.service.agent(agent_id)
        client_key = asyncssh.generate_private_key('ssh-ed25519')
        host_key = asyncssh.generate_private_key('ssh-ed25519')
        record = {
            'username': 'dirigent', 'private_key': self.service.store.seal(client_key.export_private_key().decode()),
            'host_key': host_key.export_public_key().decode().strip(), 'port': 22,
        }
        config = {
            'users': [{'name': record['username'], 'shell': '/bin/bash', 'lock_passwd': True,
                       'ssh_authorized_keys': [client_key.export_public_key().decode().strip()]}],
            'ssh_pwauth': False, 'disable_root': True,
            'ssh_keys': {'ed25519_private': host_key.export_private_key('openssh').decode(),
                         'ed25519_public': record['host_key']},
        }
        if workspace_disk:
            config.update({
                'disk_setup': {'/dev/vdb': {'table_type': 'gpt', 'layout': True, 'overwrite': False}},
                'fs_setup': [{'device': '/dev/vdb1', 'filesystem': 'ext4', 'label': 'workspace', 'overwrite': False}],
                'mounts': [['LABEL=workspace', '/home/dirigent/workspace', 'ext4', 'defaults,nofail', '0', '2']],
                'runcmd': [['chown', 'dirigent:dirigent', '/home/dirigent/workspace']],
            })
        cloud_init = '#cloud-config\n' + json.dumps(config)
        return cloud_init, record

    def persist_vm_access(self, agent_id: str, vm_id: str, record):
        """Backend-only: retain the identity before dispatch, then bind to the returned VM ID."""
        self.service.store.execute(
            'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
            (vm_id, agent_id, record['username'], record['private_key'], record['host_key'], record['port']),
        )

    async def enroll_host_key(self, agent_id: str, vm_id: str, host_key: str):
        """Backend-only: key must come from the trusted hypervisor console or an administrator."""
        key = asyncssh.import_public_key(host_key).export_public_key().decode().strip()
        record = self.service.store.one('SELECT owner_agent FROM vm_access WHERE vm_id=?', (vm_id,))
        if not record or record['owner_agent'] != agent_id:
            raise PermissionError('Only the VM SSH identity owner can enroll its trusted key')
        self.service.store.execute('UPDATE vm_access SET host_key=? WHERE vm_id=?', (key, vm_id))
        self.service.store.audit(agent_id, 'enroll_vm_host_key', vm_id)
