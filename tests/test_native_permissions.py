import asyncio
from types import SimpleNamespace

import pytest

from dirigentenstab.cloud import Cloud, CloudError, runtime_api


class Native(Cloud):
    def __init__(self, allowed):
        super().__init__(SimpleNamespace(), {'apikey': 'synthetic-native-key', 'secretkey': 'synthetic-native-secret'})
        self.allowed = set(allowed)
        self.calls = []

    async def raw(self, command, params=None):
        self.calls.append((command, params))
        if command == 'listApis':
            return {'api': [{'name': name, 'params': [{'name': 'id', 'type': 'string'}]}
                            for name in sorted(self.allowed)]}
        if command not in self.allowed:
            raise CloudError('CloudStack error 403: API key permission denied', rejected=True)
        return {'success': True}


async def test_native_grant_exposes_new_infrastructure_api_without_application_policy_change():
    cloud = Native({'listDomains'})
    assert 'newNativeVmOperation' not in await cloud.catalogue()
    cloud.allowed.add('newNativeVmOperation')
    assert await cloud.execute('newNativeVmOperation', {'id': 'owned-vm'}) == {'success': True}
    assert sum(command == 'newNativeVmOperation' for command, _ in cloud.calls) == 1
    assert runtime_api('expungeVirtualMachine')
    assert runtime_api('createDomain') and runtime_api('createAccount')


async def test_native_revocation_rejects_cached_api_without_dispatch_retry():
    cloud = Native({'destroyVirtualMachine'})
    await cloud.catalogue()
    cloud.allowed.remove('destroyVirtualMachine')
    with pytest.raises(CloudError, match='403'):
        await cloud.execute('destroyVirtualMachine', {'id': 'owned-vm'})
    assert sum(command == 'destroyVirtualMachine' for command, _ in cloud.calls) == 1
    assert 'destroyVirtualMachine' not in await cloud.catalogue()


async def test_explicit_catalogue_refresh_tracks_current_native_key_permissions():
    cloud = Native({'listDomains'})
    assert set(await cloud.catalogue()) == {'listDomains'}
    cloud.allowed = {'listVirtualMachines'}
    assert set(await cloud.catalogue(refresh=True)) == {'listVirtualMachines'}


async def test_unknown_api_does_not_repeat_fresh_native_discovery():
    cloud = Native({'listDomains'})
    with pytest.raises(PermissionError, match='CloudStack identity and API key'):
        await cloud.execute('unavailableNativeApi', {})
    assert [command for command, _ in cloud.calls] == ['listApis']


@pytest.mark.parametrize('command', ['listUserKeys', 'registerUserKeys', 'getUserKeys', 'updateRolePermission',
                                   'getKubernetesClusterConfig', 'createConsoleEndpoint', 'updateHostPassword',
                                   'createStoragePool', 'discoverGpuDevices', 'updateConfiguration'])
async def test_native_grants_cannot_expose_credentials_or_bypass_host_workflows(command):
    cloud = Native({command})
    assert command in await cloud.catalogue()  # Trusted code can inspect the authoritative native metadata.
    assert not runtime_api(command)
    with pytest.raises(PermissionError, match='trusted server-side workflow'):
        await cloud.execute(command, {})
    assert all(name != command for name, _ in cloud.calls)


@pytest.mark.parametrize('params', [{'id': '@/etc/passwd'}, {'id': '"@/etc/passwd'},
                                  {'id': 'file:/etc/passwd'}, {'id': 'host:/etc/passwd'},
                                  {'id': 'safe\x00unsafe'}, {'id': ['owned-vm']}])
async def test_native_authorization_keeps_transport_and_host_file_guards(params):
    cloud = Native({'newNativeVmOperation'})
    with pytest.raises(ValueError):
        await cloud.execute('newNativeVmOperation', params)
    assert all(command != 'newNativeVmOperation' for command, _ in cloud.calls)


async def test_native_authorization_never_interprets_model_command_as_cloudmonkey_shell():
    cloud = Native({'listDomains'})
    with pytest.raises(PermissionError):
        await cloud.execute('listDomains;cat /etc/passwd', {})
    assert cloud.calls == []


async def test_failed_native_job_explains_permission_denial_without_exposing_key_material():
    class FailedJob(Native):
        async def raw(self, command, params=None):
            if command == 'destroyVirtualMachine':
                return {'jobid': 'owned-job'}
            if command == 'queryAsyncJobResult':
                return {'jobstatus': 2, 'jobresult': {'errorcode': 530, 'errortext':
                    'Account does not have permission for expunging. synthetic-native-key synthetic-native-secret'}}
            return await super().raw(command, params)
    cloud = FailedJob({'destroyVirtualMachine'})
    with pytest.raises(CloudError, match='permission for expunging') as failure:
        await cloud.execute('destroyVirtualMachine', {'id': 'owned-vm'})
    assert '530' in str(failure.value) and 'owned-job' in str(failure.value)
    assert all(secret not in str(failure.value) for secret in cloud.credentials.values())
    assert not failure.value.rejected  # A failed async job can still leave resources requiring reconciliation.


async def test_subprocess_cleanup_cannot_outlive_its_bounded_transport_budget(monkeypatch):
    class Stream:
        async def read(self, size):
            return b''
    class Process:
        stdout, stderr, returncode = Stream(), Stream(), 0
        async def wait(self):
            return 0
        async def communicate(self):
            await asyncio.Event().wait()
    async def launch(*args, **kwargs):
        return Process()
    original_timeout = asyncio.timeout
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', launch)
    monkeypatch.setattr(asyncio, 'timeout', lambda seconds: original_timeout(0.02 if seconds == 5 else seconds))
    cloud = Cloud(SimpleNamespace(cmk='synthetic'), {'apikey': 'synthetic', 'secretkey': 'synthetic'})
    assert await asyncio.wait_for(cloud._process('/dev/shm', ['listUserKeys'], 1024), timeout=0.5) == b''


@pytest.mark.parametrize('text_error', [False, True])
async def test_native_account_permission_denial_is_definitively_rejected_and_sanitized(tmp_path, text_error):
    executable = tmp_path / 'native-denial'
    executable.write_text('''#!/usr/bin/env python3
import json,sys
if sys.argv[1]=='sync':
 print('synced')
elif ''' + repr(text_error) + ''':
 print('Error: (HTTP 531, error code 4350) Caller does not have permission to operate with provided resource. synthetic-private-key')
 sys.exit(1)
else:
 print(json.dumps({'errorresponse':{'errorcode':531,'errortext':'Caller does not have permission to operate with provided resource. synthetic-private-key'}}))
 sys.exit(1)
''')
    executable.chmod(0o700)
    cloud = Cloud(SimpleNamespace(cmk=str(executable), cloudstack_url='http://cloudstack.invalid/client/api'),
                  {'apikey': 'synthetic-private-key', 'secretkey': 'synthetic-secret'})
    with pytest.raises(CloudError, match='531') as failure:
        await cloud.raw('destroyVirtualMachine', {'id': 'unrelated-vm'})
    assert failure.value.rejected
    assert 'synthetic-private-key' not in str(failure.value)
