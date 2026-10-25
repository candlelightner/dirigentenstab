import asyncio
from types import SimpleNamespace

import pytest

from dirigentenstab.cloud import Cloud, CloudError


class Native(Cloud):
    def __init__(self, allowed, *, advertised=None, discovery_error=None):
        super().__init__(SimpleNamespace(), {'apikey': 'synthetic-native-key', 'secretkey': 'synthetic-native-secret'})
        self.allowed = set(allowed)
        self.advertised = advertised
        self.discovery_error = discovery_error
        self.calls = []
        self.identities = []
        self.disabled = False

    async def raw(self, command, params=None):
        self.calls.append((command, params))
        self.identities.append(dict(self.credentials))
        if self.disabled:
            raise CloudError('CloudStack error 401: API key revoked', rejected=True)
        if command == 'listApis':
            if self.discovery_error:
                raise self.discovery_error
            return {'api': [{'name': name, 'params': [{'name': 'id', 'type': 'string'}]}
                            for name in sorted(self.allowed if self.advertised is None else self.advertised)]}
        if command not in self.allowed:
            raise CloudError('CloudStack error 403: API key permission denied', rejected=True)
        return {'success': True}


async def test_native_grant_dispatches_even_when_api_metadata_stays_absent():
    cloud = Native({'listDomains'}, advertised={'listDomains'})
    assert 'newNativeVmOperation' not in await cloud.catalogue()
    cloud.allowed.add('newNativeVmOperation')
    assert await cloud.execute('newNativeVmOperation', {'id': 'owned-vm'}) == {'success': True}
    assert sum(command == 'newNativeVmOperation' for command, _ in cloud.calls) == 1
    assert all(identity == cloud.credentials for identity in cloud.identities)


async def test_native_revocation_rejects_cached_api_without_dispatch_retry():
    cloud = Native({'destroyVirtualMachine'})
    await cloud.catalogue()
    cloud.allowed.remove('destroyVirtualMachine')
    with pytest.raises(CloudError, match='403') as failure:
        await cloud.execute('destroyVirtualMachine', {'id': 'owned-vm'})
    assert failure.value.rejected
    assert sum(command == 'destroyVirtualMachine' for command, _ in cloud.calls) == 1
    assert all(identity == cloud.credentials for identity in cloud.identities)
    assert 'destroyVirtualMachine' not in await cloud.catalogue(refresh=True)


async def test_explicit_catalogue_refresh_tracks_current_native_key_permissions():
    cloud = Native({'listDomains'})
    assert set(await cloud.catalogue()) == {'listDomains'}
    cloud.allowed = {'listVirtualMachines'}
    assert set(await cloud.catalogue(refresh=True)) == {'listVirtualMachines'}


async def test_unknown_api_is_decided_by_native_cloudstack_without_retry():
    cloud = Native({'listDomains'})
    with pytest.raises(CloudError, match='403') as failure:
        await cloud.execute('unavailableNativeApi', {})
    assert failure.value.rejected
    assert [command for command, _ in cloud.calls] == ['listApis', 'unavailableNativeApi']
    assert all(identity == cloud.credentials for identity in cloud.identities)


async def test_native_api_remains_callable_when_list_apis_is_not_permitted():
    cloud = Native({'createServiceOffering'}, discovery_error=CloudError('listApis denied: 403', rejected=True))
    assert await cloud.execute('createServiceOffering', {'name': 'Native offering'}) == {'success': True}
    assert [command for command, _ in cloud.calls] == ['listApis', 'createServiceOffering']
    assert all(identity == cloud.credentials for identity in cloud.identities)


async def test_disabled_native_key_is_never_replaced_with_other_credentials():
    cloud = Native({'listDomains'})
    await cloud.catalogue()
    cloud.calls.clear()
    cloud.disabled = True
    with pytest.raises(CloudError, match='401') as failure:
        await cloud.execute('listDomains', {})
    assert failure.value.rejected
    assert [command for command, _ in cloud.calls] == ['listDomains']
    assert all(identity == cloud.credentials for identity in cloud.identities)


@pytest.mark.parametrize('command', [
    'createServiceOffering', 'updateServiceOffering', 'createRolePermission', 'updateRolePermission',
    'addHost', 'createStoragePool', 'listUserKeys', 'registerUserKeys', 'getUserKeys',
    'getKubernetesClusterConfig', 'createConsoleEndpoint', 'updateHostPassword',
    'discoverGpuDevices', 'updateConfiguration',
])
async def test_native_grants_expose_all_api_families_using_the_same_identity(command):
    cloud = Native({command})
    assert await cloud.execute(command, {}) == {'success': True}
    assert [name for name, _ in cloud.calls] == ['listApis', command]
    assert all(identity == cloud.credentials for identity in cloud.identities)
    cloud.allowed.clear()
    with pytest.raises(CloudError, match='403'):
        await cloud.execute(command, {})
    assert sum(name == command for name, _ in cloud.calls) == 2


@pytest.mark.parametrize('params', [
    {'id': '@/etc/passwd'}, {'id': '"@/etc/passwd'}, {'id': 'safe\x00unsafe'},
    {'id': ['owned-vm']}, {'id': {'nested': 'value'}}, {'id': None}, {'invalid;parameter': 'value'},
])
async def test_native_authorization_keeps_transport_input_guards(params):
    cloud = Native({'newNativeVmOperation'})
    with pytest.raises(ValueError):
        await cloud.execute('newNativeVmOperation', params)
    assert all(command != 'newNativeVmOperation' for command, _ in cloud.calls)


@pytest.mark.parametrize('value', ['file:/storage/native', 'host:/storage/native', 'dir:/storage/native',
                                  'sharedmountpoint:/storage/native', 'remote:https://storage.example'])
async def test_native_cloudstack_decides_path_and_backend_parameters(value):
    cloud = Native({'createStoragePool'})
    assert await cloud.execute('createStoragePool', {'id': value}) == {'success': True}
    assert cloud.calls[-1] == ('createStoragePool', {'id': value})


@pytest.mark.parametrize('parameter', ['apikey', 'secretkey', 'signature', 'sessionkey'])
async def test_raw_api_parameters_cannot_switch_the_signing_identity(parameter):
    cloud = Cloud(SimpleNamespace(), {'apikey': 'own-native-key', 'secretkey': 'own-native-secret'})
    with pytest.raises(ValueError):
        await cloud.raw('listDomains', {parameter: 'different-caller'})


@pytest.mark.parametrize('prefix', ['@', '"@'])
async def test_cloudmonkey_file_reference_never_launches_a_process(tmp_path, prefix):
    marker = tmp_path / 'process-started'
    private = tmp_path / 'private-input'
    private.write_text('synthetic-private-file-content')
    executable = tmp_path / 'fake-cloudmonkey'
    executable.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\n'
                          + f'Path({str(marker)!r}).write_text("started")\nprint("{{}}")\n')
    executable.chmod(0o700)
    cloud = Cloud(SimpleNamespace(cmk=str(executable), cloudstack_url='https://cloudstack.invalid/client/api'),
                  {'apikey': 'own-native-key', 'secretkey': 'own-native-secret'})
    with pytest.raises(ValueError):
        await cloud.raw('createStoragePool', {'url': prefix + str(private)})
    assert not marker.exists()


async def test_native_authorization_never_interprets_model_command_as_cloudmonkey_shell():
    cloud = Native({'listDomains'})
    with pytest.raises(ValueError):
        await cloud.execute('listDomains;cat /etc/passwd', {})
    assert cloud.calls == []


async def test_service_discovers_and_describes_full_native_offering_metadata():
    from dirigentenstab.service import Service

    metadata = {name: {'name': name, 'description': 'Native compute offering',
                       'params': [{'name': parameter, 'type': 'string'} for parameter in
                                  ('name', 'domainid', 'details', 'hostid', 'extraconfig')],
                       'response': [{'name': 'serviceoffering', 'type': 'object'}]}
                for name in ('createServiceOffering', 'updateServiceOffering')}

    async def agent(agent_id):
        return {'id': agent_id, 'domain_id': 'authorized-domain'}

    class Reader:
        async def catalogue(self, *, refresh=False):
            assert refresh
            return metadata

    async def cloud_client(record):
        assert record == {'id': 'agent', 'domain_id': 'authorized-domain'}
        return Reader()

    service = SimpleNamespace(agent=agent, cloud_client=cloud_client)
    matches = await Service.search_api(service, 'agent', 'offering')
    assert {item['name'] for item in matches} == set(metadata)
    for name, api in metadata.items():
        described = await Service.describe_api(service, 'agent', name)
        assert described['params'] == api['params'] and described['response'] == api['response']


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


NATIVE_CREATION_REQUESTS = [
    ('createTemplate', {'name': 'Caller chosen public image', 'displaytext': 'Public image',
                        'ispublic': True, 'isfeatured': True, 'volumeid': 'native-source-volume',
                        'ostypeid': 'native-os'}),
    ('deployVirtualMachine', {'name': 'caller-vm-name', 'displayname': 'Caller VM',
                             'templateid': 'enrolled-template', 'serviceofferingid': 'native-offering',
                             'zoneid': 'native-zone', 'userdata': 'Y3VzdG9tLWNsb3VkLWluaXQ=',
                             'securitygroupnames': 'custom-group'}),
]


@pytest.mark.parametrize('command,params', NATIVE_CREATION_REQUESTS)
@pytest.mark.parametrize('denied', [False, True])
async def test_generic_service_creation_preserves_native_request_and_identity(monkeypatch, command, params, denied):
    from dirigentenstab import service as service_module

    record = {'id': 'agent', 'domain_id': 'owned-domain', 'credentials': b'encrypted-own-pair'}
    calls, audits, lookups = [], [], []
    failure = CloudError('CloudStack error 403: native account permission denied', rejected=True)

    class OwnCloud:
        credentials = {'apikey': 'own-account-api', 'secretkey': 'own-account-secret'}

        async def execute(self, api, arguments):
            calls.append((api, arguments, dict(self.credentials)))
            if denied:
                raise failure
            return {'success': True}

    cloud = OwnCloud()

    async def agent(agent_id):
        assert agent_id == record['id']
        return record

    async def cloud_client(selected):
        assert selected is record
        return cloud

    async def forbidden(*args, **kwargs):
        pytest.fail('Generic native calls must not enter managed or privileged helpers')

    def lookup(sql, args=()):
        lookups.append((sql, args))
        return {'id': 'enrolled-template', 'guest_admin': 1}

    store = SimpleNamespace(one=lookup, audit=lambda *args, **kwargs: audits.append((args, kwargs)))
    service = SimpleNamespace(agent=agent, cloud_client=cloud_client, store=store,
                              settings=SimpleNamespace(max_output=65536), redact=lambda value: value,
                              _deploy_managed=forbidden, _create_private_template=forbidden)
    monkeypatch.setattr(service_module, 'helper_call', forbidden, raising=False)
    if denied:
        with pytest.raises(CloudError, match='403') as result:
            await service_module.Service.execute(service, 'agent', command, params)
        assert result.value is failure
    else:
        assert await service_module.Service.execute(service, 'agent', command, params) == {'success': True}
    assert calls == [(command, params, cloud.credentials)]
    assert calls[0][1] is params
    assert not lookups
    assert audits == [(('agent', command), {'status': 'failed' if denied else 'ok'})]


@pytest.mark.parametrize('command,params', NATIVE_CREATION_REQUESTS)
async def test_managed_enrollment_requires_explicit_opt_in(command, params):
    from dirigentenstab.service import Service

    record, cloud, helpers = {'id': 'agent'}, object(), []

    async def agent(agent_id):
        assert agent_id == 'agent'
        return record

    async def cloud_client(selected):
        assert selected is record
        return cloud

    async def deploy(selected, selected_cloud, arguments):
        helpers.append(('deploy', selected, selected_cloud, arguments))
        return {'enrolled': 'vm'}

    async def template(selected, selected_cloud, arguments):
        helpers.append(('template', selected, selected_cloud, arguments))
        return {'enrolled': 'template'}

    service = SimpleNamespace(agent=agent, cloud_client=cloud_client, _deploy_lock=asyncio.Lock(),
                              _deploy_managed=deploy, _create_private_template=template,
                              store=SimpleNamespace(audit=lambda *args, **kwargs: None),
                              settings=SimpleNamespace(max_output=65536), redact=lambda value: value)
    expected = 'vm' if command == 'deployVirtualMachine' else 'template'
    assert await Service.execute(service, 'agent', command, params, managed=True) == {'enrolled': expected}
    assert helpers == [('deploy' if expected == 'vm' else 'template', record, cloud, params)]


@pytest.mark.parametrize('command', ['help', 'version', 'switch', 'set', 'sync', 'exit', 'sYnC'])
async def test_cloudmonkey_builtin_commands_never_dispatch(command):
    cloud = Cloud(SimpleNamespace(), {'apikey': 'own-key', 'secretkey': 'own-secret'})
    with pytest.raises(ValueError, match='CloudMonkey local commands'):
        await cloud.raw(command)
    with pytest.raises(ValueError, match='CloudMonkey local commands'):
        await cloud.execute(command, {})


async def test_cloudmonkey_local_upload_extension_cannot_read_host_files(tmp_path):
    private = tmp_path / 'private-upload'
    private.write_text('synthetic-private-file')
    cloud = Cloud(SimpleNamespace(), {'apikey': 'own-key', 'secretkey': 'own-secret'})
    with pytest.raises(ValueError, match='local file uploads'):
        await cloud.raw('getUploadParamsForTemplate', {'filepath': str(private)})


async def test_real_cloudmonkey_signed_unknown_api_works_when_discovery_is_denied():
    import base64
    import hashlib
    import hmac
    import os
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    from threading import Thread
    from urllib.parse import parse_qs, quote, urlsplit

    candidates = [Path(__file__).parents[1] / '.work/cmk', Path('/usr/local/bin/cmk')]
    binary = next((path for path in candidates if path.is_file() and os.access(path, os.X_OK)), None)
    if not binary:
        pytest.skip('Optional real CloudMonkey binary is unavailable')
    requests = []
    credentials = {'apikey': 'synthetic-own-native-key', 'secretkey': 'synthetic-own-native-secret'}
    denied = False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            data = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
            values = {key: items[-1] for key, items in parse_qs(data or urlsplit(self.path).query).items()}
            unsigned = '&'.join(key + '=' + quote(value, safe='*-._~')
                                for key, value in sorted(values.items()) if key != 'signature').lower()
            expected = base64.b64encode(hmac.new(credentials['secretkey'].encode(), unsigned.encode(),
                                                  hashlib.sha1).digest()).decode()
            valid = (values.get('apiKey') == credentials['apikey']
                     and hmac.compare_digest(values.get('signature', ''), expected))
            requests.append((values, valid))
            if not valid:
                status, payload = 401, {'errorresponse': {'errorcode': 401, 'cserrorcode': 4350,
                                                         'errortext': 'Invalid synthetic signature'}}
            elif values.get('command') == 'listApis' or denied:
                status, payload = 403, {'errorresponse': {'errorcode': 403, 'cserrorcode': 4350,
                                                         'errortext': 'Native account denied this API'}}
            else:
                status, payload = 200, {'futurenativeoperationresponse': {'success': True, 'name': values['name'],
                                                                         'path': values['path']}}
            import json
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_home = os.environ.get('HOME')
    cloud = Cloud(SimpleNamespace(cmk=str(binary), cloudstack_url=f'http://127.0.0.1:{server.server_port}/client/api'),
                  credentials)
    params = {'name': 'literal $(echo never-executed); value', 'path': 'host:/native/pool'}
    try:
        assert await cloud.execute('futureNativeOperation', params) == {'success': True, **params}
        assert [values['command'] for values, _ in requests] == ['listApis', 'futureNativeOperation']
        denied = True
        with pytest.raises(CloudError, match='403') as failure:
            await cloud.execute('futureNativeOperation', params)
        assert failure.value.rejected
        assert [values['command'] for values, _ in requests] == [
            'listApis', 'futureNativeOperation', 'listApis', 'futureNativeOperation']
        assert all(valid for _, valid in requests)
        assert os.environ.get('HOME') == original_home
    finally:
        await asyncio.to_thread(server.shutdown)
        server.server_close()
        thread.join(timeout=2)
