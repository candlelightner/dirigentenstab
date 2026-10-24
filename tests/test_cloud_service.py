import asyncio
import collections
import json
import os
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab import cloud as cloud_module
from dirigentenstab.cloud import Cloud, CloudError, PROVISION_APIS, RUNTIME_APIS, redact, validate
from dirigentenstab.service import Service
from dirigentenstab.store import Store


@pytest.fixture
def store(tmp_path):
    master = tmp_path / 'master'
    master.write_bytes(Fernet.generate_key())
    return Store(str(tmp_path / 'state.db'), str(master))


def add_parent(store):
    store.execute('INSERT INTO providers VALUES(?,?,?,?,?,?)',
                  ('provider', 'Local', 'chat', 'http://inference/v1', store.seal('provider-secret'), 'default'))
    credentials = {
        purpose: {'id': 'old-' + purpose, 'apikey': 'parent-' + purpose + '-api',
                  'secretkey': 'parent-' + purpose + '-secret'}
        for purpose in ('runtime', 'provisioning')
    }
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,provider_id,'
                  'model,instructions,can_provision) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                  ('parent', 'Parent', 'parent-domain', 'parent-account', 'parent-user',
                   store.seal(credentials['runtime']), store.seal(credentials['provisioning']),
                   'provider', 'parent-model', 'Parent instructions', 1))
    return credentials


@pytest.fixture
def fake_cmk(tmp_path, monkeypatch):
    executable = tmp_path / 'fake-cmk'
    observations = tmp_path / 'observations.jsonl'
    executable.write_text('''#!/usr/bin/env python3
import configparser,json,os,stat,sys,time
from pathlib import Path
path=Path(os.environ['CMK_CONFIG'])
config=configparser.ConfigParser(interpolation=None)
config.read(path)
profile=config['DEFAULT']['profile']
record={'argv':sys.argv[1:], 'config':str(path), 'mode':stat.S_IMODE(path.stat().st_mode),
        'directory_mode':stat.S_IMODE(path.parent.stat().st_mode),
        'credential_present':config[profile]['apikey']=='unit-api-key',
        'overrides_removed':not any(k in os.environ for k in ('CMK_API_KEY','CMK_DEBUG','OPENAI_API_KEY',
                                                            'CLOUDSTACK_SECRET_KEY')), 'pid':os.getpid()}
with open(os.environ['DS_TEST_OBSERVATIONS'],'a') as log: log.write(json.dumps(record)+'\\n')
command=sys.argv[1]
if command=='sync': print('synced')
elif command=='overflow': print('x'*8000000,flush=True);time.sleep(30)
elif command=='slow': time.sleep(30)
elif command=='rejected': print('private backend secret',file=sys.stderr);sys.exit(1)
else: print(json.dumps({'listvirtualmachinesresponse':{'virtualmachine':[], 'arguments':sys.argv[2:]}}))
''')
    executable.chmod(0o700)
    monkeypatch.setenv('DS_TEST_OBSERVATIONS', str(observations))
    monkeypatch.setenv('CMK_API_KEY', 'must-not-override')
    monkeypatch.setenv('CMK_DEBUG', 'true')
    monkeypatch.setenv('OPENAI_API_KEY', 'do-not-inherit')
    monkeypatch.setenv('CLOUDSTACK_SECRET_KEY', 'do-not-inherit')
    settings = SimpleNamespace(cmk=str(executable), cloudstack_url='http://cloudstack.invalid/client/api')
    return Cloud(settings, {'apikey': 'unit-api-key', 'secretkey': 'unit-secret-key'}), observations


async def test_subprocess_preserves_literal_arguments_uses_private_tmpfs_and_cleans_credentials(fake_cmk, tmp_path):
    cloud, observations = fake_cmk
    marker = tmp_path / 'shell-was-invoked'
    value = f'$(touch {marker}) | cat /etc/shadow; printf dangerous'
    result = await cloud.raw('listVirtualMachines', {'name': value, 'listall': True})
    assert result == {'virtualmachine': [], 'arguments': ['name=' + value, 'listall=true']}
    assert not marker.exists()
    records = [json.loads(line) for line in observations.read_text().splitlines()]
    assert [row['argv'][0] for row in records] == ['sync', 'listVirtualMachines']
    assert all(row['credential_present'] and row['overrides_removed'] for row in records)
    assert all(row['mode'] == 0o600 and row['directory_mode'] == 0o700 for row in records)
    for row in records:
        assert row['config'].startswith('/dev/shm/ds-cmk-')
        assert not await asyncio.to_thread(os.path.exists, row['config'])
    assert 'unit-api-key' not in str([row['argv'] for row in records])
    with pytest.raises(CloudError, match='rejected') as error:
        await cloud.raw('rejected')
    assert 'private backend secret' not in str(error.value)


@pytest.mark.parametrize('command,error', [('overflow', CloudError), ('slow', TimeoutError)])
async def test_subprocess_limit_and_timeout_reap_children(fake_cmk, monkeypatch, command, error):
    cloud, observations = fake_cmk
    original_timeout = asyncio.timeout
    monkeypatch.setattr(cloud_module.asyncio, 'timeout', lambda seconds: original_timeout(0.5))
    with pytest.raises(error):
        await asyncio.wait_for(cloud.raw(command), timeout=3)
    records = [json.loads(line) for line in observations.read_text().splitlines()]
    assert len(records) == 2
    for record in records:
        with pytest.raises(ProcessLookupError):
            os.kill(record['pid'], 0)
        assert not await asyncio.to_thread(os.path.exists, record['config'])


def test_redaction_covers_nested_unknown_keys_known_values_and_private_key_blocks():
    secret = 'unit-known-secret'
    result = redact({'apiKey': 'other-user-key', 'nested': [{'sessionkey': 'unknown-session',
                     'output': f'before {secret} after', 'note': '-----BEGIN OPENSSH PRIVATE KEY-----\n'
                     'untrusted private data\n-----END OPENSSH PRIVATE KEY-----'}],
                     'userdata': 'base64-private-hostkey', 'ordinary': 42}, {secret})
    assert result['ordinary'] == 42
    assert result['apiKey'] == result['userdata'] == '[redacted]'
    assert result['nested'][0]['sessionkey'] == '[redacted]'
    assert secret not in str(result) and 'untrusted private data' not in str(result)


@pytest.mark.parametrize('params', [{}, {'id': 'not-a-uuid'}, {'id': '00000000-0000-0000-0000-000000000001',
                                                         'enabled': 'true'}])
def test_discovered_metadata_is_a_real_validation_boundary(params):
    metadata = {'params': [{'name': 'id', 'type': 'uuid', 'required': True},
                           {'name': 'enabled', 'type': 'boolean'}]}
    with pytest.raises(ValueError):
        validate(metadata, params)


async def test_runtime_cannot_execute_provisioning_or_host_apis_even_if_discovered(monkeypatch):
    cloud = Cloud(SimpleNamespace(), {'apikey': 'runtime-api', 'secretkey': 'runtime-secret'})

    async def should_not_discover():
        raise AssertionError('Reserved commands must be rejected before discovery or execution')

    monkeypatch.setattr(cloud, 'catalogue', should_not_discover)
    for command in ('createDomain', 'createAccount', 'registerUserKeys', 'createStoragePool', 'addHost', 'set',
                    'listVirtualMachines;id'):
        with pytest.raises(PermissionError):
            await cloud.execute(command, {})


class ProvisioningCloud:
    def __init__(self, fail_after=None):
        self.fail_after = fail_after
        self.failed = False
        self.calls = []
        self.domains = []
        self.accounts = []
        self.keys = {}
        self.key_number = 0
        self.validation_failed = False
        self.invalid_replacement = False

    async def raw(self, command, params=None):
        params = params or {}
        self.calls.append((command, params.copy()))
        if command == 'listDomains':
            return {'domain': self.domains}
        if command == 'createDomain':
            result = {'id': 'child-domain', 'name': params['name'], 'parentdomainid': params['parentdomainid']}
            self.domains.append(result)
            response = {'domain': result}
        elif command == 'listAccounts':
            return {'account': self.accounts}
        elif command == 'createAccount':
            result = {'id': 'child-account', 'name': params['account'], 'domainid': params['domainid'],
                      'accounttype': params['accounttype'], 'user': [{'id': 'child-user', 'username': params['username']}]}
            self.accounts.append(result)
            response = {'account': result}
        elif command == 'listUserKeys':
            return {'userapikey': list(self.keys.values())}
        elif command == 'registerUserKeys':
            self.key_number += 1
            key_id = 'key-' + str(self.key_number)
            result = {'id': key_id, 'name': params['name'], 'apikey': key_id + '-api',
                      'secretkey': key_id + '-secret'}
            self.keys[key_id] = result
            response = {'userkeys': result}
        elif command == 'deleteUserKeys':
            del self.keys[params['keypairid']]
            return {'success': True}
        else:
            raise AssertionError(command)
        fail_here = self.fail_after == command or (
            self.fail_after == 'second-key' and command == 'registerUserKeys'
            and params['name'].endswith('-provision'))
        if fail_here and not self.failed:
            self.failed = True
            raise CloudError('Response lost after committed CloudStack operation')
        return response


def provisioning_service(store, cloud):
    service = Service(store, SimpleNamespace(max_output=65536))

    async def cloud_client(agent, purpose='runtime'):
        return cloud

    class CredentialClient:
        def __init__(self, credentials):
            self.credentials = credentials

        async def raw(self, command, params):
            if cloud.fail_after == 'validation' and not cloud.validation_failed:
                cloud.validation_failed = True
                raise CloudError('Temporary validation outage')
            if command == 'listDomains':
                return {'domain': [] if cloud.invalid_replacement else [{'id': params['id']}]}
            return await cloud.raw(command, params)

    service.cloud_client = cloud_client
    service.client = CredentialClient
    return service


@pytest.mark.parametrize('failure', ['createDomain', 'createAccount', 'second-key', 'validation'])
async def test_provisioning_survives_lost_responses_and_restart_without_duplicate_privileged_resources(store, failure):
    add_parent(store)
    cloud = ProvisioningCloud(failure)
    service = provisioning_service(store, cloud)
    with pytest.raises(CloudError):
        await service.create_subgroup('parent', 'Research')
    pending = store.one('SELECT * FROM provisioning')
    assert pending['phase'] != 'complete' and pending['error']
    # A replacement service instance resumes from SQLite rather than from process memory.
    service = provisioning_service(store, cloud)
    child = await service.create_subgroup('parent', 'Research')
    assert child['id'] == pending['id'] and child['model'] == 'parent-model'
    assert child == await service.create_subgroup('parent', 'Research')
    row = store.one('SELECT * FROM agents WHERE id=?', (child['id'],))
    assert row['provider_id'] == 'provider' and row['instructions'] == 'Parent instructions'
    assert row['domain_id'] == 'child-domain' and row['can_provision'] == 1
    assert store.open(row['runtime'])['id'] in cloud.keys
    assert store.open(row['provisioning'])['id'] in cloud.keys
    counts = collections.Counter(command for command, _ in cloud.calls)
    assert counts['createDomain'] == counts['createAccount'] == 1
    assert len(cloud.domains) == len(cloud.accounts) == 1 and len(cloud.keys) == 2
    assert counts['registerUserKeys'] == (4 if failure == 'second-key' else 2)
    complete = store.one('SELECT * FROM provisioning')
    assert complete['phase'] == 'complete' and complete['credentials'] is None
    assert 'apikey' not in child and 'secret' not in str(child)
    key_requests = [params for command, params in cloud.calls if command == 'registerUserKeys']
    runtime_request = next(params for params in key_requests if params['name'].endswith('-runtime'))
    provisioning_request = next(params for params in key_requests if params['name'].endswith('-provision'))
    for request, expected in ((runtime_request, RUNTIME_APIS), (provisioning_request, PROVISION_APIS)):
        assert {value for key, value in request.items() if key.endswith('.rule')} == expected
        assert {value for key, value in request.items() if key.endswith('.permission')} == {'allow'}
        assert 'enddate' in request
    assert 'createDomain' not in RUNTIME_APIS and 'registerUserKeys' not in RUNTIME_APIS


async def test_failed_replacement_domain_validation_preserves_active_credentials(store):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    cloud.invalid_replacement = True
    service = provisioning_service(store, cloud)

    async def authorized(identity, agent_id, **kwargs):
        return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))

    service.authorize = authorized
    with pytest.raises(PermissionError, match='domain validation'):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert {purpose: store.open(row[purpose]) for purpose in original} == original
    assert not any(command == 'deleteUserKeys' for command, _ in cloud.calls)
    assert store.one('SELECT * FROM credential_rotations WHERE agent_id=?', ('parent',))


async def test_revoke_retry_keeps_agent_disabled_and_finishes_remote_deletion(store, monkeypatch):
    original = add_parent(store)
    service = Service(store, SimpleNamespace())
    keys = {value['id']: value for value in original.values()}
    failed = False

    async def human_call(identity, command, params):
        assert command == 'listDomains' and identity['userid'] == 'human'
        return {'domain': [{'id': 'parent-domain'}]}

    class RevocationCloud:
        async def raw(self, command, params):
            nonlocal failed
            if command == 'listUserKeys':
                return {'userapikey': list(keys.values())}
            assert command == 'deleteUserKeys'
            if params['keypairid'] == 'old-provisioning' and not failed:
                failed = True
                raise CloudError('Interruption between remote revocations')
            del keys[params['keypairid']]
            return {'success': True}

    async def cloud_client(agent, purpose='runtime'):
        return RevocationCloud()

    monkeypatch.setattr(service, 'human_call', human_call)
    monkeypatch.setattr(service, 'cloud_client', cloud_client)
    identity = {'userid': 'human', 'type': 2}
    with pytest.raises(CloudError):
        await service.revoke_agent(identity, 'parent')
    assert store.one('SELECT enabled FROM agents')['enabled'] == 0
    with pytest.raises(PermissionError):
        await service.agent('parent')
    await service.revoke_agent(identity, 'parent')
    assert keys == {} and store.one('SELECT enabled FROM agents')['enabled'] == 0


async def test_revoke_tracks_rotation_orphans_deletes_signing_key_last_and_recovers_lost_response(store):
    original = add_parent(store)
    tracked = {name: {'id': name, 'apikey': name + '-api', 'secretkey': name + '-secret'}
               for name in ('previous-runtime', 'previous-provision', 'replacement-runtime', 'replacement-provision')}
    store.execute('INSERT INTO credential_rotations VALUES(?,?,?,?,?,?)',
                  ('parent', 'rotation', store.seal({key: tracked[key] for key in tracked if key.startswith('previous')}),
                   store.seal({key: tracked[key] for key in tracked if key.startswith('replacement')}), 'validating', 1))
    keys = {value['id']: {**value, 'name': value['id']} for value in [*original.values(), *tracked.values()]}
    keys['lost-orphan'] = {'id': 'lost-orphan', 'name': 'ds-interrupted-provision-runtime'}
    keys['unrelated'] = {'id': 'unrelated', 'name': 'operator-managed-unrelated-key'}
    deleted = []
    lost_response = False
    service = Service(store, SimpleNamespace())

    class UnavailableSigningKey:
        async def raw(self, command, params):
            raise CloudError('Current signing credential is unavailable')

    async def cloud_client(agent, purpose='runtime'):
        return UnavailableSigningKey()

    async def human_call(identity, command, params):
        nonlocal lost_response
        if command == 'listDomains':
            return {'domain': [{'id': 'parent-domain'}]}
        if command == 'listUserKeys':
            return {'userapikey': list(keys.values())}
        assert command == 'deleteUserKeys'
        key_id = params['keypairid']
        deleted.append(key_id)
        del keys[key_id]
        if key_id == original['provisioning']['id'] and not lost_response:
            lost_response = True
            raise CloudError('Signing key deleted but response was lost')
        return {'success': True}

    service.cloud_client, service.human_call = cloud_client, human_call
    identity = {'userid': 'human', 'type': 2}
    with pytest.raises(CloudError):
        await service.revoke_agent(identity, 'parent')
    assert deleted[-1] == original['provisioning']['id']
    await service.revoke_agent(identity, 'parent')
    assert set(keys) == {'unrelated'}
    assert not store.one('SELECT * FROM credential_rotations')
    assert store.one('SELECT enabled FROM agents')['enabled'] == 0


async def test_managed_deploy_persists_before_dispatch_blocks_ambiguous_retry_and_recovers_once(store):
    add_parent(store)
    template = '00000000-0000-0000-0000-000000000001'
    params = {'templateid': template, 'zoneid': '00000000-0000-0000-0000-000000000002',
              'serviceofferingid': '00000000-0000-0000-0000-000000000003'}
    store.execute('INSERT INTO managed_templates VALUES(?,?)', (template, 'Managed Linux'))

    class DeploymentCloud:
        deployments = 0
        vm = None

        async def catalogue(self):
            return {'deployVirtualMachine': {'name': 'deployVirtualMachine', 'params': [
                *({'name': name, 'type': 'uuid', 'required': True}
                  for name in ('templateid', 'zoneid', 'serviceofferingid')),
                {'name': 'name', 'type': 'string'}, {'name': 'userdata', 'type': 'string'},
            ]}}

        async def raw(self, command, request):
            if command == 'deployVirtualMachine':
                self.deployments += 1
                pending = store.one('SELECT * FROM vm_deployments')
                assert pending['phase'] == 'dispatched' and pending['name'] == request['name']
                assert store.one('SELECT host_key FROM vm_access WHERE vm_id=?',
                                 ('pending-' + pending['id'],))['host_key']
                self.vm = {'id': 'actual-vm-id', 'name': request['name']}
                raise CloudError('Connection dropped after deployment was accepted')
            assert command == 'listVirtualMachines'
            return {'virtualmachine': [self.vm] if self.vm else []}

    cloud = DeploymentCloud()
    service = Service(store, SimpleNamespace(max_output=65536))

    async def client(agent, purpose='runtime'):
        return cloud

    service.cloud_client = client
    with pytest.raises(CloudError):
        await service.execute('parent', 'deployVirtualMachine', params)
    with pytest.raises(CloudError, match='recovery'):
        await service.execute('parent', 'deployVirtualMachine', params)
    assert cloud.deployments == 1
    await service.recover_deployments()
    await service.recover_deployments()
    assert cloud.deployments == 1
    assert store.one('SELECT * FROM vm_deployments')['phase'] == 'complete'
    assert store.one('SELECT vm_id FROM vm_access')['vm_id'] == 'actual-vm-id'
    assert b'BEGIN OPENSSH PRIVATE KEY' not in store.path.read_bytes()
