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
                  'model,instructions,can_provision,runtime_policy) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                  ('parent', 'Parent', 'parent-domain', 'parent-account', 'parent-user',
                   store.seal(credentials['runtime']), store.seal(credentials['provisioning']),
                   'provider', 'parent-model', 'Parent instructions', 1, json.dumps(sorted(RUNTIME_APIS))))
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
elif command=='quotaReject':
    print(json.dumps({'deployvirtualmachineresponse':{'errorcode':535,
          'errortext':'GPU limit exceeded unit-api-key unit-secret-key '+sys.argv[2].split('=',1)[1]}}))
    sys.exit(1)
elif command=='quotaTextReject':
    print('🙈 Error: (HTTP 535, error code 9999) Maximum gpu limit exceeded unit-api-key '+sys.argv[2].split('=',1)[1])
    sys.exit(1)
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


@pytest.mark.parametrize('command', ['quotaReject', 'quotaTextReject'])
async def test_native_quota_error_is_useful_and_redacts_credentials_and_userdata(fake_cmk, command):
    cloud, _ = fake_cmk
    userdata = 'private-guest-host-key-material' * 4
    with pytest.raises(CloudError, match='(?i)gpu limit exceeded') as error:
        await cloud.raw(command, {'userdata': userdata})
    assert error.value.rejected
    assert '535' in str(error.value)
    assert all(secret not in str(error.value) for secret in ('unit-api-key', 'unit-secret-key', userdata))


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
        self.key_rules = {}
        self.key_number = 0
        self.validation_failed = False
        self.invalid_replacement = False
        self.parent_domain = {'id': 'parent-domain', 'name': 'Parent', 'path': 'ROOT/Parent', 'level': 1}
        self.available = RUNTIME_APIS | PROVISION_APIS
        self.runtime_available = RUNTIME_APIS

    async def catalogue(self):
        return {name: {'name': name} for name in self.available}

    async def raw(self, command, params=None):
        params = params or {}
        self.calls.append((command, params.copy()))
        if command == 'listDomains':
            if params.get('id') == 'parent-domain':
                return {'domain': [self.parent_domain]}
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
            requested = {value for key, value in params.items() if key.endswith('.rule')}
            if not requested <= self.available:
                raise PermissionError('New key permissions exceed the calling key')
            self.key_number += 1
            key_id = 'key-' + str(self.key_number)
            result = {'id': key_id, 'name': params['name'], 'apikey': key_id + '-api',
                      'secretkey': key_id + '-secret'}
            self.keys[key_id] = result
            self.key_rules[key_id] = requested
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

    class RuntimeCloud:
        async def catalogue(self):
            return {name: {'name': name} for name in cloud.runtime_available}

        async def raw(self, command, params):
            return await cloud.raw(command, params)

    async def cloud_client(agent, purpose='runtime'):
        return RuntimeCloud() if purpose == 'runtime' else cloud

    class CredentialClient:
        def __init__(self, credentials):
            self.credentials = credentials

        async def catalogue(self):
            allowed = cloud.key_rules.get(self.credentials.get('id'), cloud.available)
            return {name: {'name': name} for name in allowed}

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


@pytest.mark.parametrize('limit,parent_name,error', [(1, 'Parent', 'hierarchy depth'),
                                                    (10, 'A' * 220, 'domain path')])
async def test_subgroup_checks_depth_and_actual_generated_path_before_cloud_creation(store, limit, parent_name, error):
    add_parent(store)
    cloud = ProvisioningCloud()
    cloud.parent_domain.update(name=parent_name, path='ROOT/' + parent_name)
    service = provisioning_service(store, cloud)
    service.settings.max_hierarchy_depth = limit
    with pytest.raises(ValueError, match=error):
        await service.create_subgroup('parent', 'Research')
    assert not cloud.domains and not cloud.accounts and not cloud.keys
    assert not any(command.startswith('create') for command, _ in cloud.calls)


async def test_retry_keeps_inherited_provider_and_model_together_when_parent_configuration_changes(store):
    add_parent(store)
    cloud = ProvisioningCloud('createDomain')
    service = provisioning_service(store, cloud)
    with pytest.raises(CloudError):
        await service.create_subgroup('parent', 'Research')
    store.execute('INSERT INTO providers VALUES(?,?,?,?,?,?)',
                  ('new-provider', 'New local', 'chat', 'http://other/v1', store.seal('new-key'), 'new-model'))
    store.execute('UPDATE agents SET provider_id=?,model=? WHERE id=?', ('new-provider', 'new-model', 'parent'))
    child = await provisioning_service(store, cloud).create_subgroup('parent', 'Research')
    row = store.one('SELECT provider_id,model FROM agents WHERE id=?', (child['id'],))
    assert row == {'provider_id': 'provider', 'model': 'parent-model'}


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
    assert set(json.loads(row['runtime_policy'])) == RUNTIME_APIS
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
    for request, expected in ((runtime_request, RUNTIME_APIS),
                              (provisioning_request, RUNTIME_APIS | PROVISION_APIS)):
        assert {value for key, value in request.items() if key.endswith('.rule')} == expected
        assert {value for key, value in request.items() if key.endswith('.permission')} == {'allow'}
        assert 'enddate' in request
    assert 'createDomain' not in RUNTIME_APIS and 'registerUserKeys' not in RUNTIME_APIS


async def test_child_permissions_are_limited_by_parent_runtime_even_with_broader_provisioning_key(store):
    add_parent(store)
    cloud = ProvisioningCloud()
    cloud.runtime_available = {'listApis', 'listDomains', 'listVirtualMachines'}
    service = provisioning_service(store, cloud)
    child = await service.create_subgroup('parent', 'Limited child')
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', (child['id'],))
    runtime_rules = cloud.key_rules[store.open(row['runtime'])['id']]
    provisioning_rules = cloud.key_rules[store.open(row['provisioning'])['id']]
    assert runtime_rules == cloud.runtime_available
    assert provisioning_rules == cloud.runtime_available | PROVISION_APIS
    assert 'deployVirtualMachine' in cloud.available
    assert 'deployVirtualMachine' not in runtime_rules | provisioning_rules
    assert runtime_rules <= provisioning_rules <= cloud.available


async def test_credential_permissions_also_intersect_the_issuing_keys_live_catalogue(store):
    cloud = ProvisioningCloud()
    cloud.available = {'listApis', 'listDomains', 'listVirtualMachines', 'createDomain', 'createAccount',
                       'registerUserKeys', 'listUserKeys', 'deleteUserKeys'}
    service = provisioning_service(store, cloud)
    credentials = await service._credentials(cloud, 'child-user', 'operation', runtime_allowed=RUNTIME_APIS)
    runtime_rules = cloud.key_rules[credentials['runtime']['id']]
    provisioning_rules = cloud.key_rules[credentials['provisioning']['id']]
    assert runtime_rules == RUNTIME_APIS & cloud.available
    assert provisioning_rules == (RUNTIME_APIS | PROVISION_APIS) & cloud.available
    assert all(rules <= cloud.available for rules in cloud.key_rules.values())
    assert set(credentials['runtime_policy']) == runtime_rules


async def test_failed_replacement_domain_validation_preserves_active_credentials(store):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    cloud.invalid_replacement = True
    service = provisioning_service(store, cloud)

    async def authorized(identity, agent_id, **kwargs):
        return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))

    async def human_call(identity, command, params=None):
        if command == 'listApis':
            return {'api': list((await cloud.catalogue()).values())}
        return await cloud.raw(command, params)

    service.authorize = authorized
    service.human_call = human_call
    with pytest.raises(PermissionError, match='domain validation'):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert {purpose: store.open(row[purpose]) for purpose in original} == original
    assert not any(command == 'deleteUserKeys' for command, _ in cloud.calls)
    assert store.one('SELECT * FROM credential_rotations WHERE agent_id=?', ('parent',))


@pytest.mark.parametrize('policy', [[], ['listApis', 'listDomains', 'listVirtualMachines']])
async def test_expired_runtime_credentials_preserve_stored_restrictions_or_fail_closed(store, policy):
    add_parent(store)
    store.execute('UPDATE agents SET runtime_policy=? WHERE id=?', (json.dumps(policy), 'parent'))
    cloud = ProvisioningCloud()
    service = provisioning_service(store, cloud)

    async def authorized(identity, agent_id, **kwargs):
        return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))

    async def expired_runtime(agent, purpose='runtime'):
        raise CloudError('Runtime key has expired')

    async def human_call(identity, command, params=None):
        if command == 'listApis':
            return {'api': list((await cloud.catalogue()).values())}
        return await cloud.raw(command, params)

    service.authorize, service.cloud_client, service.human_call = authorized, expired_runtime, human_call
    if not policy:
        with pytest.raises(PermissionError, match='policy unknown'):
            await service.rotate_credentials({'userid': 'human'}, 'parent')
        assert not any(command == 'registerUserKeys' for command, _ in cloud.calls)
        return
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    row = store.one('SELECT runtime,provisioning,runtime_policy FROM agents WHERE id=?', ('parent',))
    runtime_rules = cloud.key_rules[store.open(row['runtime'])['id']]
    provisioning_rules = cloud.key_rules[store.open(row['provisioning'])['id']]
    assert runtime_rules == set(policy) == set(json.loads(row['runtime_policy']))
    assert provisioning_rules == set(policy) | PROVISION_APIS
    assert 'deployVirtualMachine' not in runtime_rules | provisioning_rules


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
                  ('parent', 'rotation', store.seal({'runtime': tracked['previous-runtime'],
                                                    'provisioning': tracked['previous-provision']}),
                   store.seal({'runtime': tracked['replacement-runtime'], 'provisioning': tracked['replacement-provision'],
                               'runtime_policy': ['listDomains']}), 'validating', 1))
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
            if command == 'listServiceOfferings':
                return {'serviceoffering': [{'id': request['id'], 'gpucount': 0}]}
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

    async def ssh_group(cloud):
        return 'ssh-group'

    service.cloud_client = client
    service._ssh_security_group = ssh_group
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


@pytest.mark.parametrize('source', ['0.0.0.0/0', '::/0', '10.0.0.0/8', '127.0.0.1/32', '8.8.8.8/32'])
async def test_managed_ssh_ingress_refuses_public_or_shared_source_ranges_before_cloud_calls(store, source):
    service = Service(store, SimpleNamespace(ssh_source_cidr=source))

    class NoCloudCalls:
        async def execute(self, command, params):
            raise AssertionError('Invalid SSH source must be rejected before infrastructure changes')

    with pytest.raises(ValueError, match='one approved private'):
        await service._ssh_security_group(NoCloudCalls())


async def test_managed_ssh_ingress_uses_one_private_egress_address_and_reuses_the_rule(store):
    service = Service(store, SimpleNamespace(ssh_source_cidr='10.253.80.1/32'))

    class SecurityGroups:
        def __init__(self):
            self.groups = []
            self.calls = []

        async def execute(self, command, params):
            self.calls.append((command, params.copy()))
            if command == 'listSecurityGroups':
                return {'securitygroup': self.groups}
            if command == 'createSecurityGroup':
                group = {'id': 'ssh-group', 'name': params['name'], 'ingressrule': []}
                self.groups.append(group)
                return {'securitygroup': group}
            assert command == 'authorizeSecurityGroupIngress'
            self.groups[0]['ingressrule'].append({'protocol': params['protocol'], 'startport': params['startport'],
                                                'endport': params['endport'], 'cidr': params['cidrlist']})
            return {'success': True}

        async def raw(self, command, params):
            raise AssertionError('Managed SSH ingress must use the validated runtime API path')

    cloud = SecurityGroups()
    assert await service._ssh_security_group(cloud) == 'ssh-group'
    assert await service._ssh_security_group(cloud) == 'ssh-group'
    ingress = [params for command, params in cloud.calls if command == 'authorizeSecurityGroupIngress']
    assert ingress == [{'securitygroupid': 'ssh-group', 'protocol': 'tcp', 'startport': 22,
                        'endport': 22, 'cidrlist': '10.253.80.1/32'}]
    assert sum(command == 'createSecurityGroup' for command, _ in cloud.calls) == 1
