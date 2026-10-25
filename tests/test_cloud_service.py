import asyncio
import collections
import fnmatch
import json
import os
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab import cloud as cloud_module
from dirigentenstab.cloud import Cloud, CloudError, PROVISION_APIS, redact, runtime_api, validate
from dirigentenstab.service import Service
from dirigentenstab.store import Store


NATIVE_APIS = frozenset('listApis listDomains listAccounts listUsers listVirtualMachines listServiceOfferings '
                        'listVolumes listOsTypes deployVirtualMachine destroyVirtualMachine createTemplate '
                        'changeServiceForVirtualMachine futureNativeOperation'.split())


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


async def test_runtime_technical_controls_reject_host_and_credential_apis(monkeypatch):
    cloud = Cloud(SimpleNamespace(), {'apikey': 'runtime-api', 'secretkey': 'runtime-secret'})

    async def should_not_discover(**kwargs):
        raise AssertionError('Technical controls must reject before discovery or execution')

    monkeypatch.setattr(cloud, 'catalogue', should_not_discover)
    for command in ('registerUserKeys', 'createStoragePool', 'addHost', 'listVirtualMachines;id'):
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
        self.rule_documents = {}
        self.key_number = 0
        self.validation_failed = False
        self.invalid_replacement = False
        self.parent_domain = {'id': 'parent-domain', 'name': 'Parent', 'path': 'ROOT/Parent', 'level': 1}
        self.available = NATIVE_APIS | PROVISION_APIS
        self.runtime_available = NATIVE_APIS

    async def catalogue(self, *, refresh=False):
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
            return {'userapikey': [key for key in self.keys.values() if key.get('userid') == params['userid']]}
        elif command == 'listUserKeyRules':
            if params['keypairid'] not in self.keys:
                raise CloudError('Native key does not exist', rejected=True)
            rules = self.rule_documents.get(params['keypairid'], [])
            return {'count': len(rules), 'keypermission': rules}
        elif command == 'registerUserKeys':
            requested = {value for key, value in params.items() if key.endswith('.rule')}
            if not {name for name in requested if '*' not in name} <= self.available:
                raise PermissionError('New key permissions exceed the calling key')
            self.key_number += 1
            key_id = 'key-' + str(self.key_number)
            result = {'id': key_id, 'name': params['name'], 'apikey': key_id + '-api',
                      'secretkey': key_id + '-secret', 'userid': params['id'], 'state': 'Enabled',
                      'accountid': 'parent-account' if params['id'] == 'parent-user' else 'child-account',
                      'domainid': 'parent-domain' if params['id'] == 'parent-user' else 'child-domain'}
            self.keys[key_id] = result
            self.key_rules[key_id] = requested
            self.rule_documents[key_id] = [{'rule': params[f'rules[{i}].rule'],
                    'permission': params[f'rules[{i}].permission']} for i in range(len(requested))]
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
        async def catalogue(self, *, refresh=False):
            return {name: {'name': name} for name in cloud.runtime_available}

        async def raw(self, command, params):
            return await cloud.raw(command, params)

    async def cloud_client(agent, purpose='runtime'):
        return RuntimeCloud() if purpose == 'runtime' else cloud

    class CredentialClient:
        def __init__(self, credentials):
            self.credentials = credentials

        async def catalogue(self, *, refresh=False):
            rules = cloud.rule_documents.get(self.credentials.get('id'))
            allowed = cloud.available if rules is None else {name for name in cloud.available
                if next((r['permission'] == 'allow' for r in rules if fnmatch.fnmatchcase(name, r['rule'])), False)}
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


def rotation_service(store, cloud):
    service = provisioning_service(store, cloud)
    row = store.one('SELECT * FROM agents WHERE id=?', ('parent',))
    for purpose in ('runtime', 'provisioning'):
        pair = store.open(row[purpose])
        cloud.keys[pair['id']] = {**pair, 'name': 'prior-'+purpose, 'userid': 'parent-user',
                                  'accountid': 'parent-account', 'domainid': 'parent-domain', 'state': 'Enabled'}
        allowed = NATIVE_APIS if purpose == 'runtime' else NATIVE_APIS | PROVISION_APIS
        cloud.key_rules[pair['id']] = set(allowed)
        cloud.rule_documents[pair['id']] = [{'rule': name, 'permission': 'allow'} for name in sorted(allowed)]
    async def authorized(identity, agent_id, **kwargs):
        return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))
    async def human_call(identity, command, params=None):
        if command == 'listApis':
            return {'api': list((await cloud.catalogue()).values())}
        return await cloud.raw(command, params)
    service.authorize, service.human_call = authorized, human_call
    return service


@pytest.mark.parametrize('version', ['', '4.22.1.1', '4.24.0.0'])
async def test_existing_unsupported_cloudstack_is_rejected_before_any_provisioning(store, version):
    service = Service(store, SimpleNamespace())

    class Cloud:
        async def raw(self, command):
            assert command == 'listCapabilities'
            return {'capability': {'cloudstackversion': version}}

    service.client = lambda credentials: Cloud()
    with pytest.raises(RuntimeError, match='4.23.x is required'):
        await service.bootstrap({})
    assert not store.all('SELECT id FROM provisioning') and not store.all('SELECT id FROM agents')


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
    assert 'runtime_policy' not in row
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
    for request, expected in ((runtime_request, NATIVE_APIS),
                              (provisioning_request, NATIVE_APIS | PROVISION_APIS)):
        assert {value for key, value in request.items() if key.endswith('.rule')} == expected
        assert {value for key, value in request.items() if key.endswith('.permission')} == {'allow'}
        assert 'enddate' in request
    assert 'createDomain' not in NATIVE_APIS and 'registerUserKeys' not in NATIVE_APIS


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
    credentials = await service._credentials(cloud, 'child-user', 'operation', runtime_allowed=NATIVE_APIS)
    runtime_rules = cloud.key_rules[credentials['runtime']['id']]
    provisioning_rules = cloud.key_rules[credentials['provisioning']['id']]
    assert runtime_rules == NATIVE_APIS & cloud.available
    assert provisioning_rules == (NATIVE_APIS | PROVISION_APIS) & cloud.available
    assert all(rules <= cloud.available for rules in cloud.key_rules.values())
    assert 'runtime_policy' not in credentials


async def test_failed_replacement_domain_validation_preserves_active_credentials(store):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    cloud.invalid_replacement = True
    service = rotation_service(store, cloud)

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


@pytest.mark.parametrize('native_available', [True, False])
async def test_expired_runtime_uses_native_rules_or_fails_closed_without_local_fallback(store, native_available):
    add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    if not native_available:
        del cloud.keys['old-runtime']
        with pytest.raises(PermissionError, match='exact native key'):
            await service.rotate_credentials({'userid': 'human'}, 'parent')
        assert not any(command == 'registerUserKeys' for command, _ in cloud.calls)
        return
    cloud.runtime_available = set()  # The old key cannot authenticate; human native inspection remains authoritative.
    cloud.key_rules['old-runtime'] = {'listApis', 'listDomains', 'listVirtualMachines'}
    cloud.rule_documents['old-runtime'] = [{'rule': name, 'permission': 'allow'}
                                          for name in sorted(cloud.key_rules['old-runtime'])]
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert cloud.key_rules[store.open(row['runtime'])['id']] == {'listApis', 'listDomains', 'listVirtualMachines'}
    assert cloud.key_rules[store.open(row['provisioning'])['id']] == NATIVE_APIS | PROVISION_APIS
    assert not store.one('SELECT * FROM credential_rotations')


async def test_rotation_clones_authoritative_rule_order_denies_and_wildcards(store):
    add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    rules = [{'rule': 'destroyVirtualMachine', 'permission': 'deny'}, {'rule': '*', 'permission': 'allow'}]
    cloud.rule_documents['old-runtime'] = rules
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert cloud.rule_documents[store.open(row['runtime'])['id']] == rules
    assert store.open(row['runtime'])['id'] != store.open(row['provisioning'])['id']
    assert set(row) == {'runtime', 'provisioning'}


@pytest.mark.parametrize('foreign', ['userid', 'accountid', 'domainid', 'shared'])
async def test_adoption_rejects_foreign_native_key_and_shared_credential_identity(store, foreign):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    key = {**cloud.keys['old-runtime'], 'id': 'selected', 'apikey': 'selected-api', 'secretkey': 'selected-secret'}
    if foreign != 'shared':
        key[foreign] = 'unrelated'
    cloud.keys['selected'] = key
    selected = 'old-provisioning' if foreign == 'shared' else 'selected'
    with pytest.raises(PermissionError, match='exact agent|exact native key|separate native'):
        await service.rotate_credentials({'type': 1, 'userid': 'human'}, 'parent', native_key_ids={'runtime': selected})
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert {purpose: store.open(row[purpose]) for purpose in original} == original
    assert not any(command in {'registerUserKeys', 'deleteUserKeys'} for command, _ in cloud.calls)


@pytest.mark.parametrize('expired', [False, True])
async def test_explicit_native_adoption_uses_cloudstack_grant_without_python_permission_list(store, expired):
    add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    key = {**cloud.keys['old-runtime'], 'id': 'selected', 'apikey': 'selected-api', 'secretkey': 'selected-secret'}
    cloud.keys['selected'] = key
    cloud.available |= {'expungeVirtualMachine'}
    cloud.rule_documents['selected'] = [{'rule': name, 'permission': 'allow'}
                                        for name in sorted(NATIVE_APIS | {'expungeVirtualMachine'})]
    if expired:
        del cloud.keys['old-runtime']
    await service.rotate_credentials({'type': 1, 'userid': 'human'}, 'parent', native_key_ids={'runtime': 'selected'})
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert store.open(row['runtime'])['id'] == 'selected'
    assert store.open(row['provisioning'])['id'] == 'old-provisioning'
    assert 'old-provisioning' in cloud.keys and 'old-runtime' not in cloud.keys
    assert not any(command == 'registerUserKeys' for command, _ in cloud.calls)
    async def native_client(agent, purpose='runtime'):
        return service.client(store.open(agent[purpose]))
    service.cloud_client = native_client
    assert await service.search_api('parent', 'expunge') == [{'name': 'expungeVirtualMachine', 'description': ''}]
    assert (await service.describe_api('parent', 'expungeVirtualMachine'))['name'] == 'expungeVirtualMachine'


async def test_native_permission_change_during_rotation_preserves_previous_pair(store, monkeypatch):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    raw = cloud.raw
    reads = 0
    async def changed(command, params=None):
        nonlocal reads
        if command == 'listUserKeyRules' and params['keypairid'] == 'old-runtime':
            reads += 1
            if reads == 2:
                cloud.rule_documents['old-runtime'] = [{'rule': 'listDomains', 'permission': 'allow'}]
        return await raw(command, params)
    monkeypatch.setattr(cloud, 'raw', changed)
    with pytest.raises(PermissionError, match='permissions changed'):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    row = store.one('SELECT runtime,provisioning FROM agents WHERE id=?', ('parent',))
    assert {purpose: store.open(row[purpose]) for purpose in original} == original
    assert 'old-runtime' in cloud.keys and 'old-provisioning' in cloud.keys


async def test_rotation_recovers_lost_revocation_reply_without_issuing_keys_again(store, monkeypatch):
    add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    raw = cloud.raw
    lost = False
    async def interrupted(command, params=None):
        nonlocal lost
        result = await raw(command, params)
        if command == 'deleteUserKeys' and params['keypairid'] == 'old-runtime' and not lost:
            lost = True
            raise CloudError('Deletion committed before reply was lost')
        return result
    monkeypatch.setattr(cloud, 'raw', interrupted)
    with pytest.raises(CloudError):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert store.one('SELECT phase FROM credential_rotations')['phase'] == 'revoking'
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert not store.one('SELECT * FROM credential_rotations')
    assert 'old-runtime' not in cloud.keys and 'old-provisioning' not in cloud.keys
    assert sum(command == 'registerUserKeys' for command, _ in cloud.calls) == 2


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


@pytest.mark.parametrize('failure', ['transport', 'async-job', 'http-rejection'])
async def test_managed_deploy_classifies_failure_and_reuses_the_prepared_ssh_identity(store, failure):
    add_parent(store)
    template = '00000000-0000-0000-0000-000000000001'
    params = {'templateid': template, 'zoneid': '00000000-0000-0000-0000-000000000002',
              'serviceofferingid': '00000000-0000-0000-0000-000000000003'}
    store.execute('INSERT INTO managed_templates(id,name) VALUES(?,?)', (template, 'Managed Linux'))

    class DeploymentCloud:
        deployments = 0
        vm = None

        async def catalogue(self, *, refresh=False):
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
                pending = store.one('SELECT * FROM vm_deployments WHERE name=?', (request['name'],))
                assert pending['phase'] == 'dispatched' and pending['name'] == request['name']
                assert store.one('SELECT host_key FROM vm_access WHERE vm_id=?',
                                 ('pending-' + pending['id'],))['host_key']
                if failure == 'http-rejection':
                    raise CloudError('Definitive API validation rejection', rejected=True)
                self.vm = {'id': 'actual-vm-id', 'name': request['name'], 'state': 'Stopped',
                           'account': 'parent-service', 'domainid': 'parent-domain'}
                if failure == 'transport':
                    raise CloudError('Connection dropped after deployment was accepted')
                return {'jobid': 'failed-job'}
            if command == 'queryAsyncJobResult':
                return {'jobstatus': 2, 'jobresult': {'errorcode': 533, 'errortext': 'No destination found'}}
            if command == 'listAccounts':
                assert request['id'] == 'parent-account'
                return {'account': [{'id': 'parent-account', 'name': 'parent-service', 'domainid': 'parent-domain'}]}
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
    operation = store.one('SELECT * FROM vm_deployments')
    if failure == 'http-rejection':
        assert operation['phase'] == 'rejected'
        with pytest.raises(CloudError, match='validation rejection'):
            await service.execute('parent', 'deployVirtualMachine', params)
        assert cloud.deployments == 2
        await service.recover_deployments()
        assert all(op['phase'] == 'rejected' for op in store.all('SELECT phase FROM vm_deployments'))
        return
    assert operation['phase'] == ('failed' if failure == 'async-job' else 'dispatched')
    prepared = store.one('SELECT private_key,host_key,owner_agent FROM vm_access')
    with pytest.raises(CloudError, match='recovery'):
        await service.execute('parent', 'deployVirtualMachine', params)
    assert cloud.deployments == 1
    await service.recover_deployments()
    await service.recover_deployments()
    assert cloud.deployments == 1
    assert store.one('SELECT * FROM vm_deployments')['phase'] == 'complete'
    assert store.one('SELECT vm_id FROM vm_access')['vm_id'] == 'actual-vm-id'
    assert store.one('SELECT private_key,host_key,owner_agent FROM vm_access') == prepared
    assert b'BEGIN OPENSSH PRIVATE KEY' not in store.path.read_bytes()


@pytest.fixture
def failed_deployment(store):
    add_parent(store)
    operation_id, name = 'failed-operation', 'ds-vm-owned-stable-name'
    store.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,NULL,?,?)',
                  (operation_id, 'parent', name, store.seal({'name': name}), 'failed', 1))
    store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key) VALUES(?,?,?,?,?)',
                  ('pending-' + operation_id, 'parent', 'dirigent', store.seal('synthetic-private-key'), 'synthetic-host-key'))

    class RecoveryCloud:
        def __init__(self):
            self.vms = []
            self.calls = []

        async def raw(self, command, params):
            self.calls.append((command, params.copy()))
            if command == 'listAccounts':
                assert params == {'id': 'parent-account', 'listall': True}
                return {'account': [{'id': 'parent-account', 'name': 'parent-service', 'domainid': 'parent-domain'}]}
            assert command == 'listVirtualMachines', 'Recovery must never create infrastructure or credentials'
            assert params['name'] == name
            return {'virtualmachine': self.vms}

    service, cloud = Service(store, SimpleNamespace()), RecoveryCloud()

    async def client(agent, purpose='runtime'):
        assert agent['id'] == 'parent' and purpose == 'runtime'
        return cloud

    service.cloud_client = client
    return service, cloud, operation_id, name


@pytest.mark.parametrize('phase', ['prepared', 'dispatched', 'failed'])
async def test_missing_or_ambiguous_vm_never_clears_failed_deployment_or_dispatches_again(failed_deployment, phase):
    service, cloud, operation_id, name = failed_deployment
    service.store.execute('UPDATE vm_deployments SET phase=?', (phase,))
    agent = await service.agent('parent')
    for vms in ([], [{'id': 'one', 'name': name, 'account': 'parent-service', 'domainid': 'parent-domain', 'state': 'Running'},
                    {'id': 'two', 'name': name, 'account': 'parent-service', 'domainid': 'parent-domain', 'state': 'Running'}]):
        cloud.vms = vms
        await service.recover_deployments()
        assert service.store.one('SELECT phase,vm_id FROM vm_deployments') == {'phase': phase, 'vm_id': None}
        with pytest.raises(CloudError, match='needs recovery'):
            await service._deploy_managed(agent, cloud, {})
    assert all(command in {'listAccounts', 'listVirtualMachines'} for command, _ in cloud.calls)


@pytest.mark.parametrize('state', ['Error', 'Destroyed', 'Expunging', 'Starting', 'Stopping', 'Migrating', 'Unknown', None])
async def test_failed_vm_in_unusable_or_transient_state_is_never_adopted_or_redeployed(failed_deployment, state):
    service, cloud, operation_id, name = failed_deployment
    cloud.vms = [{'id': 'unusable-vm', 'name': name, 'account': 'parent-service',
                  'domainid': 'parent-domain', 'state': state}]
    prepared = service.store.one('SELECT * FROM vm_access')
    await service.recover_deployments()
    assert service.store.one('SELECT phase,vm_id FROM vm_deployments') == {'phase': 'failed', 'vm_id': None}
    assert service.store.one('SELECT * FROM vm_access') == prepared
    assert service.store.one('SELECT operation,target FROM audit') == {
        'operation': 'deployment-recovery-needs-review', 'target': operation_id}
    with pytest.raises(CloudError, match='needs recovery'):
        await service._deploy_managed(await service.agent('parent'), cloud, {})
    assert all(command in {'listAccounts', 'listVirtualMachines'} for command, _ in cloud.calls)


@pytest.mark.parametrize('foreign', [
    {'account': 'child-service', 'domainid': 'child-domain'},
    {'account': 'parent-service', 'domainid': 'other-domain'},
    {'account': 'other-service', 'domainid': 'parent-domain'},
])
async def test_recovery_never_adopts_a_parent_visible_child_or_other_account_vm(failed_deployment, foreign):
    service, cloud, operation_id, name = failed_deployment
    cloud.vms = [{'id': 'foreign-vm', 'name': name, 'state': 'Stopped', **foreign}]
    await service.recover_deployments()
    assert service.store.one('SELECT phase,vm_id FROM vm_deployments') == {'phase': 'failed', 'vm_id': None}
    assert service.store.one('SELECT vm_id FROM vm_access')['vm_id'] == 'pending-' + operation_id
    cloud.vms.append({'id': 'owned-vm', 'name': name, 'account': 'parent-service', 'domainid': 'parent-domain',
                      'state': 'Running'})
    await service.recover_deployments()
    assert service.store.one('SELECT phase,vm_id FROM vm_deployments') == {'phase': 'complete', 'vm_id': 'owned-vm'}
    service._bind_vm(operation_id, 'owned-vm')
    with pytest.raises(CloudError, match='another VM'):
        service._bind_vm(operation_id, 'different-vm')


@pytest.mark.parametrize('problem', ['missing', 'other-owner', 'already-managed'])
async def test_recovery_requires_the_original_ssh_record_and_matching_owner(failed_deployment, problem):
    service, cloud, operation_id, name = failed_deployment
    cloud.vms = [{'id': 'owned-vm', 'name': name, 'account': 'parent-service', 'domainid': 'parent-domain',
                  'state': 'Stopped'}]
    if problem == 'missing':
        service.store.execute('DELETE FROM vm_access')
    elif problem == 'other-owner':
        service.store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning) '
                              "SELECT 'other','Other','other-domain','other-account','other-user',runtime,provisioning "
                              "FROM agents WHERE id='parent'")
        service.store.execute("UPDATE vm_access SET owner_agent='other'")
    else:
        service.store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key) '
                              "SELECT 'owned-vm',owner_agent,username,private_key,host_key FROM vm_access")
    before = service.store.all('SELECT * FROM vm_access ORDER BY vm_id')
    with pytest.raises(CloudError, match='SSH identity'):
        await service.recover_deployments()
    assert service.store.all('SELECT * FROM vm_access ORDER BY vm_id') == before
    assert service.store.one('SELECT phase,vm_id FROM vm_deployments') == {'phase': 'failed', 'vm_id': None}


async def test_confirmed_rejection_cli_is_the_only_resolution_for_a_legacy_failed_op_without_a_vm(failed_deployment):
    from scripts.admin import perform

    service, cloud, operation_id, _ = failed_deployment
    original = cloud.raw

    async def raw(command, params):
        if command == 'listAsyncJobs':
            return {'asyncjobs': []}
        return await original(command, params)

    cloud.raw = raw
    options = SimpleNamespace(command='resolve-rejection', identifier=operation_id, confirmed_rejection=False)
    with pytest.raises(SystemExit, match='confirmed-rejection'):
        await perform(options, service)
    assert service.store.one('SELECT phase FROM vm_deployments')['phase'] == 'failed'
    options.confirmed_rejection = True
    await perform(options, service)
    assert service.store.one('SELECT phase FROM vm_deployments')['phase'] == 'rejected'


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


async def test_concurrent_catalogue_requests_share_one_fetch():
    cloud = Cloud(SimpleNamespace(), {'apikey': 'fixture'})
    calls = []
    async def raw(command):
        calls.append(command)
        await asyncio.sleep(0.01)
        return {'api': [{'name': 'listDomains'}]}
    cloud.raw = raw
    results = await asyncio.gather(*(cloud.catalogue() for _ in range(8)))
    assert calls == ['listApis'] and all('listDomains' in result for result in results)


async def test_dashboard_is_optional_platform_admin_only_and_never_carries_credentials(store):
    service = Service(store, SimpleNamespace(cloudstack_ui_url='https://cloud.tailnet.invalid/client'))
    root, domain = {'userid': 'root-human', 'type': 1}, {'userid': 'domain-human', 'type': 2}
    assert service.dashboard_url(root) == service.settings.cloudstack_ui_url + '/'
    assert service.dashboard_url(domain) == ''
    with pytest.raises(PermissionError):
        service.save_dashboard_url(domain, 'https://elsewhere.invalid')
    for value in ('http://cloud.invalid/client', 'javascript:alert(1)', 'https://user:secret@cloud.invalid',
                  'https://cloud.invalid/client?sessionkey=private', 'https://cloud.invalid/#secret'):
        with pytest.raises(ValueError):
            service.save_dashboard_url(root, value)
    service.save_dashboard_url(root, 'https://new.tailnet.invalid/client/')
    assert service.dashboard_url(root) == 'https://new.tailnet.invalid/client/'
    service.save_dashboard_url(root, '')
    assert service.dashboard_url(root) == ''


@pytest.mark.parametrize('interrupted', [False, True])
async def test_private_template_ownership_recovery_and_managed_clone_approval(store, interrupted):
    add_parent(store)
    store.execute('INSERT INTO managed_templates VALUES(?,?,?)', ('base', 'Approved build base', 1))
    store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key) VALUES(?,?,?,?)',
                  ('vm', 'parent', 'dirigent', store.seal('synthetic-key')))
    class TemplateCloud:
        calls = 0
        template = None
        async def catalogue(self, *, refresh=False):
            return {'createTemplate': {'params': [{'name': n, 'type': 'string', 'required': True}
                    for n in ('name', 'volumeid', 'ostypeid')] + [
                        {'name': 'ispublic', 'type': 'boolean'}, {'name': 'account', 'type': 'string'}]}}
        async def raw(self, command, params):
            if command == 'listVolumes':
                return {'volume': [{'id': 'root', 'type': 'ROOT', 'virtualmachineid': 'vm'}]}
            if command == 'listVirtualMachines':
                return {'virtualmachine': [{'id': 'vm', 'state': 'Stopped', 'templateid': 'base'}]}
            if command == 'listTemplates':
                return {'template': [self.template] if self.template else []}
            if command == 'listAccounts':
                return {'account': [{'id': 'parent-account', 'domainid': 'parent-domain', 'name': 'owner'}]}
            assert command == 'createTemplate' and params['ispublic'] is False and params['isfeatured'] is False
            self.calls += 1
            self.template = {'id': 'private-image', 'name': params['name'], 'accountid': 'parent-account',
                             'domainid': 'parent-domain', 'account': 'owner', 'ispublic': False, 'isready': True}
            if interrupted:
                raise CloudError('Response lost after creation')
            return {'template': self.template}
    cloud = TemplateCloud()
    service = Service(store, SimpleNamespace(max_output=65536))
    async def client(*args):
        return cloud
    service.cloud_client = client
    for params in ({'name': 'private', 'volumeid': 'root', 'ostypeid': 'linux', 'ispublic': True},
                   {'name': 'private', 'volumeid': 'root', 'ostypeid': 'linux', 'account': 'unrelated'}):
        with pytest.raises(PermissionError):
            await service.execute('parent', 'createTemplate', params)
    args = {'name': 'private', 'volumeid': 'root', 'ostypeid': 'linux'}
    if interrupted:
        with pytest.raises(CloudError):
            await service.execute('parent', 'createTemplate', args)
        with pytest.raises(CloudError, match='recovery'):
            await service.execute('parent', 'createTemplate', args)
        await service.recover_templates()
    result = await service.execute('parent', 'createTemplate', args)
    assert result['template']['id'] == 'private-image' and cloud.calls == 1
    assert store.one('SELECT guest_admin FROM managed_templates WHERE id=?', ('private-image',))['guest_admin'] == 1
    store.execute('DELETE FROM vm_access')
    with pytest.raises(PermissionError, match='managed root volume'):
        await service.execute('parent', 'createTemplate', {**args, 'name': 'unauthorized-copy'})
    assert not any(runtime_api(name) for name in ('createGpuDevice', 'discoverGpuDevices', 'registerUserKeys'))


async def test_only_platform_admin_can_adopt_an_explicit_native_key(store):
    add_parent(store)
    service = Service(store, SimpleNamespace())
    for identity, selected in [({'type': 2}, {'runtime': 'native-key'}),
                               ({'type': 1}, {'unknown-purpose': 'native-key'})]:
        with pytest.raises(PermissionError, match='human platform administrator'):
            await service.rotate_credentials(identity, 'parent', native_key_ids=selected)


async def test_managed_agent_feature_gate_does_not_override_native_infrastructure_grants(store):
    add_parent(store)
    store.execute('UPDATE agents SET can_provision=0 WHERE id=?', ('parent',))
    service = Service(store, SimpleNamespace(max_output=65536))
    class NativeGrant:
        async def catalogue(self, *, refresh=False):
            return {'createDomain': {'name': 'createDomain', 'params': [{'name': 'name', 'type': 'string'}]}}
        async def execute(self, command, params):
            assert (command, params) == ('createDomain', {'name': 'Native domain'})
            return {'domain': {'id': 'native-domain', 'name': params['name']}}
    async def client(agent, purpose='runtime'):
        return NativeGrant()
    service.cloud_client = client
    assert (await service.search_api('parent', 'createDomain'))[0]['name'] == 'createDomain'
    assert (await service.describe_api('parent', 'createDomain'))['name'] == 'createDomain'
    result = await service.execute('parent', 'createDomain', {'name': 'Native domain'})
    assert result['domain']['id'] == 'native-domain'
    with pytest.raises(PermissionError, match='Subgroup creation disabled'):
        await service.create_subgroup('parent', 'Managed agent')
