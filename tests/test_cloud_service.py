import asyncio
import base64
import collections
import json
import os
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab import cloud as cloud_module
from dirigentenstab import service as service_module
from dirigentenstab.cloud import Cloud, CloudError, redact, validate
from dirigentenstab.gpu import GPU_COMMANDS, GPU_CONTEXT
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
    credentials = {'id': 'old-key', 'apikey': 'parent-api', 'secretkey': 'parent-secret'}
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,provider_id,'
                  'model,instructions,can_provision) VALUES(?,?,?,?,?,?,?,?,?,?)',
                  ('parent', 'Parent', 'parent-domain', 'parent-account', 'parent-user',
                   store.seal(credentials), 'provider', 'parent-model', 'Parent instructions', 1))
    return credentials


async def test_agent_thinking_configuration_is_persistent_and_older_callers_preserve_it(store):
    credentials = add_parent(store)
    service = Service(store, SimpleNamespace())

    async def authorize(identity, agent_id):
        if identity['userid'] != 'owner' or agent_id != 'parent':
            raise PermissionError('Agent outside your CloudStack domain')
        return await service.agent(agent_id)

    async def chain(agent):
        return [agent]
    service.authorize, service.agent_chain = authorize, chain
    identity = {'userid': 'owner', 'type': 2}
    assert (await service.agent('parent'))['thinking'] == 'default'
    await service.update_agent(identity, 'parent', 'provider', 'parent-model', 'Updated prompt', thinking='high')
    await service.update_agent(identity, 'parent', 'provider', 'parent-model', 'Another prompt')
    agent = await service.agent('parent')
    assert agent['thinking'] == 'high' and agent['instructions'] == 'Another prompt'
    assert store.open(agent['credentials']) == credentials
    with pytest.raises(PermissionError):
        await service.update_agent({'userid': 'other', 'type': 2}, 'parent', 'provider', '', '', thinking='off')
    assert (await service.agent('parent'))['thinking'] == 'high'
    # Providers may advertise new effort names without an application release.
    await service.update_agent(identity, 'parent', 'provider', 'parent-model', '', thinking='provider-level')
    assert (await service.agent('parent'))['thinking'] == 'provider-level'


@pytest.mark.parametrize('thinking', ['', 'High', 'high\n', 'a' * 33, False, {'effort': 'high'}])
async def test_invalid_thinking_level_cannot_partially_change_agent_configuration(store, thinking):
    add_parent(store)
    service = Service(store, SimpleNamespace())

    async def authorize(identity, agent_id):
        return await service.agent(agent_id)

    service.authorize = authorize
    before = await service.agent('parent')
    with pytest.raises(ValueError, match='Invalid thinking level'):
        await service.update_agent({'userid': 'owner', 'type': 1}, 'parent', 'provider', 'changed', 'changed',
                                   can_provision=False, thinking=thinking)
    assert await service.agent('parent') == before


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
cache=Path(os.environ['HOME'])/'.cmk/profiles'/(profile+'.cache')
record={'argv':sys.argv[1:], 'config':str(path), 'mode':stat.S_IMODE(path.stat().st_mode),
        'directory_mode':stat.S_IMODE(path.parent.stat().st_mode),
        'home':os.environ['HOME'], 'cache':str(cache), 'descriptor':json.loads(cache.read_text()),
        'cache_mode':stat.S_IMODE(cache.stat().st_mode),
        'cache_directory_mode':stat.S_IMODE(cache.parent.stat().st_mode),
        'cache_home_mode':stat.S_IMODE(cache.parent.parent.stat().st_mode),
        'credential_present':config[profile]['apikey']=='unit-api-key',
        'signature_algorithm':config[profile]['signaturealgorithm'],
        'overrides_removed':not any(k in os.environ for k in ('CMK_API_KEY','CMK_DEBUG','OPENAI_API_KEY',
                                                            'CLOUDSTACK_SECRET_KEY')), 'pid':os.getpid()}
with open(os.environ['DS_TEST_OBSERVATIONS'],'a') as log: log.write(json.dumps(record)+'\\n')
command=sys.argv[1]
if command=='sync': raise AssertionError('Native requests must not invoke sync')
elif command=='listApis' or command=='futureNativeOperation' and 'deny=true' in sys.argv:
    print(json.dumps({'errorresponse':{'errorcode':403,'errortext':'Native account denied unit-api-key'}}));sys.exit(1)
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
    assert [row['argv'][0] for row in records] == ['listVirtualMachines']
    assert all(row['credential_present'] and row['overrides_removed'] for row in records)
    assert all(row['signature_algorithm'] == 'HmacSHA1' for row in records)
    assert all(row['mode'] == row['cache_mode'] == 0o600 for row in records)
    assert all(row['directory_mode'] == row['cache_directory_mode'] == row['cache_home_mode'] == 0o700 for row in records)
    for row in records:
        assert row['config'].startswith('/dev/shm/ds-cmk-')
        assert row['home'] == os.path.dirname(row['config'])
        assert row['descriptor'] == {'api': [{'name': row['argv'][0], 'isasync': False, 'description': '',
                                              'params': [], 'response': []}]}
        assert not await asyncio.to_thread(os.path.exists, row['cache'])
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
    assert len(records) == 1
    for record in records:
        with pytest.raises(ProcessLookupError):
            os.kill(record['pid'], 0)
        assert not await asyncio.to_thread(os.path.exists, record['config'])


@pytest.mark.parametrize('denied', [False, True])
async def test_transport_metadata_denial_cannot_block_or_replace_native_request(fake_cmk, denied):
    cloud, observations = fake_cmk
    params = {'name': 'native caller value', 'deny': denied}
    if denied:
        with pytest.raises(CloudError, match='403') as failure:
            await cloud.execute('futureNativeOperation', params)
        assert failure.value.rejected and 'unit-api-key' not in str(failure.value)
    else:
        result = await cloud.execute('futureNativeOperation', params)
        assert result['arguments'] == ['name=native caller value', 'deny=false']
    records = [json.loads(line) for line in observations.read_text().splitlines()]
    assert [record['argv'][0] for record in records] == ['listApis', 'futureNativeOperation']
    assert all(record['credential_present'] and record['overrides_removed'] for record in records)
    assert [record['descriptor']['api'][0]['name'] for record in records] == ['listApis', 'futureNativeOperation']
    assert len({record['home'] for record in records}) == 2


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


async def test_all_native_apis_use_the_same_agent_identity_without_an_app_permission_filter(monkeypatch):
    cloud = Cloud(SimpleNamespace(), {'apikey': 'runtime-api', 'secretkey': 'runtime-secret'})
    calls = []

    async def catalogue(**kwargs):
        return {}

    async def raw(command, params):
        assert cloud.credentials == {'apikey': 'runtime-api', 'secretkey': 'runtime-secret'}
        calls.append(command)
        return {'success': True}

    monkeypatch.setattr(cloud, 'catalogue', catalogue)
    monkeypatch.setattr(cloud, 'raw', raw)
    for command in ('registerUserKeys', 'createStoragePool', 'addHost'):
        assert await cloud.execute(command, {}) == {'success': True}
    with pytest.raises(ValueError, match='Invalid CloudStack command'):
        await cloud.execute('listVirtualMachines;id', {})
    assert calls == ['registerUserKeys', 'createStoragePool', 'addHost']


class ProvisioningCloud:
    def __init__(self, fail_after=None):
        self.calls, self.domains, self.accounts = [], [], []
        self.keys, self.key_number = {}, 0
        self.key_rules = {}
        self.fail_after, self.failed, self.validation_failed = fail_after, False, False
        self.invalid_replacement, self.invalid_user = False, False
        self.parent_domain = {'id': 'parent-domain', 'name': 'Parent', 'path': 'ROOT/Parent', 'level': 1}
        self.parent_account = {'id': 'parent-account', 'name': 'Parent', 'domainid': 'parent-domain',
                               'accounttype': 2, 'state': 'enabled'}
        self.parent_user = {'id': 'parent-user', 'accountid': 'parent-account', 'domainid': 'parent-domain',
                            'username': 'Parent', 'account': 'Parent', 'state': 'enabled', 'accounttype': 2}
        self.extra_users = []

    def users(self):
        return [self.parent_user, *[user for account in self.accounts for user in account['user']], *self.extra_users]

    async def catalogue(self, **kwargs):
        raise AssertionError('Credential issuance must not derive permissions from a Python API catalogue')

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
            values = [self.parent_account, *self.accounts]
            return {'account': [a for a in values if
                    (not params.get('id') or a['id'] == params['id']) and
                    (not params.get('name') or a['name'] == params['name']) and
                    (not params.get('domainid') or a['domainid'] == params['domainid'])]}
        elif command == 'createAccount':
            user = {'id': 'child-user', 'username': params['username'], 'account': params['account'],
                    'accountid': 'child-account', 'domainid': params['domainid'], 'state': 'enabled', 'accounttype': 2}
            result = {'id': 'child-account', 'name': params['account'], 'domainid': params['domainid'],
                      'accounttype': params['accounttype'], 'state': 'enabled', 'user': [user]}
            self.accounts.append(result)
            response = {'account': result}
        elif command == 'listUsers':
            return {'user': [u for u in self.users() if
                    (not params.get('id') or u['id'] == params['id']) and
                    (not params.get('account') or u['account'] == params['account']) and
                    (not params.get('domainid') or u['domainid'] == params['domainid'])]}
        elif command == 'listUserKeys':
            return {'userapikey': [key for key in self.keys.values() if key.get('userid') == params['userid']]}
        elif command == 'listUserKeyRules':
            rules = self.key_rules.get(params['keypairid'], [])
            return {'count': len(rules), 'keypermission': rules}
        elif command == 'registerUserKeys':
            assert set(params) == {'id', 'name'}
            self.key_number += 1
            key_id = 'key-' + str(self.key_number)
            user = next(u for u in self.users() if u['id'] == params['id'])
            result = {'id': key_id, 'name': params['name'], 'apikey': key_id + '-api',
                      'secretkey': key_id + '-secret', 'userid': user['id'], 'state': 'Enabled',
                      'accountid': user['accountid'], 'domainid': user['domainid']}
            self.keys[key_id] = result
            response = {'userkeys': result}
        elif command == 'deleteUserKeys':
            del self.keys[params['keypairid']]
            response = {'success': True}
        else:
            raise AssertionError(command)
        if self.fail_after == command and not self.failed:
            self.failed = True
            raise CloudError('Response lost after committed CloudStack operation')
        return response


def provisioning_service(store, cloud):
    service = Service(store, SimpleNamespace(max_output=65536))
    async def chain(agent):
        return [agent]
    service.agent_chain = chain

    class CredentialClient:
        def __init__(self, credentials):
            self.credentials = credentials

        async def raw(self, command, params):
            key = cloud.keys.get(self.credentials.get('id'))
            if not key or any(key[k] != self.credentials.get(k) for k in ('apikey', 'secretkey')):
                raise PermissionError('Invalid signed credential')
            if cloud.fail_after == 'validation' and not cloud.validation_failed:
                cloud.validation_failed = True
                raise CloudError('Temporary validation outage')
            if command == 'listDomains':
                return {'domain': [] if cloud.invalid_replacement else [{'id': params['id']}]}
            if command == 'listUsers' and cloud.invalid_user:
                return {'user': [{**cloud.parent_user, 'id': 'foreign-user'}]}
            return await cloud.raw(command, params)

    async def cloud_client(agent):
        return cloud

    service.cloud_client, service.client = cloud_client, CredentialClient
    return service


def rotation_service(store, cloud):
    service = provisioning_service(store, cloud)
    row = store.one('SELECT * FROM agents WHERE id=?', ('parent',))
    pairs = Service._pairs(store.open(row['credentials']))
    legacy = store.one('SELECT credentials FROM legacy_agent_credentials WHERE agent_id=?', ('parent',))
    if legacy:
        pairs += Service._pairs(store.open(legacy['credentials']))
    for pair in pairs:
        cloud.keys[pair['id']] = {**pair, 'name': 'prior-' + pair['id'], 'userid': 'parent-user',
                                  'accountid': 'parent-account', 'domainid': 'parent-domain', 'state': 'Enabled'}

    async def authorized(identity, agent_id, **kwargs):
        return store.one('SELECT * FROM agents WHERE id=?', (agent_id,))

    async def human_call(identity, command, params=None):
        return await cloud.raw(command, params)

    service.authorize, service.human_call = authorized, human_call
    return service


async def test_key_inventory_pairs_pagesize_with_page_required_by_cloudstack(store):
    add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    await service._owned_keys(cloud.raw, await service.agent('parent'))
    paginated = [(command, params) for command, params in cloud.calls if 'pagesize' in params]
    assert {command for command, _ in paginated} == {'listUsers', 'listUserKeys'}
    assert all(params['page'] == 1 for _, params in paginated)


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


async def test_subgroup_checks_actual_generated_native_path_before_cloud_creation(store):
    add_parent(store)
    cloud = ProvisioningCloud()
    cloud.parent_domain.update(name='A' * 220, path='ROOT/' + 'A' * 220)
    service = provisioning_service(store, cloud)
    with pytest.raises(ValueError, match='domain path'):
        await service.create_subgroup('parent', 'Research')
    assert not cloud.domains and not cloud.accounts and not cloud.keys


async def test_retry_keeps_inherited_provider_and_model_together_when_parent_configuration_changes(store):
    add_parent(store)
    cloud = ProvisioningCloud('createDomain')
    with pytest.raises(CloudError):
        await provisioning_service(store, cloud).create_subgroup('parent', 'Research')
    store.execute('INSERT INTO providers VALUES(?,?,?,?,?,?)',
                  ('new-provider', 'New local', 'chat', 'http://other/v1', store.seal('new-key'), 'new-model'))
    store.execute('UPDATE agents SET provider_id=?,model=? WHERE id=?', ('new-provider', 'new-model', 'parent'))
    child = await provisioning_service(store, cloud).create_subgroup('parent', 'Research')
    row = store.one('SELECT provider_id,model FROM agents WHERE id=?', (child['id'],))
    assert row == {'provider_id': 'provider', 'model': 'parent-model'}


@pytest.mark.parametrize('failure', ['createDomain', 'createAccount', 'registerUserKeys', 'validation'])
async def test_provisioning_resumes_with_one_native_pair_and_no_permission_rules(store, failure):
    add_parent(store)
    cloud = ProvisioningCloud(failure)
    with pytest.raises(CloudError):
        await provisioning_service(store, cloud).create_subgroup('parent', 'Research')
    pending = store.one('SELECT * FROM provisioning')
    assert pending['phase'] != 'complete' and pending['error']
    service = provisioning_service(store, cloud)
    child = await service.create_subgroup('parent', 'Research')
    assert child == await service.create_subgroup('parent', 'Research')
    row = store.one('SELECT * FROM agents WHERE id=?', (child['id'],))
    assert row['provider_id'] == 'provider' and row['model'] == 'parent-model'
    assert row['instructions'] == 'Parent instructions' and row['can_provision'] == 1
    assert 'runtime' not in row and 'provisioning' not in row
    assert store.open(row['credentials'])['id'] in cloud.keys
    counts = collections.Counter(command for command, _ in cloud.calls)
    assert counts['createDomain'] == counts['createAccount'] == counts['registerUserKeys'] == 1
    assert len(cloud.domains) == len(cloud.accounts) == len(cloud.keys) == 1
    assert store.one('SELECT * FROM provisioning')['credentials'] is None
    assert 'apikey' not in child and 'secret' not in str(child)
    assert not any(command in {'listApis', 'listUserKeyRules'} for command, _ in cloud.calls)


@pytest.mark.parametrize('invalid', ['domain', 'user'])
async def test_failed_replacement_authentication_retains_previous_keys_and_resumes(store, invalid):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    cloud.invalid_replacement, cloud.invalid_user = invalid == 'domain', invalid == 'user'
    with pytest.raises(PermissionError, match=invalid + ' validation'):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert store.open(store.one('SELECT credentials FROM agents')['credentials']) == original
    assert original['id'] in cloud.keys
    assert not any(command == 'deleteUserKeys' for command, _ in cloud.calls)
    assert store.one('SELECT phase FROM credential_rotations')['phase'] == 'validating'
    cloud.invalid_replacement = cloud.invalid_user = False
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert len(cloud.keys) == 1 and cloud.key_number == 1


async def test_rotation_uses_human_maintenance_when_the_old_signing_key_is_gone(store):
    add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    cloud.keys.clear()
    cloud.parent_account['accounttype'] = cloud.parent_user['accounttype'] = 0

    async def no_privileged_fallback(agent):
        raise AssertionError('Maintenance must use human authority directly, never a runtime fallback')

    service.cloud_client = no_privileged_fallback
    await service.rotate_credentials({'userid': 'human', 'type': 2}, 'parent')
    assert len(cloud.keys) == 1 and not store.one('SELECT * FROM credential_rotations')
    assert not any(command in {'listApis', 'listUserKeyRules'} for command, _ in cloud.calls)


@pytest.mark.parametrize('foreign', ['userid', 'accountid', 'domainid'])
async def test_adoption_rejects_foreign_native_key_before_issuance_or_deletion(store, foreign):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    key = {**cloud.keys[original['id']], 'id': 'selected', 'apikey': 'selected-api', 'secretkey': 'selected-secret'}
    key[foreign] = 'unrelated'
    cloud.keys['selected'] = key
    with pytest.raises(PermissionError, match='ownership|exact native'):
        await service.rotate_credentials({'userid': 'human', 'type': 2}, 'parent', native_key_id='selected')
    assert store.open(store.one('SELECT credentials FROM agents')['credentials']) == original
    assert not any(command in {'registerUserKeys', 'deleteUserKeys'} for command, _ in cloud.calls)


async def test_adoption_validates_native_pair_then_consolidates_all_owned_account_keys(store):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    selected = {**cloud.keys[original['id']], 'id': 'selected', 'apikey': 'selected-api', 'secretkey': 'selected-secret'}
    cloud.keys['selected'] = selected
    await service.rotate_credentials({'userid': 'human', 'type': 2}, 'parent', native_key_id='selected')
    assert store.open(store.one('SELECT credentials FROM agents')['credentials'])['id'] == 'selected'
    assert set(cloud.keys) == {'selected'}
    assert not any(command == 'registerUserKeys' for command, _ in cloud.calls)


@pytest.mark.parametrize('failure', ['registerUserKeys', 'deleteUserKeys'])
async def test_rotation_recovers_lost_replies_without_issuing_duplicate_keys(store, failure):
    original = add_parent(store)
    cloud = ProvisioningCloud(failure)
    service = rotation_service(store, cloud)
    with pytest.raises(CloudError):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    journal = store.one('SELECT * FROM credential_rotations')
    assert journal
    if failure == 'deleteUserKeys':
        assert journal['phase'] == 'revoking'
        assert store.open(store.one('SELECT credentials FROM agents')['credentials'])['id'] != original['id']
    await rotation_service(store, cloud).rotate_credentials({'userid': 'human'}, 'parent')
    assert not store.one('SELECT * FROM credential_rotations')
    assert len(cloud.keys) == 1 and cloud.key_number == 1


async def test_rotation_rejects_ambiguous_multiple_users_without_mutating_remote_keys(store):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    cloud.extra_users.append({**cloud.parent_user, 'id': 'operator-user'})
    with pytest.raises(PermissionError, match='exactly its recorded user'):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert set(cloud.keys) == {original['id']}
    assert not any(command in {'registerUserKeys', 'deleteUserKeys'} for command, _ in cloud.calls)


async def test_rotation_archives_paired_journal_until_verified_single_pair_cleanup_finishes(store):
    original = add_parent(store)
    def pair(name):
        return {'id': name, 'apikey': name + '-api', 'secretkey': name + '-secret'}
    legacy = pair('legacy-provisioning')
    store.execute('INSERT INTO legacy_agent_credentials VALUES(?,?)', ('parent', store.seal(legacy)))
    previous = {'runtime': pair('prior-runtime'), 'provisioning': pair('prior-provisioning')}
    replacements = {'runtime': pair('interrupted-runtime'), 'provisioning': pair('interrupted-provisioning')}
    store.execute('INSERT INTO credential_rotations VALUES(?,?,?,?,?,?)',
                  ('parent', 'old-operation', store.seal(previous), store.seal(replacements), 'validating', 1))
    cloud = ProvisioningCloud('deleteUserKeys')
    service = rotation_service(store, cloud)
    for tracked in Service._pairs(previous) + Service._pairs(replacements):
        cloud.keys[tracked['id']] = {**cloud.keys[original['id']], **tracked}
    with pytest.raises(CloudError):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert store.one('SELECT * FROM legacy_agent_credentials')
    tracked_ids = {p['id'] for p in Service._pairs(store.open(store.one('SELECT previous FROM credential_rotations')['previous']))}
    assert {original['id'], legacy['id'], *[p['id'] for p in Service._pairs(previous)], *[p['id'] for p in Service._pairs(replacements)]} <= tracked_ids
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert len(cloud.keys) == 1
    assert not store.one('SELECT * FROM legacy_agent_credentials') and not store.one('SELECT * FROM credential_rotations')


async def test_keys_added_after_rotation_snapshot_are_retained_for_human_review(store, monkeypatch):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    validate_pair = service._validate_credentials

    async def concurrent(call, agent, credentials):
        result = await validate_pair(call, agent, credentials)
        cloud.keys['concurrent'] = {**cloud.keys[original['id']], 'id': 'concurrent', 'apikey': 'concurrent-api'}
        return result

    monkeypatch.setattr(service, '_validate_credentials', concurrent)
    with pytest.raises(PermissionError, match='New keys appeared'):
        await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert original['id'] in cloud.keys and 'concurrent' in cloud.keys
    assert store.one('SELECT phase FROM credential_rotations')['phase'] == 'revoking'


async def test_revoke_uses_human_authority_and_recovers_after_last_key_reply_is_lost(store):
    add_parent(store)
    cloud = ProvisioningCloud('deleteUserKeys')
    service = rotation_service(store, cloud)
    with pytest.raises(CloudError):
        await service.revoke_agent({'userid': 'human'}, 'parent')
    assert store.one('SELECT enabled FROM agents')['enabled'] == 0 and not cloud.keys
    await service.revoke_agent({'userid': 'human'}, 'parent')
    assert not cloud.keys and not store.one('SELECT * FROM credential_rotations')


def test_single_key_migration_preserves_encrypted_legacy_pair_and_interrupted_journal(store):
    original = add_parent(store)
    archived = store.seal({'id': 'legacy', 'apikey': 'legacy-api', 'secretkey': 'legacy-secret'})
    store.execute('ALTER TABLE agents RENAME COLUMN credentials TO runtime')
    store.execute('ALTER TABLE agents ADD COLUMN provisioning BLOB')
    store.execute('UPDATE agents SET provisioning=?', (archived,))
    store.execute('DROP TABLE legacy_agent_credentials')
    store.execute('DROP TABLE conversation_compactions')
    for column in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window'):
        store.execute('ALTER TABLE agents DROP COLUMN ' + column)
    store.execute('ALTER TABLE agents DROP COLUMN thinking')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_providers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('PRAGMA user_version=11')
    journal = store.seal({'runtime': original, 'provisioning': {'id': 'pending', 'apikey': 'pending-api', 'secretkey': 'pending-secret'}})
    store.execute('INSERT INTO credential_rotations VALUES(?,?,?,?,?,?)', ('parent', 'pending', journal, journal, 'validating', 1))
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    agent = reopened.one('SELECT * FROM agents')
    assert reopened.open(agent['credentials']) == original
    assert 'runtime' not in agent and 'provisioning' not in agent
    assert reopened.one('SELECT credentials FROM legacy_agent_credentials')['credentials'] == archived
    assert reopened.one('SELECT previous FROM credential_rotations')['previous'] == journal
    restarted = Service(reopened, SimpleNamespace())
    assert restarted.redact('legacy-secret pending-secret') == '[redacted] [redacted]'


@pytest.mark.parametrize('command', sorted(GPU_COMMANDS))
async def test_managed_gpu_lifecycle_uses_authenticated_controller_and_native_calls_stay_native(store, monkeypatch, command):
    add_parent(store)
    service = Service(store, SimpleNamespace(max_output=65536))
    requests, native, local = [], [], []

    class AgentCloud:
        gpu = True
        reads = 0

        async def raw(self, command, params):
            self.reads += 1
            if command == 'listVirtualMachines':
                return {'virtualmachine': [{'id': 'vm', 'serviceofferingid': 'gpu'}]}
            assert command == 'listServiceOfferings'
            return {'serviceoffering': [{'id': params['id'], 'gpucount': int(self.gpu and params['id'] == 'gpu')}]}

        async def execute(self, command, params):
            native.append((command, params))
            return {'path': 'native'}

    cloud = AgentCloud()

    async def client(agent):
        assert agent['id'] == 'parent'
        return cloud

    async def deploy(agent, client, params):
        local.append(params)
        return {'path': 'local'}

    async def helper(settings, action, **request):
        assert action == 'execute'
        requests.append(request)
        return {'path': 'controller'}

    service.cloud_client, service._deploy_managed = client, deploy
    monkeypatch.setattr(service_module, 'helper_call', helper)
    params = {'serviceofferingid': 'gpu'} if command == 'deployVirtualMachine' else {'id': 'vm'}
    context = {'session': 'backend-session', 'run_id': 'durable-run', 'call_id': 'tool-call'}
    for invalid in (None, {key: value for key, value in context.items() if key != 'call_id'}):
        token = GPU_CONTEXT.set(invalid)
        try:
            with pytest.raises(PermissionError, match='authenticated durable'):
                await service.execute('parent', command, params, managed=True)
        finally:
            GPU_CONTEXT.reset(token)
    assert not requests and not native and not local
    token = GPU_CONTEXT.set(context)
    try:
        assert await service.execute('parent', command, params, managed=True) == {'path': 'controller'}
        assert requests[-1] == {'agent_id': 'parent', 'command': command, 'params': params,
                                'session': 'backend-session',
                                'context': {'run_id': 'durable-run', 'call_id': 'tool-call'}}
        if command in {'scaleVirtualMachine', 'changeServiceForVirtualMachine'}:
            await service.execute('parent', command, {**params, 'serviceofferingid': 'cpu'}, managed=True)
            assert requests[-1]['params']['serviceofferingid'] == 'cpu'
    finally:
        GPU_CONTEXT.reset(token)
    reads, routed = cloud.reads, len(requests)
    assert await service.execute('parent', command, params) == {'path': 'native'}
    assert cloud.reads == reads and len(requests) == routed
    cloud.gpu = False
    if command == 'deployVirtualMachine':
        assert await service.execute('parent', command, params, managed=True) == {'path': 'local'}
        service.gpu_local, cloud.gpu = True, True
        assert await service.execute('parent', command, params, managed=True) == {'path': 'local'}
    else:
        with pytest.raises(ValueError, match='GPU lifecycle'):
            await service.execute('parent', command, params, managed=True)
    assert len(requests) == routed


@pytest.mark.parametrize('failure', ['transport', 'async-job', 'http-rejection'])
@pytest.mark.parametrize('guest_admin', [None, 0, 1])
@pytest.mark.parametrize('groups', [{}, {'securitygroupids': 'explicit-group'},
                                   {'securitygroupnames': 'explicit-name'}])
async def test_managed_deploy_classifies_failure_and_reuses_the_prepared_ssh_identity(store, failure, guest_admin, groups):
    add_parent(store)
    template = '00000000-0000-0000-0000-000000000001'
    params = {'templateid': template, 'zoneid': '00000000-0000-0000-0000-000000000002',
              'serviceofferingid': '00000000-0000-0000-0000-000000000003'}
    params.update(groups)
    if guest_admin is not None:
        store.execute('INSERT INTO managed_templates VALUES(?,?,?)', (template, 'Managed Linux', guest_admin))

    class DeploymentCloud(Cloud):
        deployments = 0
        vm = None

        def __init__(self):
            super().__init__(SimpleNamespace(), {'apikey': 'parent-api', 'secretkey': 'parent-secret'})

        async def catalogue(self, *, refresh=False):
            return {'deployVirtualMachine': {'name': 'deployVirtualMachine', 'params': [
                *({'name': name, 'type': 'uuid', 'required': True}
                  for name in ('templateid', 'zoneid', 'serviceofferingid')),
                {'name': 'name', 'type': 'string'}, {'name': 'userdata', 'type': 'string'},
                {'name': 'securitygroupids', 'type': 'string'}, {'name': 'securitygroupnames', 'type': 'string'},
            ]}}

        async def raw(self, command, request):
            if command == 'listServiceOfferings':
                return {'serviceoffering': [{'id': request['id'], 'gpucount': 0}]}
            if command == 'deployVirtualMachine':
                assert {k: v for k, v in request.items() if k.startswith('securitygroup')} == groups
                self.deployments += 1
                self.userdata = request['userdata']
                config = json.loads(base64.b64decode(request['userdata']).decode().split('\n', 1)[1])
                assert config['users'][0]['sudo'] == ['ALL=(ALL) NOPASSWD:ALL']
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
                return {'jobstatus': 2, 'jobresult': {'errorcode': 533,
                        'errortext': 'No destination found parent-secret ' + self.userdata}}
            if command == 'listAccounts':
                assert request['id'] == 'parent-account'
                return {'account': [{'id': 'parent-account', 'name': 'parent-service', 'domainid': 'parent-domain'}]}
            assert command == 'listVirtualMachines'
            return {'virtualmachine': [self.vm] if self.vm else []}

    cloud = DeploymentCloud()
    service = Service(store, SimpleNamespace(max_output=65536))

    async def client(agent, purpose='runtime'):
        return cloud

    service.cloud_client = client
    with pytest.raises(CloudError) as error:
        await service.execute('parent', 'deployVirtualMachine', params, managed=True)
    if failure == 'async-job':
        assert error.value.public_detail == 'No destination found [redacted] [redacted]'
        assert not error.value.rejected
    operation = store.one('SELECT * FROM vm_deployments')
    if failure == 'http-rejection':
        assert operation['phase'] == 'rejected'
        with pytest.raises(CloudError, match='validation rejection'):
            await service.execute('parent', 'deployVirtualMachine', params, managed=True)
        assert cloud.deployments == 2
        await service.recover_deployments()
        assert all(op['phase'] == 'rejected' for op in store.all('SELECT phase FROM vm_deployments'))
        return
    assert operation['phase'] == ('failed' if failure == 'async-job' else 'dispatched')
    prepared = store.one('SELECT private_key,host_key,owner_agent FROM vm_access')
    with pytest.raises(CloudError, match='recovery'):
        await service.execute('parent', 'deployVirtualMachine', params, managed=True)
    assert cloud.deployments == 1
    recovered = await service.recover_operation('parent', operation['id'])
    assert recovered['phase'] == 'complete' and 'BEGIN OPENSSH PRIVATE KEY' not in str(recovered)
    with pytest.raises(PermissionError):
        await service.recover_operation('different-agent', operation['id'])
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
        service.store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) '
                              "SELECT 'other','Other','other-domain','other-account','other-user',credentials "
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


@pytest.mark.parametrize('interrupted', [False, True, 'async-job'])
@pytest.mark.parametrize('guest_admin', [None, 0, 1])
async def test_private_template_ownership_recovery_and_managed_clone_approval(store, interrupted, guest_admin):
    add_parent(store)
    if guest_admin is not None:
        store.execute('INSERT INTO managed_templates VALUES(?,?,?)', ('base', 'Managed base', guest_admin))
    store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key) VALUES(?,?,?,?)',
                  ('vm', 'parent', 'dirigent', store.seal('synthetic-key')))
    class TemplateCloud(Cloud):
        calls = 0
        template = None
        state = 'Running'
        def __init__(self):
            super().__init__(SimpleNamespace(), {'apikey': 'parent-api', 'secretkey': 'parent-secret'})
        async def catalogue(self, *, refresh=False):
            return {'createTemplate': {'params': [{'name': n, 'type': 'string', 'required': True}
                    for n in ('name', 'volumeid', 'ostypeid')] + [
                        {'name': 'ispublic', 'type': 'boolean'}, {'name': 'account', 'type': 'string'}]}}
        async def raw(self, command, params):
            if command == 'listVolumes':
                return {'volume': [{'id': 'root', 'type': 'ROOT', 'virtualmachineid': 'vm'}]}
            if command == 'listVirtualMachines':
                return {'virtualmachine': [{'id': 'vm', 'state': self.state, 'templateid': 'base'}]}
            if command == 'listTemplates':
                return {'template': [self.template] if self.template else []}
            if command == 'listAccounts':
                return {'account': [{'id': 'parent-account', 'domainid': 'parent-domain', 'name': 'owner'}]}
            if command == 'queryAsyncJobResult':
                return {'jobstatus': 2, 'jobresult': {'errortext': 'Template job failed parent-secret'}}
            assert command == 'createTemplate' and params['ispublic'] is False and params['isfeatured'] is False
            self.calls += 1
            self.template = {'id': 'private-image', 'name': params['name'], 'accountid': 'parent-account',
                             'domainid': 'parent-domain', 'account': 'owner', 'ispublic': False, 'isready': True}
            if interrupted == 'async-job':
                return {'jobid': 'template-job'}
            if interrupted:
                raise CloudError('Response lost after creation', public_detail='Template creation response unavailable')
            return {'template': self.template}
    cloud = TemplateCloud()
    service = Service(store, SimpleNamespace(max_output=65536))
    async def client(*args):
        return cloud
    service.cloud_client = client
    for params in ({'name': 'private', 'volumeid': 'root', 'ostypeid': 'linux', 'ispublic': True},
                   {'name': 'private', 'volumeid': 'root', 'ostypeid': 'linux', 'account': 'unrelated'}):
        with pytest.raises(PermissionError):
            await service.execute('parent', 'createTemplate', params, managed=True)
    args = {'name': 'private', 'volumeid': 'root', 'ostypeid': 'linux'}
    with pytest.raises(PermissionError, match='Stop the managed VM'):
        await service.execute('parent', 'createTemplate', args, managed=True)
    assert cloud.calls == 0 and not store.one('SELECT id FROM template_creations')
    cloud.state = 'Stopped'
    if interrupted:
        with pytest.raises(CloudError) as error:
            await service.execute('parent', 'createTemplate', args, managed=True)
        assert error.value.public_detail == ('Template job failed [redacted]' if interrupted == 'async-job'
                                            else 'Template creation response unavailable')
        assert not error.value.rejected
        assert error.value.operation_id == store.one('SELECT id FROM template_creations')['id']
        with pytest.raises(CloudError, match='recovery'):
            await service.execute('parent', 'createTemplate', args, managed=True)
        await service.recover_templates()
    result = await service.execute('parent', 'createTemplate', args, managed=True)
    assert result['template']['id'] == 'private-image' and cloud.calls == 1
    assert store.one('SELECT guest_admin FROM managed_templates WHERE id=?', ('private-image',))['guest_admin'] == bool(guest_admin)
    store.execute('DELETE FROM vm_access')
    with pytest.raises(PermissionError, match='managed root volume'):
        await service.execute('parent', 'createTemplate', {**args, 'name': 'unauthorized-copy'}, managed=True)


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
    # The stored legacy flag no longer gates subgroup creation; the native account decides.
    native = ProvisioningCloud()
    managed = provisioning_service(store, native)
    result = await managed.create_subgroup('parent', 'Managed agent')
    assert result['id'] and native.domains


@pytest.mark.parametrize('rule_count', [1, 449])
async def test_adoption_keeps_native_permissions_without_interpreting_effective_rules(store, rule_count):
    original = add_parent(store)
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    cloud.keys['selected'] = {**cloud.keys[original['id']], 'id': 'selected',
                              'apikey': 'selected-api', 'secretkey': 'selected-secret'}
    rules = [{'rule': 'nativeOperation' + str(index), 'permission': 'allow'} for index in range(rule_count)]
    cloud.key_rules['selected'] = rules
    await service.rotate_credentials({'userid': 'human'}, 'parent', native_key_id='selected')
    assert store.open(store.one('SELECT credentials FROM agents')['credentials'])['id'] == 'selected'
    assert set(cloud.keys) == {'selected'} and cloud.key_rules['selected'] == rules
    assert not any(command in {'registerUserKeys', 'listUserKeyRules'} for command, _ in cloud.calls)


async def test_legacy_issuing_journal_reconciles_paired_orphans_before_single_key_cleanup(store):
    original = add_parent(store)
    previous = {'runtime': original, 'provisioning': {
        'id': 'old-provision', 'apikey': 'old-provision-api', 'secretkey': 'old-provision-secret'}}
    store.execute('INSERT INTO credential_rotations VALUES(?,?,?,NULL,?,?)',
                  ('parent', 'old-operation', store.seal(previous), 'issuing', 1))
    cloud = ProvisioningCloud()
    service = rotation_service(store, cloud)
    cloud.keys['lost-orphan'] = {**cloud.keys[original['id']], 'id': 'lost-orphan',
                                'name': 'ds-old-operation-runtime', 'apikey': 'orphan-api', 'secretkey': 'orphan-secret'}
    await service.rotate_credentials({'userid': 'human'}, 'parent')
    assert len(cloud.keys) == 1 and cloud.key_number == 1
    assert not store.one('SELECT * FROM credential_rotations')


async def test_admin_migrates_only_legacy_agents_in_the_humans_visible_domains(store, monkeypatch, capsys):
    from scripts import admin

    add_parent(store)
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) '
                  "SELECT 'other','Other','other-domain','other-account','other-user',credentials FROM agents")
    for identifier in ('parent', 'other'):
        store.execute('INSERT INTO legacy_agent_credentials VALUES(?,?)', (identifier, store.seal({})))
    app = Service(store, SimpleNamespace())
    migrated, revoked = [], []

    class Auth:
        def __init__(self, service):
            assert service is app

        async def login(self, *args):
            return 'token', 'csrf'

        async def identity(self, token):
            return {'userid': 'human', 'type': 2}

        async def revoke(self, token):
            revoked.append(token)

    async def human_call(identity, command, params):
        assert command == 'listDomains'
        return {'domain': [{'id': 'parent-domain'}]}

    async def rotate(identity, agent_id):
        migrated.append(agent_id)

    app.human_call, app.rotate_credentials = human_call, rotate
    monkeypatch.setattr(admin, 'Auth', Auth)
    await admin.perform(SimpleNamespace(command='migrate-keys'), app,
                        {'username': 'Human', 'password': 'private-login'})
    assert migrated == ['parent'] and revoked == ['token']
    await admin.perform(SimpleNamespace(command='status'), app)
    output = capsys.readouterr().out
    status = json.loads(output[output.index('{'):])
    assert status['legacy_credential_count'] == 2
    assert 'private-login' not in output and 'parent-secret' not in output


async def test_subgroup_copies_model_compaction_provider_and_mcp_selections(store):
    add_parent(store)
    store.execute('UPDATE agents SET thinking=?,compaction_provider_id=?,compaction_model=?,'
                  'auto_compact_percent=?,context_window=?,enabled_providers=?,enabled_mcp_servers=? WHERE id=?',
                  ('high', 'provider', 'summary', 75, 100000, '["provider"]', '["tools"]', 'parent'))
    store.execute('INSERT INTO mcp_servers(id,name,url,token) VALUES(?,?,?,?)',
                  ('tools', 'Tools', 'https://tools.invalid/mcp', store.seal('secret')))
    store.execute('INSERT INTO mcp_assignments VALUES(?,?,?)', ('parent', 'tools', '["search"]'))
    result = await provisioning_service(store, ProvisioningCloud()).create_subgroup('parent', 'Inherited')
    child = store.one('SELECT * FROM agents WHERE id=?', (result['id'],))
    assert {name: child[name] for name in ('thinking', 'compaction_provider_id', 'compaction_model',
                                         'auto_compact_percent', 'context_window', 'enabled_providers', 'enabled_mcp_servers')} == {
        'thinking': 'high', 'compaction_provider_id': 'provider', 'compaction_model': 'summary',
        'auto_compact_percent': 75, 'context_window': 100000,
        'enabled_providers': '["provider"]', 'enabled_mcp_servers': '["tools"]'}
    assert store.one('SELECT tools FROM mcp_assignments WHERE agent_id=?', (child['id'],))['tools'] == '["search"]'


async def test_owner_ssh_configuration_accepts_public_keys_only_and_vm_overview_is_informational(store):
    import asyncssh
    add_parent(store)
    service = Service(store, SimpleNamespace(max_output=65536, cloudstack_ui_url='https://cloud.invalid/client'))
    owner = {'userid': 'human-owner', 'type': 1}
    key = asyncssh.generate_private_key('ssh-ed25519')
    public = key.export_public_key().decode().strip()
    await service.save_owner_ssh_key(owner, public)
    assert service.owner_ssh_key(owner) == public
    for invalid in (key.export_private_key().decode(), 'not a public key'):
        with pytest.raises(ValueError):
            await service.save_owner_ssh_key(owner, invalid)
    with pytest.raises(PermissionError):
        await service.save_owner_ssh_key({'_agent_id': 'parent', 'userid': 'human-owner', 'type': 1}, public)
    async def authorize(identity, agent_id):
        return await service.agent(agent_id)
    calls = []
    class Native:
        async def raw(self, command, params):
            calls.append((command, params))
            return {'virtualmachine': [{'id': 'vm', 'name': 'Managed', 'state': 'Running',
                                        'nic': [{'isdefault': True, 'ipaddress': '10.50.0.2'}]}]}
    async def client(agent):
        assert agent['id'] == 'parent'
        return Native()
    service.authorize, service.cloud_client = authorize, client
    store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key) VALUES(?,?,?,?)',
                  ('vm', 'parent', 'dirigent', store.seal('private')))
    machines = await service.vm_overview(owner, 'parent')
    assert machines[0]['username'] == 'dirigent' and machines[0]['address'] == '10.50.0.2'
    assert machines[0]['cloudstack_url'] == 'https://cloud.invalid/client/#/vm/vm'
    assert calls == [('listVirtualMachines', {'listall': True})]
    assert 'private' not in str(machines)
