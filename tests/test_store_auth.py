import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet, InvalidToken

from dirigentenstab.auth import Auth
from dirigentenstab.store import Store


@pytest.fixture
def store(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    return Store(str(tmp_path / 'application.db'), str(key))


def test_migrations_resume_and_encrypted_records_reject_tampering(store):
    value = store.seal({'secretkey': 'never-plaintext'})
    assert b'never-plaintext' not in value
    assert store.open(value) == {'secretkey': 'never-plaintext'}
    with pytest.raises(InvalidToken):
        store.open(value[:20] + b'broken' + value[25:])
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    assert reopened.one('PRAGMA user_version')['user_version'] == 16
    assert reopened.one("SELECT name FROM sqlite_master WHERE name='credential_rotations'")


def test_permission_column_migration_preserves_agent_keys_and_owned_conversation(store):
    # Recreate the removed schema-9 column around real encrypted records before upgrading.
    store.execute('DROP TABLE mcp_assignments')
    store.execute('DROP TABLE mcp_servers')
    store.execute('DROP TABLE legacy_agent_credentials')
    store.execute('DROP TABLE conversation_compactions')
    for column in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window'):
        store.execute('ALTER TABLE agents DROP COLUMN ' + column)
    store.execute('ALTER TABLE agents DROP COLUMN thinking')
    store.execute('ALTER TABLE agents RENAME COLUMN credentials TO runtime')
    store.execute('ALTER TABLE agents ADD COLUMN provisioning BLOB NOT NULL')
    store.execute("ALTER TABLE agents ADD COLUMN runtime_policy TEXT NOT NULL DEFAULT '[]'")
    store.execute('ALTER TABLE agents DROP COLUMN enabled_providers')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('PRAGMA user_version=9')
    runtime = store.seal({'id': 'runtime-key-id', 'apikey': 'runtime'})
    provisioning = store.seal({'id': 'provisioning-key-id', 'apikey': 'provision'})
    messages = store.seal([])
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,runtime_policy) '
                  'VALUES(?,?,?,?,?,?,?,?)', ('agent', 'Agent', 'domain', 'account', 'user', runtime, provisioning, '["old"]'))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'human', 'Preserved', 1, messages))
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    agent = reopened.one('SELECT * FROM agents')
    assert not {'runtime_policy', 'runtime', 'provisioning'} & agent.keys()
    assert agent['credentials'] == runtime
    assert reopened.open(agent['credentials'])['id'] == 'runtime-key-id'
    legacy = reopened.one('SELECT * FROM legacy_agent_credentials WHERE agent_id=?', ('agent',))
    assert legacy['credentials'] == provisioning
    assert reopened.open(legacy['credentials'])['id'] == 'provisioning-key-id'
    conversation = reopened.one('SELECT * FROM conversations')
    assert conversation['agent_id'] == 'agent' and conversation['human_id'] == 'human' and conversation['messages'] == messages


def test_single_credentials_migration_preserves_agent_settings_and_mcp_assignments(store):
    credentials = store.seal({'id': 'retained-key', 'apikey': 'same-api-key'})
    old_provisioning = store.seal({'id': 'archived-key', 'secretkey': 'legacy-secret'})
    mcp_token = store.seal('private-mcp-credential')
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,model,instructions,can_provision) '
                  'VALUES(?,?,?,?,?,?,?,?,?)',
                  ('agent', 'Preserved agent', 'domain', 'account', 'user', credentials, 'model-id', 'Custom prompt', 1))
    store.execute('INSERT INTO mcp_servers(id,name,url,token) VALUES(?,?,?,?)',
                  ('search', 'Search', 'https://search.example/mcp', mcp_token))
    store.execute('INSERT INTO mcp_assignments VALUES(?,?,?)', ('agent', 'search', '["web_search"]'))
    store.execute('DROP TABLE legacy_agent_credentials')
    store.execute('ALTER TABLE agents RENAME COLUMN credentials TO runtime')
    store.execute('ALTER TABLE agents ADD COLUMN provisioning BLOB')
    store.execute('UPDATE agents SET provisioning=?', (old_provisioning,))
    store.execute('DROP TABLE conversation_compactions')
    for column in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window'):
        store.execute('ALTER TABLE agents DROP COLUMN ' + column)
    store.execute('ALTER TABLE agents DROP COLUMN thinking')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_providers')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('PRAGMA user_version=11')
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    agent = reopened.one('SELECT * FROM agents')
    assert agent['credentials'] == credentials and not {'runtime', 'provisioning'} & agent.keys()
    assert {key: agent[key] for key in ('id', 'name', 'domain_id', 'account_id', 'user_id', 'model', 'instructions', 'can_provision')} == {
        'id': 'agent', 'name': 'Preserved agent', 'domain_id': 'domain', 'account_id': 'account', 'user_id': 'user',
        'model': 'model-id', 'instructions': 'Custom prompt', 'can_provision': 1}
    assert reopened.one('SELECT credentials FROM legacy_agent_credentials WHERE agent_id=?', ('agent',))['credentials'] == old_provisioning
    assert reopened.one('SELECT token FROM mcp_servers')['token'] == mcp_token
    assert reopened.one('SELECT * FROM mcp_assignments') == {
        'agent_id': 'agent', 'server_id': 'search', 'tools': '["web_search"]'}


def test_thinking_migration_preserves_credentials_and_conversations_with_model_default(store):
    credentials = store.seal({'id': 'account-key', 'apikey': 'unchanged-key'})
    messages = store.seal([{'private': 'unchanged conversation'}])
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                  ('agent', 'Agent', 'domain', 'account', 'user', credentials))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'human', 'Existing conversation', 1, messages))
    store.execute('DROP TABLE conversation_compactions')
    for column in ('compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window'):
        store.execute('ALTER TABLE agents DROP COLUMN ' + column)
    store.execute('ALTER TABLE agents DROP COLUMN thinking')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_providers')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('PRAGMA user_version=12')
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    agent = reopened.one('SELECT * FROM agents')
    assert agent['thinking'] == 'default' and agent['credentials'] == credentials
    assert reopened.one('SELECT messages FROM conversations')['messages'] == messages
    reopened.execute("UPDATE agents SET thinking='high' WHERE id='agent'")
    assert Store(str(store.path), str(store.path.parent / 'master')).one('SELECT thinking FROM agents')['thinking'] == 'high'


async def test_revoked_cloudstack_account_invalidates_session(store):
    enabled = True

    async def human_call(identity, command, params):
        if command == 'listUsers':
            return {'user': [{'id': 'person', 'state': 'enabled' if enabled else 'disabled'}]}
        return {'account': [{'name': 'admin', 'domainid': 'root', 'state': 'enabled', 'accounttype': 1}]}

    app = SimpleNamespace(store=store, human_call=human_call)
    auth = Auth(app)
    private = {'userid': 'person', 'username': 'admin', 'domainid': 'root', 'account': 'admin', 'type': 1,
               'sessionkey': 'secret-session', 'cookies': {'JSESSIONID': 'private-cookie'}}
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                  (auth.digest('opaque-token'), 'csrf-nonce', store.seal(private), time.time() + 300))
    identity = await auth.identity('opaque-token')
    assert 'sessionkey' not in identity and 'cookies' not in identity
    assert identity['userid'] == 'person'
    auth.csrf('opaque-token', 'csrf-nonce')
    with pytest.raises(PermissionError):
        auth.csrf('opaque-token', 'forged')
    enabled = False
    with pytest.raises(PermissionError):
        await auth.identity('opaque-token')
    assert not store.one('SELECT token_hash FROM sessions')


async def test_session_expiration_and_persistent_login_rate_limit(store):
    app = SimpleNamespace(store=store)
    auth = Auth(app)
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                  (auth.digest('expired'), 'csrf', store.seal({}), time.time() - 1))
    with pytest.raises(PermissionError, match='expired'):
        await auth.identity('expired')
    for _ in range(8):
        with pytest.raises(PermissionError, match='Invalid login'):
            await auth.login('', '', '/', 'test-address')
    restarted = Auth(app)
    with pytest.raises(PermissionError, match='Too many'):
        await restarted.login('', '', '/', 'test-address')


@pytest.mark.parametrize('raw,expected', [(None, 3600), ('43200', 43200), ('0', None),
                                         ('-1', None), ('1.5', None), ('forever', None)])
def test_session_lifetime_environment_default_override_and_validation(monkeypatch, raw, expected):
    from dirigentenstab import settings

    monkeypatch.setattr(settings, 'load_dotenv', lambda: None)
    monkeypatch.setenv('CLOUDSTACK_URL', 'https://cloud.invalid/client/api')
    monkeypatch.setenv('PUBLIC_ORIGIN', 'https://hub.invalid')
    if raw is None:
        monkeypatch.delenv('SESSION_SECONDS', raising=False)
    else:
        monkeypatch.setenv('SESSION_SECONDS', raw)
    if expected is None:
        with pytest.raises(ValueError):
            settings.Settings.load()
    else:
        assert settings.Settings.load().session_seconds == expected


async def test_configured_login_lifetime_matches_cookie_and_server_expiration(store, monkeypatch):
    from http.cookies import SimpleCookie

    import httpx
    from fastapi import FastAPI

    from dirigentenstab import auth as auth_module, settings

    monkeypatch.setattr(settings, 'load_dotenv', lambda: None)
    monkeypatch.setenv('CLOUDSTACK_URL', 'https://cloud.invalid/client/api')
    monkeypatch.setenv('PUBLIC_ORIGIN', 'https://hub.invalid')
    monkeypatch.setenv('SESSION_SECONDS', '43200')
    configuration = settings.Settings.load()

    async def human_call(identity, command, params):
        if command == 'listUsers':
            return {'user': [{'id': 'person', 'state': 'enabled'}]}
        return {'account': [{'name': 'admin', 'domainid': 'root', 'state': 'enabled', 'accounttype': 1}]}

    def cloud_login(request):
        assert request.url == configuration.cloudstack_url
        return httpx.Response(200, json={'loginresponse': {
            'userid': 'person', 'username': 'admin', 'domainid': 'root', 'account': 'admin',
            'type': 1, 'sessionkey': 'private-cloud-session'}},
            headers={'set-cookie': 'JSESSIONID=private-cloud-cookie; Path=/'})

    client_type = httpx.AsyncClient
    monkeypatch.setattr(auth_module.httpx, 'AsyncClient',
                        lambda **kwargs: client_type(transport=httpx.MockTransport(cloud_login), **kwargs))
    monkeypatch.setattr(auth_module, 'bind_sockets', lambda auth: None)
    auth = Auth(SimpleNamespace(store=store, settings=configuration, human_call=human_call))
    application = FastAPI()
    auth_module.attach(application, auth, configuration)
    started = time.time()
    async with client_type(transport=httpx.ASGITransport(app=application), base_url=configuration.origin) as client:
        response = await client.post('/auth/login', data={'username': 'admin', 'password': 'fixture-password', 'domain': '/'},
                                     headers={'origin': configuration.origin})
    finished = time.time()
    assert response.status_code == 303
    cookie = SimpleCookie(response.headers['set-cookie'])['ds_session']
    assert cookie['max-age'] == '43200'
    token = cookie.value
    session = store.one('SELECT expires,csrf FROM sessions WHERE token_hash=?', (auth.digest(token),))
    assert started + 43200 <= session['expires'] <= finished + 43200
    now = session['expires'] - 1
    monkeypatch.setattr(auth_module.time, 'time', lambda: now)
    assert (await auth.identity(token))['userid'] == 'person'
    auth.csrf(token, session['csrf'])
    now = session['expires']
    with pytest.raises(PermissionError, match='Session expired'):
        await auth.identity(token)
    with pytest.raises(PermissionError, match='Invalid CSRF token'):
        auth.csrf(token, session['csrf'])
