import time
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet, InvalidToken

from dirigentenstab.auth import (GLOBAL_LOGIN_ATTEMPTS, KEEPALIVE_SECONDS, TRANSIENT_GRACE_SECONDS, USER_LOGIN_ATTEMPTS,
                                 Auth)
from dirigentenstab.cloud import CloudError
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
    assert reopened.one('PRAGMA user_version')['user_version'] == 25
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
    store.execute('ALTER TABLE agents DROP COLUMN enabled_secrets')
    store.execute('DROP TABLE secrets')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('ALTER TABLE agents DROP COLUMN escalation_requests_enabled')
    store.execute('DROP TABLE escalation_requests')
    store.execute('DROP TABLE conversation_seen')
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
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,model,instructions) '
                  'VALUES(?,?,?,?,?,?,?,?)',
                  ('agent', 'Preserved agent', 'domain', 'account', 'user', credentials, 'model-id', 'Custom prompt'))
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
    store.execute('ALTER TABLE agents DROP COLUMN enabled_secrets')
    store.execute('DROP TABLE secrets')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('ALTER TABLE agents DROP COLUMN escalation_requests_enabled')
    store.execute('DROP TABLE escalation_requests')
    store.execute('DROP TABLE conversation_seen')
    store.execute('PRAGMA user_version=11')
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    agent = reopened.one('SELECT * FROM agents')
    assert agent['credentials'] == credentials and not {'runtime', 'provisioning'} & agent.keys()
    assert {key: agent[key] for key in ('id', 'name', 'domain_id', 'account_id', 'user_id', 'model', 'instructions')} == {
        'id': 'agent', 'name': 'Preserved agent', 'domain_id': 'domain', 'account_id': 'account', 'user_id': 'user',
        'model': 'model-id', 'instructions': 'Custom prompt'}
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
    store.execute('ALTER TABLE agents DROP COLUMN enabled_secrets')
    store.execute('DROP TABLE secrets')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_mcp_servers')
    store.execute('ALTER TABLE agents DROP COLUMN owner_ssh_key_enabled')
    store.execute('ALTER TABLE agents DROP COLUMN escalation_requests_enabled')
    store.execute('DROP TABLE escalation_requests')
    store.execute('DROP TABLE conversation_seen')
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

    app = SimpleNamespace(store=store, human_call=human_call, settings=SimpleNamespace(session_seconds=3600))
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
    auth.verified.clear()
    with pytest.raises(PermissionError):
        await auth.identity('opaque-token')
    assert not store.one('SELECT token_hash FROM sessions')


async def test_native_revalidation_is_cached_for_thirty_seconds(store, monkeypatch):
    calls, enabled, clock = [], True, [1000.0]

    async def human_call(identity, command, params):
        calls.append(command)
        if command == 'listUsers':
            return {'user': [{'id': 'person', 'state': 'enabled' if enabled else 'disabled'}]}
        return {'account': [{'name': 'admin', 'domainid': 'root', 'state': 'enabled', 'accounttype': 1}]}

    monkeypatch.setattr('dirigentenstab.auth.time.monotonic', lambda: clock[0])
    auth = Auth(SimpleNamespace(store=store, human_call=human_call, settings=SimpleNamespace(session_seconds=3600)))
    private = {'userid': 'person', 'username': 'admin', 'domainid': 'root', 'account': 'admin', 'type': 1}
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                  (auth.digest('tok'), 'csrf', store.seal(private), time.time() + 300))
    await auth.identity('tok')
    assert len(calls) == 2
    clock[0] += 29
    enabled = False
    assert (await auth.identity('tok'))['userid'] == 'person'
    assert len(calls) == 2
    clock[0] += 1
    with pytest.raises(PermissionError):
        await auth.identity('tok')
    assert len(calls) == 4
    assert not store.one('SELECT token_hash FROM sessions')
    enabled = True
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                  (auth.digest('tok'), 'csrf', store.seal(private), time.time() + 300))
    await auth.identity('tok')
    assert len(calls) == 6
    await auth.identity('tok')
    assert len(calls) == 6
    await auth.identity_from_session(auth.digest('tok'), fresh=True)
    assert len(calls) == 8
    await auth.identity('tok')
    store.execute('DELETE FROM sessions')
    with pytest.raises(PermissionError, match='Session expired'):
        await auth.identity('tok')


async def test_session_expiration_and_persistent_login_rate_limit(store):
    app = SimpleNamespace(store=store)
    auth = Auth(app)
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                  (auth.digest('expired'), 'csrf', store.seal({}), time.time() - 1))
    with pytest.raises(PermissionError, match='expired'):
        await auth.identity('expired')
    for _ in range(8):
        with pytest.raises(PermissionError, match='Invalid login'):
            await auth.login('', '', '/')
    restarted = Auth(app)
    with pytest.raises(PermissionError, match='Too many'):
        await restarted.login('', '', '/')


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


async def test_configured_idle_timeout_sets_server_expiry_and_cookie_has_none(store, monkeypatch):
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
    assert not cookie['max-age'] and not cookie['expires']  # browser-session cookie; server expiry is the authority
    assert cookie['httponly'] and cookie['secure'] and cookie['samesite'].lower() == 'strict'
    token = cookie.value
    session = store.one('SELECT expires,csrf FROM sessions WHERE token_hash=?', (auth.digest(token),))
    assert started + 43200 <= session['expires'] <= finished + 43200
    now = session['expires'] - 1
    monkeypatch.setattr(auth_module.time, 'time', lambda: now)
    assert (await auth.identity(token))['userid'] == 'person'
    auth.csrf(token, session['csrf'])
    renewed = store.one('SELECT expires FROM sessions WHERE token_hash=?', (auth.digest(token),))['expires']
    assert renewed == now + 43200  # activity at the end of the first window slides the expiry
    now = renewed
    with pytest.raises(PermissionError, match='Session expired'):
        await auth.identity(token)
    with pytest.raises(PermissionError, match='Invalid CSRF token'):
        auth.csrf(token, session['csrf'])


def test_escalation_migration_preserves_single_queue_ciphertext_decisions_and_history(store):
    # Recreate the actual deployed schema17, with encrypted records and disabled access.
    for column in ('command', 'description', 'reason'):
        store.execute('ALTER TABLE escalation_requests DROP COLUMN ' + column)
    store.execute('ALTER TABLE escalation_requests RENAME TO compute_offering_requests')
    store.execute('ALTER TABLE agents RENAME COLUMN escalation_requests_enabled TO compute_offering_requests_enabled')
    store.execute('ALTER TABLE agents DROP COLUMN enabled_secrets')
    store.execute('DROP TABLE secrets')
    store.execute('DROP TABLE conversation_seen')
    store.execute('PRAGMA user_version=17')
    credentials, params = store.seal({'apikey': 'legacy-key'}), store.seal({'name': 'Legacy', 'domainid': 'owned'})
    result = store.seal({'serviceoffering': {'id': 'created-offering'}})
    history = store.seal([{'kind': 'request', 'parts': [{'part_kind': 'system-prompt',
                           'content': 'Saved legacy notice', 'dynamic_ref': 'compute_offering_decision'}]}])
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,compute_offering_requests_enabled) '
                  'VALUES(?,?,?,?,?,?,0)', ('agent', 'Agent', 'owned', 'account', 'user', credentials))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,compute_offering_requests_enabled) '
                  'VALUES(?,?,?,?,?,?,1)', ('child', 'Child', 'owned-child', 'child-account', 'child-user', credentials))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'owner', 'History', 1, history))
    store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                  ('run', 'conversation', 'completed', 'agent', 1, 1, store.seal([])))
    statuses = ('pending', 'applying', 'approved', 'deferred', 'uncertain', 'failed')
    for status in statuses:
        store.execute('INSERT INTO compute_offering_requests '
                      '(id,agent_id,conversation_id,run_id,call_id,human_id,params,result,status,created,updated,delivery_run_id) '
                      'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                      (status, 'agent', 'conversation', 'run', status, 'owner', params, result, status, 1, 2,
                       'run' if status == 'approved' else None))
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    assert not reopened.one("SELECT name FROM sqlite_master WHERE name='compute_offering_requests'")
    assert {row['id']: row['escalation_requests_enabled'] for row in reopened.all(
        'SELECT id,escalation_requests_enabled FROM agents')} == {'agent': 0, 'child': 1}
    assert reopened.one("SELECT value FROM platform_settings WHERE name='escalation_request_limit'")['value'] == '3'
    assert reopened.one('SELECT credentials FROM agents')['credentials'] == credentials
    assert reopened.one('SELECT messages FROM conversations')['messages'] == history
    rows = reopened.all('SELECT * FROM escalation_requests ORDER BY id')
    assert {row['status'] for row in rows} == set(statuses)
    for row in rows:
        assert row['params'] == params and row['result'] == result
        assert row['command'] == 'createServiceOffering'
        assert row['call_id'] == row['status'] and row['created'] == 1 and row['updated'] == 2
        assert row['description'] == 'Legacy compute offering request'
        assert row['delivery_run_id'] == ('run' if row['status'] == 'approved' else None)


def _session_auth(store, human_call, closed=None):
    service = SimpleNamespace(store=store, human_call=human_call, settings=SimpleNamespace(session_seconds=3600),
                              close_user_terminal_sessions=(closed if closed is not None else []).append)
    auth = Auth(service)
    private = {'userid': 'person', 'username': 'admin', 'domainid': 'root', 'account': 'admin', 'type': 1}
    for name, expires in (('live', time.time() + 300), ('old', time.time() - 1)):
        store.execute('INSERT INTO sessions VALUES(?,?,?,?)', (auth.digest(name), 'csrf', store.seal(private), expires))
    return auth


def _ok(calls=None):
    async def human_call(identity, command, params):
        if calls is not None:
            calls.append(identity['_session'])
        if command == 'listUsers':
            return {'user': [{'id': 'person', 'state': 'enabled'}]}
        return {'account': [{'name': 'admin', 'domainid': 'root', 'state': 'enabled', 'accounttype': 1}]}
    return human_call


def _expires(store, auth, name):
    return store.one('SELECT expires FROM sessions WHERE token_hash=?', (auth.digest(name),))['expires']


async def test_activity_renews_throttled_and_idle_session_expires(store, monkeypatch):
    from dirigentenstab import auth as auth_module
    auth = _session_auth(store, _ok())
    now = 1000.0
    monkeypatch.setattr(auth_module.time, 'time', lambda: now)
    store.execute('UPDATE sessions SET expires=? WHERE token_hash=?', (now + 300, auth.digest('live')))
    await auth.identity('live')
    assert _expires(store, auth, 'live') == now + 3600
    now += 30  # within the throttle window: no write
    await auth.identity('live', renew=False)
    await auth.identity('live')
    assert _expires(store, auth, 'live') == 1000.0 + 3600
    now += 61
    await auth.identity('live', renew=False)  # polling alone never extends the session
    assert _expires(store, auth, 'live') == 1000.0 + 3600
    await auth.identity('live')  # a user action does
    assert _expires(store, auth, 'live') == now + 3600
    now += 3600  # idle for the full timeout
    with pytest.raises(PermissionError, match='Session expired'):
        await auth.identity('live')


async def test_keepalive_and_agent_revalidation_do_not_renew(store):
    auth = _session_auth(store, _ok())
    before = _expires(store, auth, 'live')
    await auth.keepalive()
    await auth.identity_from_session(auth.digest('live'))
    assert _expires(store, auth, 'live') == before


async def test_keepalive_touches_only_unexpired_sessions(store):
    calls = []
    auth = _session_auth(store, _ok(calls))
    await auth.keepalive()
    assert set(calls) == {auth.digest('live')}
    assert store.one('SELECT 1 FROM sessions WHERE token_hash=?', (auth.digest('old'),))


@pytest.mark.parametrize('error', [PermissionError('gone'), CloudError('bad account', rejected=True)])
async def test_keepalive_definitive_failure_revokes_and_closes_terminals(store, error):
    closed = []

    async def human_call(identity, command, params):
        raise error
    auth = _session_auth(store, human_call, closed)
    await auth.keepalive()
    assert not store.one('SELECT 1 FROM sessions WHERE token_hash=?', (auth.digest('live'),))
    assert closed == ['person']


@pytest.mark.parametrize('error', [httpx.ConnectError('down'), httpx.ReadTimeout('slow'),
                                   CloudError('CloudStack error 530: internal')])
async def test_transient_failure_keeps_session_and_loop_continues(store, error):
    async def human_call(identity, command, params):
        raise error
    auth = _session_auth(store, human_call)
    await auth.keepalive()
    assert store.one('SELECT 1 FROM sessions WHERE token_hash=?', (auth.digest('live'),))
    with pytest.raises(CloudError, match='temporarily unreachable'):
        await auth.identity('live')
    assert store.one('SELECT 1 FROM sessions WHERE token_hash=?', (auth.digest('live'),))


async def test_transient_failure_allows_recently_verified_session_only(store, monkeypatch):
    clock, down = [1000.0], []

    async def human_call(identity, command, params):
        if down:
            raise httpx.ConnectError('down')
        return await _ok()(identity, command, params)
    monkeypatch.setattr('dirigentenstab.auth.time.monotonic', lambda: clock[0])
    auth = _session_auth(store, human_call)
    await auth.identity('live')
    down.append(1)
    clock[0] += 60
    assert (await auth.identity('live'))['userid'] == 'person'
    clock[0] += TRANSIENT_GRACE_SECONDS
    with pytest.raises(CloudError):
        await auth.identity('live')
    assert store.one('SELECT 1 FROM sessions WHERE token_hash=?', (auth.digest('live'),))


def test_grace_covers_at_least_two_keepalives():
    assert TRANSIENT_GRACE_SECONDS >= 2 * KEEPALIVE_SECONDS


async def test_tab_woken_after_one_failed_keepalive_still_has_grace(store, monkeypatch):
    clock, down = [1000.0], []

    async def human_call(identity, command, params):
        if down:
            raise httpx.ConnectError('down')
        return await _ok()(identity, command, params)
    monkeypatch.setattr('dirigentenstab.auth.time.monotonic', lambda: clock[0])
    auth = _session_auth(store, human_call)
    await auth.identity('live')
    down.append(1)
    clock[0] += KEEPALIVE_SECONDS  # the next keepalive fails; the tab wakes just after it
    await auth.keepalive()
    clock[0] += 1
    assert (await auth.identity('live'))['userid'] == 'person'


async def test_failed_logins_lock_out_per_user_not_per_client(store):
    auth = Auth(SimpleNamespace(store=store))
    for _ in range(USER_LOGIN_ATTEMPTS):
        with pytest.raises(PermissionError, match='Invalid login'):
            await auth.login('', '', '/')
    with pytest.raises(PermissionError, match='Too many'):
        await auth.login('', '', '/')
    with pytest.raises(PermissionError, match='Invalid login'):  # another user is unaffected
        await auth.login('', 'x', 'other')


async def test_global_login_cap_limits_spread_guessing(store):
    auth = Auth(SimpleNamespace(store=store))
    for n in range(GLOBAL_LOGIN_ATTEMPTS):
        with pytest.raises(PermissionError, match='Invalid login'):
            await auth.login('', '', 'd%d' % n)
    with pytest.raises(PermissionError, match='Too many'):
        await auth.login('', '', 'fresh')
