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
    assert reopened.one('PRAGMA user_version')['user_version'] == 10
    assert reopened.one("SELECT name FROM sqlite_master WHERE name='credential_rotations'")


def test_permission_column_migration_preserves_agent_keys_and_owned_conversation(store):
    # Recreate the removed schema-9 column around real encrypted records before upgrading.
    store.execute("ALTER TABLE agents ADD COLUMN runtime_policy TEXT NOT NULL DEFAULT '[]'")
    store.execute('PRAGMA user_version=9')
    runtime, provisioning, messages = store.seal({'apikey': 'runtime'}), store.seal({'apikey': 'provision'}), store.seal([])
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,runtime_policy) '
                  'VALUES(?,?,?,?,?,?,?,?)', ('agent', 'Agent', 'domain', 'account', 'user', runtime, provisioning, '["old"]'))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'human', 'Preserved', 1, messages))
    reopened = Store(str(store.path), str(store.path.parent / 'master'))
    agent = reopened.one('SELECT * FROM agents')
    assert 'runtime_policy' not in agent and agent['runtime'] == runtime and agent['provisioning'] == provisioning
    conversation = reopened.one('SELECT * FROM conversations')
    assert conversation['agent_id'] == 'agent' and conversation['human_id'] == 'human' and conversation['messages'] == messages


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
