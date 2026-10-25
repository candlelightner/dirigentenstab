import json
import base64
import importlib.util
from pathlib import Path
import hashlib
import os
import sqlite3
from types import SimpleNamespace
import subprocess

import pytest
from cryptography.fernet import Fernet
from pydantic_ai.messages import ModelMessagesTypeAdapter

from dirigentenstab.store import Store
spec = importlib.util.spec_from_file_location('migrate_history', Path(__file__).parents[1] / 'scripts/migrate_history.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


@pytest.fixture
def configured(tmp_path):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key() + b'\n')
    key.chmod(0o600)
    store = Store(str(tmp_path / 'app.db'), str(key))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) '
                  'VALUES(?,?,?,?,?,?)', ('target', 'Target', 'domain', 'account', 'user',
                                           store.seal({})))
    root = tmp_path / 'legacy-agents'
    history = root / '.codex/sessions/2026/01'
    history.mkdir(parents=True)
    private = tmp_path / 'old-credentials.json'
    private.write_text(json.dumps({'access_token': 'OLD-PRIVATE-TOKEN-DO-NOT-MIGRATE'}))
    private.chmod(0o600)
    mapping = tmp_path / 'mapping.json'
    mapping.write_text(json.dumps({'version': 1, 'human_id': 'human', 'secret_references': [str(private)],
                                   'agents': [{'source_id': 'old-agent', 'target_agent_id': 'target',
                                               'agents_path': str(root)}]}))
    mapping.chmod(0o600)
    args = SimpleNamespace(mapping=mapping, database=store.path, key_file=key, archive_dir=tmp_path / 'archives',
                           dry_run=False, progress=False)
    return args, store, history


def write_codex(path, records):
    path.write_text(''.join(json.dumps(record) + '\n' for record in records))


def test_import_is_inert_redacted_encrypted_complete_and_idempotent(configured):
    args, store, history = configured
    source = history / 'rollout-session.jsonl'
    records = [
        {'type': 'session_meta', 'timestamp': '2026-01-02T03:04:05Z', 'payload': {'id': 'old-session'}},
        {'type': 'response_item', 'payload': {'type': 'message', 'role': 'developer',
                                             'content': [{'type': 'input_text', 'text': 'Historical system instruction'}]}},
        {'type': 'response_item', 'payload': {'type': 'message', 'role': 'user',
                                             'content': [{'type': 'input_text', 'text': 'A private old user message'}]}},
        {'type': 'response_item', 'payload': {'type': 'function_call', 'name': 'dangerous_old_tool',
                                             'arguments': '{"secretkey":"OLD-PRIVATE-TOKEN-DO-NOT-MIGRATE"}'}},
        {'type': 'response_item', 'payload': {'type': 'function_call_output', 'output': 'Historical result'}},
        {'type': 'response_item', 'payload': {'type': 'message', 'role': 'assistant',
                                             'content': [{'type': 'output_text', 'text': 'Historical assistant answer'}]}},
    ]
    write_codex(source, records)
    original = source.read_bytes()
    report = migration.run(args)
    row = store.one('SELECT * FROM conversations')
    assert row['imported'] == 1 and row['human_id'] == 'human' and row['agent_id'] == 'target'
    assert b'private old user message' not in store.path.read_bytes()
    messages = store.open(row['messages'])
    ModelMessagesTypeAdapter.validate_python(messages)
    parts = [part for message in messages for part in message['parts']]
    assert all(part['part_kind'] in {'user-prompt', 'text'} for part in parts)
    assert 'Historical system instruction' in str(parts) and 'Historical result' in str(parts)
    assert 'OLD-PRIVATE-TOKEN-DO-NOT-MIGRATE' not in str(parts)
    assert '[redacted]' in str(parts)
    assert report['source_files'] == 1 and report['conversations'] == 1
    archived = next(args.archive_dir.glob('*/original.jsonl.gpg'))
    restored = subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase-file', str(args.key_file),
                               '--decrypt', str(archived)], capture_output=True, check=True).stdout
    assert restored == original
    assert report['manifest_sha256']
    again = migration.run(args)
    assert again['conversations'] == 1 and len(store.all('SELECT id FROM conversations')) == 1
    assert store.one('SELECT messages FROM conversations')['messages'] == row['messages']
    assert source.read_bytes() == original
    assert (args.archive_dir / 'destination-before.sqlite.gpg').exists()
    verified = migration.verify_archives(args.archive_dir, args.key_file)
    assert verified['verified_sources'] == 1 and verified['verified_source_bytes'] == len(original)
    assert verified['destination_backup_verified'] and verified['verified_transcript_chunks'] == 1


def test_malformed_record_is_preserved_in_archive_and_reported(configured):
    args, store, history = configured
    source = history / 'interrupted.jsonl'
    source.write_bytes(b'{"type":"response_item","payload":{"type":"message","role":"user","content":"hello"}}\n'
                       b'{"partial":"unfinished')
    report = migration.run(args)
    assert report['malformed_records'] == 1
    assert 'could not be rendered' in str(store.open(store.one('SELECT messages FROM conversations')['messages']))
    assert len(store.all('SELECT id FROM conversations')) == 1


def test_unrenderable_deep_json_still_gets_archived_with_a_visible_marker(configured):
    args, store, history = configured
    source = history / 'deep.jsonl'
    source.write_bytes(b'[' * 2000 + b'0' + b']' * 2000 + b'\n')
    report = migration.run(args)
    assert report['malformed_records'] == 1
    assert 'could not be rendered' in str(store.open(store.one('SELECT messages FROM conversations')['messages']))
    assert migration.verify_archives(args.archive_dir, args.key_file)['verified_source_bytes'] == source.stat().st_size


def test_legacy_surrogate_text_remains_readable_and_does_not_break_pydantic_restore(configured):
    args, store, history = configured
    write_codex(history / 'unicode.jsonl', [{'type': 'response_item', 'payload': {
        'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': 'Legacy \ud800 text'}]}}])
    migration.run(args)
    messages = store.open(store.one('SELECT messages FROM conversations')['messages'])
    ModelMessagesTypeAdapter.validate_python(messages)
    assert '\\ud800' in ''.join(part['content'] for message in messages for part in message['parts'])


def test_large_transcripts_split_into_bounded_valid_chunks(configured):
    args, store, history = configured
    source = history / 'large.jsonl'
    write_codex(source, [{'type': 'response_item', 'payload': {'type': 'function_call_output', 'output': '研' * 900000}}])
    report = migration.run(args)
    rows = store.all('SELECT * FROM conversations ORDER BY created')
    assert report['conversations'] > 1
    joined = ''
    for row in rows:
        encoded = store.cipher.decrypt(row['messages'])
        assert len(encoded) <= migration.CHUNK_BYTES
        messages = ModelMessagesTypeAdapter.validate_json(encoded)
        joined += ''.join(part.content for message in messages for part in message.parts)
    assert joined.count('研') == 900000


def test_dry_run_reads_metadata_without_importing_or_archiving(configured):
    args, store, history = configured
    write_codex(history / 'one.jsonl', [{'type': 'event_msg', 'payload': {'type': 'user_message', 'message': 'private'}}])
    args.dry_run = True
    report = migration.run(args)
    assert report['source_files'] == 1 and report['formats'] == {'codex': 1}
    assert not args.archive_dir.exists() and not store.all('SELECT * FROM conversations')


def test_symlink_sources_and_credential_files_are_never_imported(configured, tmp_path):
    args, store, history = configured
    secret = tmp_path / 'secret.jsonl'
    secret.write_text('{"password":"not history"}')
    (history / 'link.jsonl').symlink_to(secret)
    (history.parent / 'indirect').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        with migration.regular_file(history / 'link.jsonl'):
            pass
    args.dry_run = True
    assert migration.run(args)['source_files'] == 0


def test_claude_history_preserves_roles_and_tool_blocks_as_plain_text(configured):
    args, store, history = configured
    root = history.parents[3]
    claude = root / '.claude/projects/project/session.jsonl'
    claude.parent.mkdir(parents=True)
    write_codex(claude, [
        {'type': 'user', 'message': {'role': 'user', 'content': [{'type': 'text', 'text': 'Question'}]}},
        {'type': 'assistant', 'message': {'role': 'assistant', 'content': [
            {'type': 'tool_use', 'name': 'old_command', 'input': {'command': 'example'}},
            {'type': 'text', 'text': 'Answer'}]}},
    ])
    result = migration.run(args)
    assert result['formats'] == {'claude': 1}
    messages = store.open(store.one('SELECT messages FROM conversations')['messages'])
    assert 'old_command' in str(messages) and 'Question' in str(messages) and 'Answer' in str(messages)
    assert all(p['part_kind'] in {'text', 'user-prompt'} for m in messages for p in m['parts'])


def test_prompt_and_session_index_sidecars_are_preserved_as_private_reference_transcripts(configured):
    args, store, history = configured
    root = history.parents[3]
    write_codex(root / '.codex/history.jsonl', [{'session_id': 'old', 'text': 'Private orphaned prompt'}])
    write_codex(root / '.codex/session_index.jsonl', [{'id': 'old', 'thread_name': 'Private original title'}])
    result = migration.run(args)
    assert result['formats'] == {'codex-prompts': 1, 'codex-index': 1}
    rows = store.all('SELECT * FROM conversations')
    assert all('Private' not in row['title'] for row in rows)
    restored = str([store.open(row['messages']) for row in rows])
    assert 'Private orphaned prompt' in restored and 'Private original title' in restored
    assert migration.verify_archives(args.archive_dir, args.key_file)['verified_sources'] == 2


def test_redaction_covers_known_values_structured_fields_assignments_and_private_keys():
    value = {'secretkey': 'unknown-secret', 'output': 'known-private-value API_KEY=sk-abcdefghijklmnopqrstuv\n'
             '-----BEGIN OPENSSH PRIVATE KEY-----\nverysecret\n-----END OPENSSH PRIVATE KEY-----'}
    result = migration.redact(value, ['known-private-value'])
    assert result['secretkey'] == '[redacted]'
    assert 'known-private-value' not in result['output'] and 'verysecret' not in result['output']
    nested = migration.redact('{"api_key":"previously-unknown-secret","command":"example"}', [])
    assert 'previously-unknown-secret' not in nested and 'example' in nested
    assert 'unknown-header-value' not in migration.redact('Authorization: Bearer unknown-header-value', [])


def test_binary_reference_keys_are_loaded_only_as_redaction_variants(tmp_path):
    key = tmp_path / 'legacy-binary-key'
    value = bytes(range(256))
    key.write_bytes(value)
    references = migration.references([str(key)])
    assert value.hex() in references and base64.b64encode(value).decode() in references


def test_mapping_change_or_conversation_conflict_never_overwrites_existing_history(configured):
    args, store, history = configured
    write_codex(history / 'one.jsonl', [{'type': 'event_msg', 'payload': {'type': 'user_message', 'message': 'old'}}])
    migration.run(args)
    row = store.one('SELECT * FROM conversations')
    changed = store.seal([{'kind': 'response', 'parts': [{'part_kind': 'text', 'content': 'Changed outside migration'}]}])
    store.execute('UPDATE conversations SET messages=? WHERE id=?', (changed, row['id']))
    with pytest.raises(ValueError, match='conflicts'):
        migration.run(args)
    assert store.one('SELECT messages FROM conversations')['messages'] == changed


def test_interruption_after_capture_resumes_and_uses_immutable_source_snapshot(configured, monkeypatch):
    args, store, history = configured
    source = history / 'one.jsonl'
    write_codex(source, [{'type': 'event_msg', 'payload': {'type': 'user_message', 'message': 'Captured version'}}])
    original_import = migration.import_source

    def interrupted(*args):
        raise migration.MigrationError('Synthetic interruption after durable capture')

    monkeypatch.setattr(migration, 'import_source', interrupted)
    with pytest.raises(migration.MigrationError, match='Synthetic interruption'):
        migration.run(args)
    assert not store.all('SELECT id FROM conversations')
    assert (args.archive_dir / 'manifest.json').exists()
    source.write_text(source.read_text() + json.dumps({'type': 'event_msg', 'payload': {
        'type': 'user_message', 'message': 'Appended after point-in-time snapshot'}}) + '\n')
    monkeypatch.setattr(migration, 'import_source', original_import)
    result = migration.run(args)
    restored = store.open(store.one('SELECT messages FROM conversations')['messages'])
    assert result['conversations'] == 1
    assert 'Captured version' in str(restored) and 'Appended after point-in-time' not in str(restored)


@pytest.mark.parametrize('sidecar', ['-wal', '-shm'])
def test_unsafe_existing_sqlite_sidecars_are_rejected_without_modification(configured, sidecar):
    args, store, history = configured
    before = hashlib.sha256(store.path.read_bytes()).hexdigest()
    path = store.path.with_name(store.path.name + sidecar)
    path.write_bytes(b'Existing unsafe file must remain untouched')
    path.chmod(0o644)
    with pytest.raises(migration.MigrationError, match='ownership or private permissions'):
        with migration.database(store.path):
            pytest.fail('Unsafe database files must be rejected before use')
    assert path.read_bytes() == b'Existing unsafe file must remain untouched'
    assert hashlib.sha256(store.path.read_bytes()).hexdigest() == before


def test_sqlite_sidecar_symlinks_are_rejected_before_opening(configured, tmp_path):
    args, store, history = configured
    target = tmp_path / 'other-private-file'
    target.write_bytes(b'Unrelated private data')
    target.chmod(0o600)
    store.path.with_name(store.path.name + '-shm').symlink_to(target)
    with pytest.raises(migration.MigrationError, match='ownership or private permissions'):
        with migration.database(store.path):
            pytest.fail('A sidecar symlink must never be opened')
    assert target.read_bytes() == b'Unrelated private data'


@pytest.mark.skipif(os.geteuid() != 0, reason='Root-only native SQLite ownership check; no real application data')
def test_native_sqlite_root_writer_preserves_application_wal_ownership(tmp_path):
    directory = tmp_path / 'private-application'
    directory.mkdir(mode=0o700)
    path = directory / 'ownership.db'
    connection = sqlite3.connect(path)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('CREATE TABLE example(value INTEGER)')
    connection.close()
    path.chmod(0o600)
    os.chown(directory, 10001, 10001)
    os.chown(path, 10001, 10001)
    with migration.database(path) as connection:
        connection.execute('INSERT INTO example VALUES(1)')
        for suffix in ('-wal', '-shm'):
            info = path.with_name(path.name + suffix).stat()
            assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (10001, 10001, 0o600)
    assert os.geteuid() == 0
