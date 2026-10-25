import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import tarfile

import pytest


spec = importlib.util.spec_from_file_location('migrate_data', Path(__file__).parents[1] / 'scripts/migrate_data.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_groups_require_complete_acyclic_source_relationships():
    with pytest.raises(ValueError, match='Missing'):
        migration.ordered_groups([{'source_id': 'child', 'parent_source_id': 'missing'}])
    with pytest.raises(ValueError, match='cycles'):
        migration.ordered_groups([{'source_id': 'a', 'parent_source_id': 'b'},
                                  {'source_id': 'b', 'parent_source_id': 'a'}])
    groups = [{'source_id': 'child', 'parent_source_id': 'parent'}, {'source_id': 'parent'}]
    assert [group['source_id'] for group in migration.ordered_groups(groups)] == ['parent', 'child']
    assert migration.label('source', 'w') == migration.label('source', 'w')
    assert len(migration.label('source', 'w')) == 10
    chain = [{'source_id': str(index), 'parent_source_id': str(index - 1) if index else None}
             for index in range(9)]
    with pytest.raises(ValueError, match='depth'):
        migration.ordered_groups(chain)


def test_archive_quarantines_credentials_and_never_follows_external_links(tmp_path):
    source = tmp_path / 'workspace'
    source.mkdir()
    (source / 'code.py').write_text('print(42)\n')
    (source / '.env.local').write_text('TOKEN=synthetic-only\n')
    (source / 'hidden.txt').write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n')
    outside = tmp_path / 'outside'
    outside.write_text('outside content must never be read')
    (source / 'escape').symlink_to(outside)
    (source / 'relative').symlink_to('code.py')
    (source / 'known.txt').write_text('synthetic-known-provider-secret')
    destination = tmp_path / 'workspace.tar.gz'
    result = migration.safe_archive(source, destination, migration.tree_state(source),
                                    (b'synthetic-known-provider-secret',))
    assert [item['path'] for item in result['files']] == ['code.py']
    assert result['files'][0]['sha256'] == hashlib.sha256(b'print(42)\n').hexdigest()
    assert {item['path'] for item in result['quarantine']} == {'.env.local', 'hidden.txt', 'escape', 'known.txt'}
    with tarfile.open(destination) as archive:
        assert set(archive.getnames()) == {'code.py', 'relative'}
        assert archive.extractfile('code.py').read() == b'print(42)\n'


def test_open_rejects_intermediate_symlink_and_capture_rejects_changed_source(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret').write_text('synthetic secret')
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'link').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        migration.safe_open(source, 'link/secret')
    file = source / 'file'
    file.write_text('before')
    state = migration.tree_state(source)
    file.write_text('changed')
    with pytest.raises(ValueError, match='changed'):
        migration.safe_archive(source, tmp_path / 'archive.tar.gz', state)


def test_sensitive_content_detection_spans_chunk_boundaries():
    secret = b'fixture-token-123456789'
    content = b'x' * (1024 * 1024 - 4) + secret + b'tail'
    checksum, sensitive = migration.scan_file(io.BytesIO(content), (secret,))
    assert sensitive and checksum == hashlib.sha256(content).hexdigest()
    assert not migration.internal_link('nested/link', '../../outside')
    assert not migration.internal_link('nested/link', '../.ssh/id_ed25519')
    assert migration.internal_link('nested/link', '../code.py')
    assert migration.internal_link('alias', '.')
    assert migration.internal_link('sub/alias', '..')


def test_capture_detects_content_race_even_when_size_and_mtime_are_restored(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    path = source / 'file'
    path.write_bytes(b'initial')
    state = migration.tree_state(source)
    scan = migration.scan_file

    def swap_after_scan(file, secrets):
        result = scan(file, secrets)
        path.write_bytes(b'changed')
        os.utime(path, ns=(path.stat().st_atime_ns, state['file']['mtime_ns']))
        return result

    monkeypatch.setattr(migration, 'scan_file', swap_after_scan)
    with pytest.raises(ValueError, match='contents changed'):
        migration.safe_archive(source, tmp_path / 'archive.tar.gz', state)
    assert not (tmp_path / 'archive.tar.gz').exists()


@pytest.mark.skipif(shutil.which('gpg') is None, reason='GnuPG is required for operator backup verification')
def test_original_backup_authenticates_decrypt_and_checks_file_link_and_byte_totals(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    content = b'synthetic private workspace fixture\n'
    (source / 'file').write_bytes(content)
    os.link(source / 'file', source / 'hardlink')
    (source / 'symlink').symlink_to('file')
    key = tmp_path / 'key'
    key.write_text('synthetic-test-passphrase-only')
    backup = tmp_path / 'original.tar.gpg'
    checksum = migration.original_backup(source, backup, key)
    expected = {'files': 2, 'links': 1, 'bytes': len(content) * 2}
    assert migration.verify_original(backup, key, checksum, expected) == expected
    with pytest.raises(ValueError, match='totals'):
        migration.verify_original(backup, key, checksum, {**expected, 'files': 3})
    damaged = bytearray(backup.read_bytes())
    damaged[-1] ^= 1
    backup.write_bytes(damaged)
    with pytest.raises((ValueError, tarfile.TarError), match='decryption|header|archive|data'):
        migration.verify_original(backup, key, checksum, expected)
