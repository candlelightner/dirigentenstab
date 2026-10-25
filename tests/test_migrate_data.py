import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
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


def test_restore_preserves_source_marker_filename_and_rejects_symlink_destination(tmp_path):
    content = b'ordinary source file must be preserved'
    name = '.dirigentenstab-migration.json'
    archive = tmp_path / '.migration-workspace.tar.gz'
    with tarfile.open(archive, 'w:gz') as file:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        file.addfile(member, io.BytesIO(content))
    archive_bytes = archive.read_bytes()
    checksum = hashlib.sha256(archive_bytes).hexdigest()
    report = tmp_path / '.migration-files.json'
    report_json = json.dumps({'files': [{'path': name, 'size': len(content),
                                       'sha256': hashlib.sha256(content).hexdigest()}], 'links': []})
    report.write_text(report_json)
    program = migration.RESTORE_PROGRAM.replace("pathlib.Path('/home/dirigent/workspace')",
                                                'pathlib.Path(' + repr(str(tmp_path)) + ')')
    program = program.replace('assert os.getuid()!=0 and base.is_mount()', 'assert base.is_dir()')
    completed = subprocess.run([sys.executable, '-c', program, checksum], capture_output=True, timeout=10)
    assert completed.returncode == 0
    assert (tmp_path / 'legacy' / name).read_bytes() == content
    assert (tmp_path / 'legacy' / ('.dirigentenstab-migration-' + checksum + '.json')).is_file()
    other = tmp_path / 'other'
    other.mkdir()
    (other / '.migration-workspace.tar.gz').write_bytes(archive_bytes)
    (other / '.migration-files.json').write_text(report_json)
    (other / 'legacy').symlink_to(tmp_path / 'legacy', target_is_directory=True)
    rejected_program = program.replace(repr(str(tmp_path)), repr(str(other)))
    rejected = subprocess.run([sys.executable, '-c', rejected_program, checksum], capture_output=True, timeout=10)
    assert rejected.returncode != 0
    assert (tmp_path / 'legacy' / name).read_bytes() == content


class DeploymentStore:
    def __init__(self, phase):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.execute('CREATE TABLE vm_deployments(id,agent_id,phase,vm_id,updated)')
        self.db.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,?)', ('old', 'target', phase, None, 1))

    def all(self, sql, args):
        return [dict(row) for row in self.db.execute(sql, args)]

    def one(self, sql, args):
        return next(iter(self.all(sql, args)), None)


class DeploymentService:
    def __init__(self, phase):
        self.store, self.dispatched = DeploymentStore(phase), 0

    async def agent(self, agent_id):
        return {'id': agent_id}

    async def cloud_client(self, agent):
        return object()

    async def _deploy_managed(self, agent, cloud, params, *, workspace_disk):
        assert workspace_disk
        self.dispatched += 1
        self.store.db.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,?)',
                              ('new', agent['id'], 'complete', 'new-vm', 2))
        return {'virtualmachine': {'id': 'new-vm'}}

    async def recover_deployments(self):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize('phase', ['rejected', 'failed', 'dispatched', 'adopted'])
async def test_migration_retries_only_terminal_rejection(tmp_path, monkeypatch, phase):
    monkeypatch.setattr(migration, 'STATE', tmp_path)
    monkeypatch.setattr(migration, 'MANIFEST', tmp_path / 'manifest.json')
    (tmp_path / 'zone.json').write_text(json.dumps({'zone_id': 'zone', 'template_id': 'template',
                                                 'service_offering_id': 'offering'}))
    (tmp_path / 'migration-storage.json').write_text(json.dumps({'disk_offering_id': 'disk'}))
    agent = {'target_agent_id': 'target', 'deployment_id': 'old', 'deployment_phase': phase,
             'workspace_bytes': 1, 'source_id': 'fixture'}
    service = DeploymentService('failed' if phase == 'adopted' else phase)
    if phase == 'rejected':
        assert await migration.deploy({'agents': [agent]}, service, agent) == 'new-vm'
        assert service.dispatched == 1
        assert agent['rejected_deployment_ids'] == ['old']
        assert agent['deployment_id'] == 'new'
    elif phase == 'adopted':
        async def recover():
            service.store.db.execute("UPDATE vm_deployments SET phase='complete',vm_id='existing-vm'")
        service.recover_deployments = recover
        assert await migration.deploy({'agents': [agent]}, service, agent) == 'existing-vm'
        assert service.dispatched == 0
        assert agent['deployment_phase'] == 'complete'
    else:
        with pytest.raises(ValueError, match='explicit recovery'):
            await migration.deploy({'agents': [agent]}, service, agent)
        assert service.dispatched == 0
        assert agent['deployment_id'] == 'old'


@pytest.mark.parametrize(('target', 'accepted'), [('./folder/file', True), ('folder//file', True),
    ('folder/', True), ('folder/.', True), ('folder/../folder/file', False),
    ('folder/file/', False), ('missing/', False)])
def test_restore_accepts_only_redundant_safe_symlink_normalization(tmp_path, target, accepted):
    content = b'unchanged synthetic workspace data'
    archive = tmp_path / '.migration-workspace.tar.gz'
    with tarfile.open(archive, 'w:gz') as file:
        member = tarfile.TarInfo('folder/file')
        member.size = len(content)
        file.addfile(member, io.BytesIO(content))
        link = tarfile.TarInfo('link')
        link.type, link.linkname = tarfile.SYMTYPE, target
        file.addfile(link)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    # Simulate the already extracted directory: rerun must verify without extracting again.
    final = tmp_path / 'legacy'
    (final / 'folder').mkdir(parents=True)
    (final / 'folder/file').write_bytes(content)
    (final / 'link').symlink_to(os.path.normpath(target))
    (final / ('.dirigentenstab-migration-' + checksum + '.json')).write_text(
        json.dumps({'archive_sha256': checksum}))
    (tmp_path / '.migration-files.json').write_text(json.dumps({'files': [{'path': 'folder/file',
        'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}],
        'links': [{'path': 'link', 'target': target}]}))
    program = migration.RESTORE_PROGRAM.replace("pathlib.Path('/home/dirigent/workspace')",
                                                'pathlib.Path(' + repr(str(tmp_path)) + ')')
    program = program.replace('assert os.getuid()!=0 and base.is_mount()', 'assert base.is_dir()')
    result = subprocess.run([sys.executable, '-c', program, checksum], capture_output=True, timeout=10)
    assert (result.returncode == 0) == accepted
    assert (final / 'folder/file').read_bytes() == content
    if accepted:
        receipt = json.loads(result.stdout)
        assert receipt['normalized_links'] == 1 and receipt['archive_sha256'] == checksum
