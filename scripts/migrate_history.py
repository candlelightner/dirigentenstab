#!/usr/bin/env python3
"""Import private legacy Codex/Claude histories as encrypted, read-only transcripts."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import uuid

from cryptography.fernet import Fernet, InvalidToken
from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelRequest, ModelResponse, TextPart, UserPromptPart

CHUNK_BYTES = 1024 * 1024
TEXT_CHARS = 120000
MAX_RECORD_BYTES = 64 * 1024 * 1024
SECRET_FIELD = re.compile(r'(?i)(password|secret|token|credential|authorization|cookie|private.?key|api.?key|encrypted_content)')
PRIVATE_KEY = re.compile(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', re.S)
ASSIGNMENT = re.compile(r'''(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret[_-]?key|password|authorization|cookie)\b(\s*[:=]\s*)(["']?)[^\s"';,}]+''')
COMMON_TOKEN = re.compile(r'\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b')
AUTH_HEADER = re.compile(r'(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+')


class MigrationError(ValueError):
    """A bounded, deliberately non-secret diagnostic safe to show an administrator."""


def private_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    sync_directory(path.parent)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def references(paths):
    values = set()

    def collect(value):
        if isinstance(value, str) and len(value) >= 8:
            values.add(value)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    for name in paths:
        with regular_file(Path(name)) as handle:
            value = handle.read(1024 * 1024 + 1)
        if len(value) > 1024 * 1024:
            raise MigrationError('A secret reference exceeds the 1 MiB limit; no history was imported')
        try:
            collect(json.loads(value))
        except (ValueError, UnicodeError):
            try:
                collect(value.decode().strip())
            except UnicodeError:
                for encoded in (value.hex(), base64.b64encode(value).decode(), base64.urlsafe_b64encode(value).decode()):
                    collect(encoded)
    return sorted(values, key=len, reverse=True)


def redact(value, secrets):
    if isinstance(value, dict):
        return {key: '[redacted]' if SECRET_FIELD.search(str(key)) else redact(item, secrets)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        if value.lstrip().startswith(('{', '[')):
            try:
                structured = json.loads(value)
                if isinstance(structured, (dict, list)):
                    return json.dumps(redact(structured, secrets), ensure_ascii=False)
            except (ValueError, RecursionError):
                pass
        for secret in secrets:
            value = value.replace(secret, '[redacted]')
        value = PRIVATE_KEY.sub('[redacted private key]', value)
        value = AUTH_HEADER.sub(lambda match: match[1] + ': [redacted]', value)
        value = ASSIGNMENT.sub(lambda match: match[1] + match[2] + '[redacted]', value)
        return COMMON_TOKEN.sub('[redacted token]', value)
    return value


@contextmanager
def regular_file(path):
    """Walk with directory descriptors so a guest cannot redirect a history read through symlinks."""
    path = path.absolute()
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MigrationError('History/reference sources must be regular files; no data imported')
        with os.fdopen(descriptor, 'rb') as handle:
            descriptor = None
            yield handle
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


@contextmanager
def database(path):
    """SQLite's native VFS inherits WAL/SHM ownership from the database."""
    owner = path.lstat()

    def check_files():
        for suffix in ('', '-wal', '-shm'):
            try:
                info = Path(str(path) + suffix).lstat()
            except FileNotFoundError:
                if suffix:
                    continue
                raise
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or (info.st_uid, info.st_gid) != (owner.st_uid, owner.st_gid)):
                raise MigrationError('SQLite database/sidecar ownership or private permissions are unsafe. '
                                     'No transaction was committed; inspect existing files before retrying.')

    check_files()
    connection = sqlite3.connect(path, timeout=30)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        check_files()
        with connection:
            yield connection
            check_files()
    finally:
        connection.close()


def source_files(mapping):
    for agent in mapping['agents']:
        root = Path(agent['agents_path']).absolute()
        for kind, relative in [('codex', '.codex/sessions'), ('codex', '.codex/archived_sessions'),
                               ('claude', '.claude/projects')]:
            start = root / relative
            if not start.exists() or any(part.is_symlink() for part in [start, *start.parents]):
                continue
            for directory, dirs, files in os.walk(start, followlinks=False):
                dirs[:] = sorted(name for name in dirs if not (Path(directory) / name).is_symlink())
                for name in sorted(files):
                    path = Path(directory) / name
                    if path.suffix != '.jsonl' or path.is_symlink():
                        continue
                    reference = kind + ':' + agent['source_id'] + ':' + str(path.relative_to(root))
                    key = hashlib.sha256(reference.encode()).hexdigest()
                    yield {'key': key, 'kind': kind, 'path': path, 'source_id': agent['source_id'],
                           'target': agent.get('target_agent_id')}
        for kind, relative in [('codex-prompts', '.codex/history.jsonl'), ('codex-index', '.codex/session_index.jsonl')]:
            path = root / relative
            if not path.is_file() or any(part.is_symlink() for part in [path, *path.parents]):
                continue
            reference = kind + ':' + agent['source_id'] + ':' + relative
            yield {'key': hashlib.sha256(reference.encode()).hexdigest(), 'kind': kind, 'path': path,
                   'source_id': agent['source_id'], 'target': agent.get('target_agent_id')}


def text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return '\n'.join(text(item) for item in value)
    if isinstance(value, dict) and isinstance(value.get('text'), str):
        return value['text']
    return json.dumps(value, ensure_ascii=False)


def transcript(record, kind):
    if not isinstance(record, dict):
        return 'assistant', '[Historical non-object record]\n' + text(record)
    if kind in {'codex-prompts', 'codex-index'}:
        label = 'prompt history' if kind == 'codex-prompts' else 'session index'
        return ('user' if kind == 'codex-prompts' else 'assistant'), f'[Historical {label}; reference only]\n' + text(record)
    if kind == 'claude':
        message = record.get('message')
        if isinstance(message, dict):
            role = message.get('role', record.get('type', 'unknown'))
            body = text(message.get('content', message))
            return ('user' if role == 'user' else 'assistant'), f'[Historical {role}]\n' + body
        return 'assistant', '[Historical Claude event]\n' + text(record)
    event, payload = record.get('type'), record.get('payload', {})
    if event in {'session_meta', 'turn_context', 'world_state', 'token_usage_record'}:
        return None
    if not isinstance(payload, dict):
        return 'assistant', '[Historical record]\n' + text(record)
    part = payload.get('type')
    if event == 'response_item':
        if part in {'message', 'agent_message'} or payload.get('role') in {'developer', 'system', 'user', 'assistant'}:
            role = payload.get('role', 'assistant')
            body = text(payload.get('content', payload))
            return ('user' if role == 'user' else 'assistant'), f'[Historical {role}; reference only]\n' + body
        if part == 'reasoning':
            summary = payload.get('summary')
            return ('assistant', '[Historical reasoning summary]\n' + text(summary)) if summary else None
        return 'assistant', '[Historical tool/action; never executed by this import]\n' + text(payload)
    if event == 'event_msg':
        if part in {'token_count', 'task_started', 'task_complete', 'context_compacted'}:
            return None
        if part in {'user_message', 'agent_message', 'agent_reasoning'}:
            return ('user' if part == 'user_message' else 'assistant'), f'[Historical UI event: {part}]\n' + text(
                payload.get('message', payload.get('text', payload)))
    return 'assistant', '[Historical event; reference only]\n' + text(record)


class Chunks:
    def __init__(self, source, folder, cipher, secrets, limit=CHUNK_BYTES):
        self.source, self.folder, self.cipher, self.secrets, self.limit = source, folder, cipher, secrets, limit
        self.items, self.size, self.chunks = [], 2, []
        self.records = self.displayed = self.malformed = 0
        self.created = source['path'].stat().st_mtime

    def append(self, role, body):
        body = redact(body, self.secrets).encode('utf-8', errors='backslashreplace').decode('utf-8')
        for offset in range(0, max(1, len(body)), TEXT_CHARS):
            piece = body[offset:offset + TEXT_CHARS]
            message = ModelRequest(parts=[UserPromptPart(piece)]) if role == 'user' else ModelResponse(parts=[TextPart(piece)])
            encoded = ModelMessagesTypeAdapter.dump_json([message])[1:-1]
            if len(encoded) + 2 > self.limit:
                raise MigrationError('A transcript segment exceeds the bounded conversation size; originals are preserved')
            if self.items and self.size + len(encoded) + 1 > self.limit:
                self.flush()
            self.items.append(encoded)
            self.size += len(encoded) + 1

    def record(self, raw, oversized=False):
        self.records += 1
        try:
            if oversized:
                raise ValueError('oversized')
            record = json.loads(raw)
            converted = transcript(redact(record, self.secrets), self.source['kind'])
        except (ValueError, TypeError, UnicodeError, RecursionError):
            self.malformed += 1
            self.append('assistant', f'[Legacy record {self.records} could not be rendered. '
                        'Its exact original bytes are retained in the encrypted source archive.]')
            return
        stamp = record.get('timestamp') if isinstance(record, dict) else None
        if self.records == 1 and isinstance(stamp, str):
            try:
                self.created = datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
            except ValueError:
                pass
        if converted:
            self.displayed += 1
            self.append(*converted)

    def flush(self):
        if not self.items:
            return
        encoded = b'[' + b','.join(self.items) + b']'
        ModelMessagesTypeAdapter.validate_json(encoded)
        index = len(self.chunks) + 1
        identity = str(uuid.uuid5(uuid.NAMESPACE_URL,
                                 f'dirigentenstab:history:{self.source["target"]}:{self.source["key"]}:{index}'))
        path = self.folder / (identity + '.fernet')
        with path.open('wb') as handle:
            handle.write(self.cipher.encrypt(encoded))
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
        self.chunks.append({'id': identity, 'file': path.name, 'sha256': hashlib.sha256(encoded).hexdigest(),
                            'bytes': len(encoded), 'part': index, 'created': self.created + index / 1000})
        self.items, self.size = [], 2


def gpg(command, key, *, output=None, archive=None, stdin=None, stdout=None):
    args = ['gpg', '--batch', '--yes', '--no-symkey-cache', '--pinentry-mode', 'loopback', '--passphrase-file', str(key)]
    if command == 'encrypt':
        args += ['--symmetric', '--cipher-algo', 'AES256', '--compress-algo', 'ZIP', '--output', str(output)]
    else:
        args += ['--decrypt', str(archive)]
    return subprocess.Popen(args, stdin=stdin, stdout=stdout, stderr=subprocess.DEVNULL)


def snapshot(source, folder, key, cipher, secrets):
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = folder / 'original.jsonl.gpg'
    temporary = folder / 'original.jsonl.gpg.tmp'
    chunks = Chunks(source, folder, cipher, secrets)
    chunks.append('assistant', '[Imported historical transcript. Read-only reference. Continuing starts a new '
                  'conversation without sending this old history to a model.]\nSource reference: ' + source['key'])
    digest = hashlib.sha256()
    with regular_file(source['path']) as original:
        before = os.fstat(original.fileno())
        remaining = before.st_size
        process = gpg('encrypt', key, output=temporary, stdin=subprocess.PIPE)
        try:
            while remaining:
                raw = original.readline(min(remaining, MAX_RECORD_BYTES + 1))
                if not raw:
                    raise MigrationError('A source changed during capture; no conversation from it was imported. Retry safely.')
                remaining -= len(raw)
                process.stdin.write(raw)
                digest.update(raw)
                oversized = len(raw) > MAX_RECORD_BYTES
                if oversized and not raw.endswith(b'\n'):
                    while remaining:
                        tail = original.readline(min(remaining, CHUNK_BYTES))
                        if not tail:
                            raise MigrationError('A source changed during capture; retry safely')
                        remaining -= len(tail)
                        process.stdin.write(tail)
                        digest.update(tail)
                        if tail.endswith(b'\n'):
                            break
                chunks.record(raw, oversized)
            process.stdin.close()
            if process.wait(timeout=120):
                raise MigrationError('GPG encryption failed; no history from this source was imported. Retry after checking disk space.')
            after = os.fstat(original.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                original.seek(0)
                verify, remaining = hashlib.sha256(), before.st_size
                while remaining:
                    block = original.read(min(CHUNK_BYTES, remaining))
                    if not block:
                        raise MigrationError('A source changed during capture; retry safely')
                    verify.update(block)
                    remaining -= len(block)
                if verify.digest() != digest.digest():
                    raise MigrationError('A source changed during capture; no history from it was imported. Retry safely.')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
    chunks.flush()
    with temporary.open('rb') as handle:
        os.fsync(handle.fileno())
    temporary.replace(archive)
    sync_directory(folder)
    return {'phase': 'captured', 'source_sha256': digest.hexdigest(), 'source_bytes': before.st_size,
            'archive_sha256': file_hash(archive), 'records': chunks.records, 'displayed_records': chunks.displayed,
            'malformed_records': chunks.malformed, 'chunks': chunks.chunks, 'target': source['target']}


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        while block := handle.read(CHUNK_BYTES):
            digest.update(block)
    return digest.hexdigest()


def backup_destination(destination, output, key):
    temporary_name = '.history-before-' + uuid.uuid4().hex + '.sqlite'
    temporary = destination.parent / temporary_name
    archive = output / 'destination-before.sqlite.gpg'
    try:
        with database(destination) as conn:
            backup = sqlite3.connect(temporary)
            try:
                conn.backup(backup)
            finally:
                backup.close()
        process = gpg('encrypt', key, output=archive.with_suffix('.gpg.tmp'), stdin=subprocess.PIPE)
        try:
            with regular_file(temporary) as handle:
                while block := handle.read(CHUNK_BYTES):
                    process.stdin.write(block)
            process.stdin.close()
            if process.wait(timeout=120):
                raise MigrationError('Application database backup encryption failed; no history was imported')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        with archive.with_suffix('.gpg.tmp').open('rb') as handle:
            os.fsync(handle.fileno())
        archive.with_suffix('.gpg.tmp').replace(archive)
        sync_directory(output)
        return {'archive_sha256': file_hash(archive), 'database_sha256': file_hash(temporary)}
    finally:
        temporary.unlink(missing_ok=True)


def import_source(entry, source, folder, destination, human, cipher):
    for chunk in entry['chunks']:
        sealed = (folder / chunk['file']).read_bytes()
        if hashlib.sha256(cipher.decrypt(sealed)).hexdigest() != chunk['sha256']:
            raise MigrationError('Encrypted transcript verification failed; import stopped without overwriting data')
        with database(destination) as conn:
            existing = conn.execute('SELECT agent_id,human_id,messages,imported FROM conversations WHERE id=?',
                                    (chunk['id'],)).fetchone()
            if existing:
                if (existing['agent_id'] != source['target'] or existing['human_id'] != human or not existing['imported']
                        or hashlib.sha256(cipher.decrypt(existing['messages'])).hexdigest() != chunk['sha256']):
                    raise MigrationError('An existing conversation conflicts with this import; nothing was overwritten')
                continue
            title = f'Imported {source["kind"].title()} {source["key"][:10]} · part {chunk["part"]:04d}'
            conn.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages,imported) VALUES(?,?,?,?,?,?,1)',
                         (chunk['id'], source['target'], human, title, chunk['created'], sealed))


def verify_archives(output, key):
    manifest = json.loads((output / 'manifest.json').read_text())
    report = {'verified_sources': 0, 'verified_source_bytes': 0, 'verified_transcript_chunks': 0,
              'destination_backup_verified': False}
    cipher = Fernet(key.read_bytes().strip())
    entries = [(output / 'destination-before.sqlite.gpg', manifest['destination_backup']['archive_sha256'],
                manifest['destination_backup']['database_sha256'], None)]
    for source_key, entry in manifest['sources'].items():
        if not re.fullmatch('[a-f0-9]{64}', source_key):
            raise MigrationError('Invalid source reference in private manifest; verification stopped')
        folder = output / source_key
        for chunk in entry['chunks']:
            sealed = (folder / chunk['file']).read_bytes()
            if hashlib.sha256(cipher.decrypt(sealed)).hexdigest() != chunk['sha256']:
                raise MigrationError('Encrypted transcript hash mismatch; verification stopped for recovery')
            report['verified_transcript_chunks'] += 1
        entries.append((folder / 'original.jsonl.gpg', entry['archive_sha256'], entry['source_sha256'], entry['source_bytes']))
    for archive, encrypted_hash, original_hash, original_size in entries:
        if file_hash(archive) != encrypted_hash:
            raise MigrationError('Encrypted archive hash mismatch; verification stopped for recovery')
        process = gpg('decrypt', key, archive=archive, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
        digest, size = hashlib.sha256(), 0
        try:
            while block := process.stdout.read(CHUNK_BYTES):
                digest.update(block)
                size += len(block)
            if process.wait(timeout=120) or digest.hexdigest() != original_hash:
                raise MigrationError('GPG decryption/authentication or original-byte hash verification failed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        if original_size is None:
            report['destination_backup_verified'] = True
        else:
            if size != original_size:
                raise MigrationError('Decrypted original byte count differs from the captured source')
            report['verified_sources'] += 1
            report['verified_source_bytes'] += size
    return report


def run(args):
    if getattr(args, 'verify', False):
        return verify_archives(args.archive_dir.absolute(), args.key_file.absolute())
    mapping_path, destination, key, output = (path.absolute() for path in
                                             (args.mapping, args.database, args.key_file, args.archive_dir))
    if mapping_path.stat().st_mode & 0o077 or key.stat().st_mode & 0o077:
        raise MigrationError('Mapping and master key must be private files (chmod 600 or 400)')
    mapping = json.loads(mapping_path.read_text())
    sources = list(source_files(mapping))
    report = {'source_files': len(sources), 'source_bytes': sum(s['path'].stat().st_size for s in sources),
              'source_agents': len({s['source_id'] for s in sources}), 'formats': {}}
    for source in sources:
        report['formats'][source['kind']] = report['formats'].get(source['kind'], 0) + 1
    if args.dry_run:
        return report
    if not mapping.get('human_id') or not mapping.get('secret_references'):
        raise MigrationError('A human identity and explicit private secret references are required before import')
    with database(destination) as conn:
        if 'imported' not in {row['name'] for row in conn.execute('PRAGMA table_info(conversations)')}:
            raise MigrationError('Run the application database migrations before importing history')
        for source in sources:
            if not source['target'] or not conn.execute('SELECT 1 FROM agents WHERE id=? AND enabled=1',
                                                       (source['target'],)).fetchone():
                raise MigrationError('Every history source must map to an existing enabled CloudStack agent')
    cipher, secrets = Fernet(key.read_bytes().strip()), references(mapping['secret_references'])
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.is_symlink() or output.stat().st_mode & 0o077:
        raise MigrationError('The encrypted archive directory must be private and must not be a symlink')
    manifest_path = output / 'manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {'version': 1, 'sources': {}}
    if 'destination_backup' not in manifest:
        manifest['destination_backup'] = backup_destination(destination, output, key)
        private_json(manifest_path, manifest)
    elif file_hash(output / 'destination-before.sqlite.gpg') != manifest['destination_backup']['archive_sha256']:
        raise MigrationError('The original application database backup changed; import stopped for recovery')
    report.update(imported_sources=0, conversations=0, malformed_records=0)
    for source in sources:
        folder = output / source['key']
        entry = manifest['sources'].get(source['key'])
        if entry and entry['target'] != source['target']:
            raise MigrationError('A source mapping changed after capture; restore the original mapping before retrying')
        if not entry:
            entry = snapshot(source, folder, key, cipher, secrets)
            manifest['sources'][source['key']] = entry
            private_json(manifest_path, manifest)
        if file_hash(folder / 'original.jsonl.gpg') != entry['archive_sha256']:
            raise MigrationError('An encrypted source archive changed; import stopped for recovery')
        import_source(entry, source, folder, destination, mapping['human_id'], cipher)
        entry['phase'] = 'imported'
        private_json(manifest_path, manifest)
        report['imported_sources'] += 1
        report['conversations'] += len(entry['chunks'])
        report['malformed_records'] += entry['malformed_records']
        if args.progress:
            print(json.dumps({'source_sha256': source['key'], 'phase': 'imported', 'conversations': len(entry['chunks'])}),
                  flush=True)
    report['manifest_sha256'] = file_hash(manifest_path)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--run', action='store_true')
    mode.add_argument('--verify', action='store_true', help='Stream-decrypt every archive and compare original-byte hashes')
    parser.add_argument('--mapping', type=Path, required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--key-file', type=Path, required=True)
    parser.add_argument('--archive-dir', type=Path, required=True)
    parser.add_argument('--progress', action='store_true', help='Print source hashes and completed counts only')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        print(json.dumps(run(args), sort_keys=True))
    except MigrationError as exc:
        print(f'History migration stopped safely: {exc} Completed checkpoints and originals are retained.', file=sys.stderr)
        sys.exit(1)
    except (ValueError, TypeError, KeyError, InvalidToken, OSError, sqlite3.Error, subprocess.SubprocessError):
        print('History migration stopped safely; originals and completed checkpoints are retained. '
              'Check private mapping, schema, references, archive integrity, permissions and free space before retrying.',
              file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
