#!/usr/bin/env python3
"""Stage one operator-approved binary in the existing private app volume, never a public endpoint."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from dirigentenstab.guest import MAX_ASSET


def stage(directory, source, asset_id, name, agent_id, sha256):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', asset_id) or not re.fullmatch('[0-9a-f]{64}', sha256):
        raise ValueError('Use a simple asset ID and the expected SHA-256')
    if not name or len(name) > 128 or any(c in name for c in '\r\n\0'):
        raise ValueError('Invalid asset display name')
    directory = Path(directory)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError('Asset directory must not be a symlink')
    directory.chmod(0o755)
    manifest = directory / 'manifest.json'
    entries = json.loads(manifest.read_text()) if manifest.exists() else {}
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as original:
        info = os.fstat(original.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ASSET:
            raise ValueError('Approved asset must be a regular file up to 512 MiB')
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as target:
            temporary = Path(target.name)
            try:
                total = 0
                while data := original.read(1024 * 1024):
                    total += len(data)
                    if total > MAX_ASSET:
                        raise ValueError('Asset exceeds the 512 MiB limit')
                    target.write(data)
                target.flush()
                os.fsync(target.fileno())
                with temporary.open('rb') as copied:
                    actual = hashlib.file_digest(copied, 'sha256').hexdigest()
                if actual != sha256 or temporary.stat().st_size != info.st_size:
                    raise ValueError('Asset does not match the operator-approved digest')
                temporary.chmod(0o444)
                temporary.replace(directory / (sha256 + '.bin'))
            finally:
                temporary.unlink(missing_ok=True)
    entries[asset_id] = {'name': name, 'sha256': sha256, 'bytes': info.st_size, 'agent_ids': [agent_id]}
    pending = directory / '.manifest.tmp'
    pending.write_text(json.dumps(entries, indent=2))
    pending.chmod(0o444)
    pending.replace(manifest)
    directory.chmod(0o555)
    return entries[asset_id]


if __name__ == '__main__':
    from admin import service
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('source', 'id', 'name', 'agent-id', 'sha256'):
        parser.add_argument('--' + field, required=True)
    options = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Platform administrator/root is required; binary files never enter agent workspace or GitHub')
    app = service()
    if not app.store.one('SELECT id FROM agents WHERE id=? AND enabled=1', (options.agent_id,)):
        parser.error('Agent is unavailable')
    stage(app.settings.guest_assets, options.source, options.id, options.name, options.agent_id, options.sha256)
    app.store.audit('local-platform-admin', 'stage-guest-asset', options.id)
    print('Approved asset staged privately; use transfer_vm_file with source asset:' + options.id)
