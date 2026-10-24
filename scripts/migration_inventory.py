#!/usr/bin/env python3
"""Read-only Agentor/Incus metadata inventory; never reads credentials or conversation rows."""
import collections
import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess


OUTPUT = Path('/var/lib/dirigentenstab/setup/migration-inventory.json')
DISK_FIELDS = ('type', 'pool', 'source', 'path', 'size', 'readonly', 'required')


def query(*args):
    return json.loads(subprocess.check_output(args, text=True, timeout=60))


def device_metadata(devices):
    return {name: {key: device[key] for key in DISK_FIELDS if key in device}
            for name, device in devices.items() if device.get('type') == 'disk'}


def database_metadata(path):
    # mode=ro sees the active WAL; immutable=1 would incorrectly omit committed WAL records.
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5) as database:
        database.execute('PRAGMA query_only=ON')
        database.execute('BEGIN')
        result = {}
        for name, in database.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            quoted = '"' + name.replace('"', '""') + '"'
            columns = [{'name': row[1], 'type': row[2], 'not_null': bool(row[3]), 'primary_key': bool(row[5])}
                       for row in database.execute(f'PRAGMA table_info({quoted})')]
            try:
                count = database.execute(f'SELECT COUNT(*) FROM {quoted}').fetchone()[0]
            except sqlite3.DatabaseError:
                count = None
            result[name] = {'columns': columns, 'rows': count}
        return result


def inventory():
    docker = query('docker', 'inspect', 'agentor-orchestrator')[0]
    mounts = [{key: mount.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'RW')}
              for mount in docker.get('Mounts', [])]
    instances = query('incus', 'list', '--all-projects', '--format', 'json')
    pools, volumes, disks = [], [], []
    for pool in query('incus', 'storage', 'list', '--format', 'json'):
        source = pool.get('config', {}).get('source')
        pools.append({'name': pool['name'], 'driver': pool['driver'], 'source': source,
                      'resolved_source': os.path.realpath(source) if source else None})
        for volume in query('incus', 'storage', 'volume', 'list', pool['name'], '--all-projects', '--format', 'json'):
            volumes.append({key: volume.get(key) for key in ('name', 'type', 'content_type', 'project', 'used_by')}
                           | {'pool': pool['name'], 'size': volume.get('config', {}).get('size')})
        if pool['driver'] == 'dir' and source:
            directory = Path(source) / 'virtual-machines'
            if directory.is_dir():
                for entry in directory.iterdir():
                    image = entry / 'root.img'
                    if image.is_file():
                        stat = image.stat()
                        disks.append({'pool': pool['name'], 'instance_directory': entry.name,
                                      'path': str(image), 'file_bytes': stat.st_size,
                                      'allocated_bytes': stat.st_blocks * 512})
    databases = {}
    for mount in mounts:
        if mount['Type'] == 'volume' and mount['Destination'] == '/data':
            # Only top-level SQLite files; do not traverse users, credentials, backups or workspaces.
            for path in Path(mount['Source']).iterdir():
                if path.is_file() and not path.is_symlink() and path.suffix in {'.db', '.sqlite', '.sqlite3'}:
                    databases[str(path)] = database_metadata(path)
    return {'captured_at': datetime.datetime.now(datetime.UTC).isoformat(),
            'scope': 'metadata, schema and row counts only; no guest commands, credential or conversation values',
            'container_mounts': mounts, 'storage_pools': pools, 'storage_volumes': volumes,
            'root_disk_files': disks, 'databases': databases,
            'instances': [{key: instance.get(key) for key in ('name', 'project', 'status', 'type', 'architecture')}
                          | {'disk_devices': device_metadata(instance.get('expanded_devices', {}))}
                          for instance in instances]}


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo; the inventory is written only to root-private setup state.')
    os.umask(0o077)
    result = inventory()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = OUTPUT.with_suffix('.tmp')
    with temporary.open('w') as file:
        json.dump(result, file, indent=2)
    temporary.chmod(0o600)
    temporary.replace(OUTPUT)
    print('Inventory saved to root-private setup state.')
    print('VM states:', dict(collections.Counter(row['status'] for row in result['instances'])))
    print('Storage volume types:', dict(collections.Counter(row['type'] for row in result['storage_volumes'])))


if __name__ == '__main__':
    main()
