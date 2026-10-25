#!/usr/bin/env python3
"""Explicit optional installation of the scoped GPU controller, never an NVIDIA driver installer."""
import argparse
import grp
import json
import os
from pathlib import Path
import subprocess
import shutil
import asyncio
import socket

from native_setup import ROOT, STATE, save, run


def install(parent, host_id):
    if os.geteuid() != 0:
        raise PermissionError('Run as platform administrator/root')
    from dirigentenstab.gpu_control import NativeHost
    NativeHost(parent).profiles()
    missing = [name for name in ('mdevctl', 'xmlstarlet') if not shutil.which(name)]
    if missing:
        run('apt-get', 'install', '-y', '--no-install-recommends', *missing)
    try:
        backend_group = grp.getgrgid(10001).gr_name
    except KeyError:
        run('groupadd', '--system', '--gid', '10001', 'dirigentenstab-gpu')
        backend_group = grp.getgrgid(10001).gr_name
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    save(STATE / 'gpu-controller.json', json.dumps({'parent': parent, 'host_id': host_id}), 0o600)
    save('/etc/systemd/system/dirigentenstab-gpu.socket', f'''[Unit]
Description=Private Dirigentenstab GPU backend socket

[Socket]
ListenStream=/run/dirigentenstab-gpu/control.sock
SocketUser=root
SocketGroup={backend_group}
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=true

[Install]
WantedBy=sockets.target
''')
    save('/etc/systemd/system/dirigentenstab-gpu.service', f'''[Unit]
Description=Scoped Dirigentenstab GPU policy and lifecycle controller
Requires=dirigentenstab-gpu.socket
After=cloudstack-management.service cloudstack-agent.service

[Service]
ExecStart={ROOT}/.venv/bin/python {ROOT}/scripts/gpu_helper.py
WorkingDirectory={ROOT}
User=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/etc/mdevctl.d
Restart=on-failure
''')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'dirigentenstab-gpu.socket')
    run('systemctl', 'is-active', 'dirigentenstab-gpu.socket')
    # Socket activation keeps the inode stable across helper upgrades and container binds.
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'dirigentenstab-gpu.service'], check=False)
    if active.returncode == 0:
        run('systemctl', 'restart', 'dirigentenstab-gpu.service')
    env = ROOT / '.env'
    from dotenv import dotenv_values
    files = (dotenv_values(env).get('COMPOSE_FILE') or 'compose.yaml').split(':')
    if 'compose.gpu.yaml' not in files:
        files.append('compose.gpu.yaml')
    lines = [line for line in env.read_text().splitlines()
             if not line.startswith(('COMPOSE_FILE=', 'ENABLE_GPU_CONTROL='))]
    save(env, '\n'.join([*lines, 'ENABLE_GPU_CONTROL=true', 'COMPOSE_FILE=' + ':'.join(files)]) + '\n', 0o600)
    print('Private GPU socket installed. Recreate only the app container to enable its scoped socket mount.')


def automatic():
    from dotenv import dotenv_values
    values = dotenv_values(ROOT / '.env')
    if str(values.get('ENABLE_GPU_CONTROL', '')).lower() not in {'true', '1', 'yes'}:
        print('Optional GPU control disabled. Set ENABLE_GPU_CONTROL=true before installation to enable it.')
        return
    parents = [p.parent.name for p in Path('/sys/bus/pci/devices').glob('*/mdev_supported_types') if any(p.iterdir())]
    parent = values.get('GPU_PARENT') or (parents[0] if len(parents) == 1 else None)
    if not parent or parent not in parents:
        raise RuntimeError('GPU control needs an installed licensed vGPU Manager and one explicit local GPU_PARENT when ambiguous')
    from admin import service
    async def detect():
        app = service()
        credentials = json.loads((STATE / 'cloudstack-admin.json').read_text())
        cloud = app.client({k: credentials[k] for k in ('apikey', 'secretkey')})
        hosts = (await cloud.raw('listHosts', {'type': 'Routing'})).get('host', [])
        matches = [h for h in hosts if h.get('name') in {socket.gethostname(), socket.getfqdn()} and h.get('state') == 'Up']
        if len(matches) != 1:
            raise RuntimeError('Cannot uniquely verify this local CloudStack KVM host; specify --parent and --host-id explicitly')
        return matches[0]['id']
    install(parent, asyncio.run(detect()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--auto', action='store_true')
    parser.add_argument('--parent')
    parser.add_argument('--host-id')
    options = parser.parse_args()
    if options.auto:
        automatic()
    elif options.parent and options.host_id:
        install(options.parent, options.host_id)
    else:
        parser.error('Choose --auto or provide --parent and --host-id')
