#!/usr/bin/env python3
"""CloudStack Orchestrator extension: Firecracker microVMs on this host (stdlib only).

CloudStack runs `firecracker.py <action> <payload.json> <timeout>` as user `cloud`. That user cannot create taps or
systemd units, so as `cloud` this file only forwards the payload to the root-owned socket
/run/dirigentenstab-firecracker.sock (systemd socket activation, one short-lived root process per call), which runs
this same file with `--worker`. As root (dev/testing) the same invocation works directly.
"""
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys

SOCK = '/run/dirigentenstab-firecracker.sock'
HOME = os.environ.get('FC_HOME', '/opt/dirigentenstab/firecracker')
STATE = os.environ.get('FC_STATE', '/var/lib/dirigentenstab/firecracker')
FC = os.environ.get('FC_BIN', f'{HOME}/current/firecracker')
KERNEL = os.environ.get('FC_KERNEL', f'{HOME}/current/vmlinux')
ROOTFS = os.environ.get('FC_ROOTFS', f'{HOME}/rootfs/current.ext4')
BRIDGE = os.environ.get('FC_BRIDGE', 'dscloud0')
DISK_GB = int(os.environ.get('FC_DISK_GB', '8'))
BOOT_ARGS = ('console=ttyS0 reboot=k panic=1 pci=off 8250.nr_uarts=1 random.trust_cpu=on i8042.noaux i8042.nomux '
             'i8042.nopnp i8042.dumbkbd root=/dev/vda rw init=/sbin/init net.ifnames=0 biosdevname=0 loglevel=3')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
MAC = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


def run(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def vm_of(payload):
    details = payload.get('cloudstack.vm.details') or {}
    uuid = payload.get('virtualmachineid') or details.get('uuid') or ''
    if not UUID.match(uuid):
        raise ValueError(f'bad virtual machine id {uuid!r}')
    return uuid, details


def paths(uuid):
    d = f'{STATE}/{uuid}'
    return {'dir': d, 'rootfs': f'{d}/rootfs.ext4', 'seed': f'{d}/seed.img', 'cfg': f'{d}/vm.json',
            'meta': f'{d}/cs.json', 'log': f'{d}/console.log', 'api': f'{d}/api.sock', 'unit': f'fc-{uuid}'}


def taps(uuid, count):
    return [f'fc{uuid[:8]}n{i}' for i in range(count)]


def running(uuid):
    return run('systemctl', 'is-active', '--quiet', paths(uuid)['unit'] + '.service', check=False).returncode == 0


def userdata(details, payload):
    """cloud-init user-data and public keys from whatever the payload carries (CloudStack vmData triples)."""
    data, keys = payload.get('userdata') or details.get('userdata'), ''
    for item in details.get('vmData') or []:
        if len(item) == 3 and item[1] == 'user_data':
            data = item[2]
        if len(item) == 3 and item[1] == 'public_keys':
            keys = item[2]
    if data:
        try:
            data = base64.b64decode(data, validate=True).decode()
        except ValueError:
            pass
    return data or '#cloud-config\n{}\n', keys


def build_seed(p, uuid, name, macs, ud, keys):
    meta = f'instance-id: {uuid}\nlocal-hostname: {name}\n'
    if keys:
        meta += 'public-keys:\n' + ''.join(f'  - {line}\n' for line in keys.splitlines() if line.strip())
    net = 'version: 2\nethernets:\n' + ''.join(
        f'  nic{i}:\n    match: {{macaddress: "{mac}"}}\n    set-name: eth{i}\n    dhcp4: true\n    dhcp-identifier: mac\n'
        for i, mac in enumerate(macs))
    seed = p['dir'] + '/seed'
    os.makedirs(seed, exist_ok=True)
    for file, text in (('user-data', ud), ('meta-data', meta), ('network-config', net)):
        with open(f'{seed}/{file}', 'w') as f:
            f.write(text)
    # the Firecracker guest kernel has ext4 but no iso9660/vfat: NoCloud accepts an ext4 volume labelled cidata
    run('mke2fs', '-q', '-F', '-t', 'ext4', '-O', '^has_journal', '-L', 'cidata', '-d', seed, p['seed'], '2M')
    shutil.rmtree(seed)


def create(payload):
    uuid, details = vm_of(payload)
    p = paths(uuid)
    name = details.get('name') or payload.get('virtualmachinename') or uuid
    macs = [n['mac'].lower() for n in details.get('nics') or [] if MAC.match(n.get('mac', '').lower())]
    if not macs:
        raise ValueError('payload has no NIC MAC')
    os.makedirs(p['dir'], exist_ok=True)
    if not os.path.exists(p['rootfs']):
        tmp = p['rootfs'] + '.new'
        run('cp', '--sparse=always', '--reflink=auto', ROOTFS, tmp)
        size = max(DISK_GB, 1) * 1024 ** 3
        if os.path.getsize(tmp) < size:
            os.truncate(tmp, size)
            run('e2fsck', '-fy', tmp, check=False)
            run('resize2fs', tmp)
        os.rename(tmp, p['rootfs'])
    ud, keys = userdata(details, payload)
    build_seed(p, uuid, name, macs, ud, keys)
    mem = max(128, int(details.get('minRam') or details.get('maxRam') or 512 * 1024 ** 2) // 1024 ** 2)
    cfg = {'boot-source': {'kernel_image_path': KERNEL, 'boot_args': BOOT_ARGS},
           'drives': [{'drive_id': 'rootfs', 'path_on_host': p['rootfs'], 'is_root_device': True, 'is_read_only': False},
                      {'drive_id': 'cidata', 'path_on_host': p['seed'], 'is_root_device': False, 'is_read_only': True}],
           'network-interfaces': [{'iface_id': f'eth{i}', 'guest_mac': mac, 'host_dev_name': tap}
                                  for i, (mac, tap) in enumerate(zip(macs, taps(uuid, len(macs)), strict=True))],
           'machine-config': {'vcpu_count': int(details.get('cpus') or 1), 'mem_size_mib': mem}}
    with open(p['cfg'], 'w') as f:
        json.dump(cfg, f)
    with open(p['meta'], 'w') as f:
        json.dump({'name': name, 'macs': macs}, f)
    start(payload)


def start(payload):
    uuid, _ = vm_of(payload)
    p = paths(uuid)
    if running(uuid):
        return
    cfg = json.load(open(p['cfg']))
    for nic in cfg['network-interfaces']:
        tap = nic['host_dev_name']
        run('ip', 'link', 'del', tap, check=False)
        run('ip', 'tuntap', 'add', tap, 'mode', 'tap')
        run('ip', 'link', 'set', tap, 'master', BRIDGE, 'up')
    open(p['log'], 'a').close()
    if os.path.exists(p['api']):
        os.unlink(p['api'])
    run('systemd-run', '--unit', p['unit'], '--collect', '-p', f'StandardOutput=append:{p["log"]}',
        '-p', f'StandardError=append:{p["log"]}', '-p', 'KillMode=control-group',
        FC, '--api-sock', p['api'], '--config-file', p['cfg'])


def stop(payload):
    """Power off. Firecracker offers no ACPI shutdown on x86 (SendCtrlAltDel is ignored by this guest), so this is a hard
    stop: ext4 journals make it as safe as pulling the plug."""
    uuid, _ = vm_of(payload)
    run('systemctl', 'stop', paths(uuid)['unit'] + '.service', check=False)
    for tap in taps(uuid, 8):
        run('ip', 'link', 'del', tap, check=False)


def delete(payload):
    uuid, _ = vm_of(payload)
    stop(payload)
    shutil.rmtree(paths(uuid)['dir'], ignore_errors=True)


def status(payload):
    uuid, _ = vm_of(payload)
    return {'power_state': 'poweron' if running(uuid) else 'poweroff'}


def statuses(_payload):
    states = {}
    for uuid in os.listdir(STATE) if os.path.isdir(STATE) else []:
        if UUID.match(uuid) and os.path.exists(paths(uuid)['meta']):
            name = json.load(open(paths(uuid)['meta']))['name']
            states[name] = 'poweron' if running(uuid) else 'poweroff'
    return {'power_state': states}


ACTIONS = {'prepare': lambda p: {'details': {}}, 'create': create, 'deploy': create, 'start': start, 'stop': stop,
           'reboot': lambda p: (stop(p), start(p)), 'delete': delete, 'status': status, 'statuses': statuses}


def worker(action, payload):
    if action not in ACTIONS:
        return {'status': 'error', 'error': f'unsupported action {action}'}
    try:
        return {'status': 'success', **(ACTIONS[action](payload) or {})}
    except Exception as exc:  # report to CloudStack as JSON, never a traceback
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else exc
        return {'status': 'error', 'error': f'{action}: {detail}'}


def main():
    if sys.argv[1:] == ['--worker']:
        request = json.load(sys.stdin)
        print(json.dumps(worker(request['action'], request['payload'])))
        return 0
    action, payload = sys.argv[1], json.load(open(sys.argv[2]))
    if os.geteuid() == 0:
        result = worker(action, payload)
    else:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(float(sys.argv[3]) if len(sys.argv) > 3 else 300)
            s.connect(SOCK)
            s.sendall(json.dumps({'action': action, 'payload': payload}).encode())
            s.shutdown(socket.SHUT_WR)
            result = json.loads(s.makefile().read())
    print(json.dumps(result))
    return 0 if result.get('status') == 'success' else 1


if __name__ == '__main__':
    sys.exit(main())
