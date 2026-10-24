#!/usr/bin/env python3
"""Conservative native Ubuntu installer. Does not change the host uplink or SSH."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
STATE = Path('/var/lib/dirigentenstab/setup')
VERSION = '4.23.0.0'
BRIDGE = 'dscloud0'
NETWORK = ipaddress.ip_network('10.253.80.0/24')
ADDRESS = '10.253.80.1'
CMK_SHA256 = '9f4f92ebc3b1e6139d81a2b3f9e7f7c663d1806234ae0ab27cf77753c553d76b'


def run(*args, input=None, check=True, quiet=False):
    result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=1800,
                            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive',
                                 'NEEDRESTART_MODE': 'l'})
    if STATE.exists():
        with (STATE / 'commands.log').open('a') as log:
            log.write(result.stdout)
    if result.returncode and check:
        raise RuntimeError(f'{args[0]} failed (exit {result.returncode}); see root-private {STATE}/commands.log')
    if not quiet:
        return result.stdout
    return ''


def save(path, text, mode=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == text:
        return
    backup = STATE / 'originals' / str(path).lstrip('/')
    if path.exists() and not backup.exists():
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
    temp = path.with_name(path.name + '.dirigentenstab-tmp')
    temp.write_text(text)
    previous = path.stat() if path.exists() else None
    temp.chmod(mode if mode is not None else (previous.st_mode & 0o777 if previous else 0o644))
    if previous:
        os.chown(temp, previous.st_uid, previous.st_gid)
    temp.replace(path)
    with (STATE / 'changed-files').open('a') as log:
        log.write(str(path) + '\n')


def download(url, destination, fingerprint=None, sha256=None):
    destination = Path(destination)
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read()
    if sha256 and hashlib.sha256(data).hexdigest() != sha256:
        raise RuntimeError(f'Checksum mismatch downloading {url}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    destination.chmod(0o644)
    if fingerprint:
        info = run('gpg', '--show-keys', '--with-colons', str(destination))
        if f'fpr:::::::::{fingerprint}:' not in info:
            destination.unlink()
            raise RuntimeError(f'Signing-key fingerprint mismatch for {url}')


def properties(path, values):
    path = Path(path)
    old = path.read_text() if path.exists() else ''
    for key, value in values.items():
        line = f'{key}={value}'
        pattern = rf'(?m)^\s*#?\s*{re.escape(key)}\s*=.*$'
        old = re.sub(pattern, line, old) if re.search(pattern, old) else old + '\n' + line + '\n'
    save(path, old)


def preflight(existing=False):
    osinfo = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if osinfo.get('ID', '').strip('"') != 'ubuntu' or osinfo.get('VERSION_ID', '').strip('"') != '24.04':
        raise RuntimeError('Native installation supports Ubuntu 24.04 LTS. Use --existing for another CloudStack host.')
    if not existing and (not Path('/dev/kvm').exists() or not re.search(r'\b(vmx|svm)\b', Path('/proc/cpuinfo').read_text())):
        raise RuntimeError('Hardware KVM is unavailable; enable CPU virtualization in firmware.')
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    available = int(memory['MemAvailable'].split()[0]) // 1024
    disk = shutil.disk_usage('/var/lib').free // 2**30
    if not existing and (available < 8192 or disk < 50):
        raise RuntimeError(f'Insufficient resources: {available} MiB available RAM, {disk} GiB free disk. Need 8 GiB and 50 GiB.')
    routes = json.loads(run('ip', '-json', 'route'))
    for route in routes:
        if route.get('dst') == 'default' or route.get('dev') == BRIDGE:
            continue
        subnet = ipaddress.ip_network(route['dst'], strict=False)
        if subnet.overlaps(NETWORK):
            raise RuntimeError(f'Private network {NETWORK} conflicts with route {route["dst"]}. Administrator must choose a separate host/network.')
    if not existing and shutil.which('virsh'):
        domains = run('virsh', '-c', 'qemu:///system', 'list', '--all', '--name', check=False).strip()
        if domains and not (STATE / 'packages.done').exists():
            raise RuntimeError('Existing libvirt VMs detected; use an empty KVM host or --existing. No VM is adopted or deleted.')
    print(f'Ubuntu 24.04; KVM={Path("/dev/kvm").exists()}; available RAM={available} MiB; free disk={disk} GiB')
    print('Existing virtualization:', run('pgrep', '-a', 'qemu-system', check=False).split(' -')[0] or 'none')
    print('Existing ports:', run('ss', '-lnt').strip())
    print('PCI/NVIDIA inventory:', run('lspci', '-nn', check=False).strip())
    print('Native plan: dedicated dscloud0 10.253.80.1/24, local storage, private native CloudStack services.')
    print('Host uplink, SSH, Incus, NVIDIA/vGPU, Cloudflare Tunnel and Tailscale are preserved.')


def step(name, action):
    marker = STATE / f'{name}.done'
    if marker.exists():
        print(f'{name}: already completed', flush=True)
        return
    print(f'{name}: starting', flush=True)
    action()
    marker.touch(mode=0o600)
    print(f'{name}: complete', flush=True)


def repositories():
    download('https://download.cloudstack.org/release.asc', '/usr/share/keyrings/dirigentenstab-cloudstack.asc',
             fingerprint='549A7B269985045A6CA8F3343D62B837F100E758')
    download('https://repo.mysql.com/RPM-GPG-KEY-mysql-2025', '/usr/share/keyrings/dirigentenstab-mysql.asc',
             fingerprint='BCA43417C3B485DD128EC6D4B7B3B788A8D3785C')
    save('/etc/apt/sources.list.d/dirigentenstab-cloudstack.list',
         'deb [signed-by=/usr/share/keyrings/dirigentenstab-cloudstack.asc] https://download.cloudstack.org/ubuntu noble 4.23\n')
    save('/etc/apt/sources.list.d/dirigentenstab-mysql.list',
         'deb [signed-by=/usr/share/keyrings/dirigentenstab-mysql.asc] https://repo.mysql.com/apt/ubuntu noble mysql-8.4-lts\n')
    save('/etc/apt/preferences.d/dirigentenstab-cloudstack',
         'Package: cloudstack-*\nPin: version 4.23.0.0\nPin-Priority: 1001\n')
    run('apt-get', 'update')
    candidate = run('apt-cache', 'policy', 'cloudstack-management')
    if f'Candidate: {VERSION}' not in candidate:
        raise RuntimeError('Pinned CloudStack release is unavailable in the signed native repository.')


def packages():
    for service in ['cloudstack-management', 'cloudstack-agent']:
        override = Path(f'/etc/systemd/system/{service}.service')
        if override.exists() and not (override.is_symlink() and os.readlink(override) == '/dev/null'):
            raise RuntimeError(f'Existing override for {service}; inspect manually before native installation.')
        run('systemctl', 'mask', service)
    run('apt-get', 'install', '-y', '--no-install-recommends',
        f'cloudstack-management={VERSION}', f'cloudstack-agent={VERSION}',
        f'cloudstack-common={VERSION}', 'mysql-community-server', 'nfs-kernel-server',
        'python3.12-venv', 'curl', 'ca-certificates', 'nftables', 'jq', 'bridge-utils')
    mysql = run('mysql', '--version')
    if '8.4.' not in mysql:
        raise RuntimeError('MySQL 8.4 is required by the pinned CloudStack compatibility matrix.')


def network():
    save('/etc/systemd/network/80-dirigentenstab.netdev', f'[NetDev]\nName={BRIDGE}\nKind=bridge\n')
    save('/etc/systemd/network/80-dirigentenstab.network',
         f'[Match]\nName={BRIDGE}\n\n[Network]\nAddress={ADDRESS}/24\nConfigureWithoutCarrier=yes\nLinkLocalAddressing=no\n')
    save('/etc/systemd/network/81-dirigentenstab-anchor.netdev', '[NetDev]\nName=dummyds0\nKind=dummy\n')
    save('/etc/systemd/network/81-dirigentenstab-anchor.network',
         f'[Match]\nName=dummyds0\n\n[Network]\nBridge={BRIDGE}\nLinkLocalAddressing=no\n')
    if not Path(f'/sys/class/net/{BRIDGE}').exists():
        run('ip', 'link', 'add', BRIDGE, 'type', 'bridge')
    if not Path('/sys/class/net/dummyds0').exists():
        run('ip', 'link', 'add', 'dummyds0', 'type', 'dummy')
    run('ip', 'link', 'set', 'dummyds0', 'master', BRIDGE)
    run('ip', 'link', 'set', 'dummyds0', 'up')
    run('ip', 'address', 'replace', f'{ADDRESS}/24', 'dev', BRIDGE)
    run('ip', 'link', 'set', BRIDGE, 'up')
    # Separate chain: never flush an existing firewall or alter its default policy.
    save('/etc/dirigentenstab-network.nft',
         'table ip dirigentenstab {\n'
         ' chain nat { type nat hook postrouting priority srcnat; policy accept;\n'
         f'  ip saddr {NETWORK} ip daddr != {NETWORK} masquerade\n }}\n'
         '}\n'
         'table inet dirigentenstab_private {\n'
         ' chain private_services { type filter hook input priority -10; policy accept;\n'
         f'  ip saddr 172.30.253.2 ip daddr {ADDRESS} tcp dport 8080 accept\n'
         f'  iifname != "lo" iifname != "{BRIDGE}" tcp dport {{ 111, 8080, 8250, 9090, 16509, 16514, 2049 }} drop\n'
         f'  iifname != "lo" iifname != "{BRIDGE}" udp dport {{ 111, 2049 }} drop\n'
         ' }\n}\n')
    save('/etc/systemd/system/dirigentenstab-network.service',
         '[Unit]\nDescription=Dirigentenstab isolated CloudStack network rules\nAfter=network-online.target\n'
         'Before=cloudstack-management.service cloudstack-agent.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
         'ExecStart=/usr/sbin/nft -f /etc/dirigentenstab-network.nft\n'
         'ExecStop=/usr/sbin/nft delete table ip dirigentenstab\n'
         'ExecStop=/usr/sbin/nft delete table inet dirigentenstab_private\n\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'dirigentenstab-network')


def database():
    save('/etc/mysql/mysql.conf.d/dirigentenstab.cnf',
         '[mysqld]\nbind-address=127.0.0.1\nmysqlx-bind-address=127.0.0.1\n'
         'server-id=1\ninnodb_rollback_on_timeout=1\ninnodb_lock_wait_timeout=600\n'
         'max_connections=350\nlog_bin=mysql-bin\nbinlog_format=ROW\n'
         'sql_mode=STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION\n')
    run('systemctl', 'restart', 'mysql')
    schema = run('mysql', '-NBe', "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='cloud'")
    if schema.strip():
        raise RuntimeError('Existing cloud database found without completion marker; inspect it before recovery. Never overwrite it.')
    secret_file = STATE / 'database-secrets.json'
    if not secret_file.exists():
        save(secret_file, json.dumps({name: secrets.token_hex(24) for name in ['password', 'management_key', 'database_key']}), 0o600)
    creds = json.loads(secret_file.read_text())
    run('cloudstack-setup-databases', f'cloud:{creds["password"]}@localhost', '--deploy-as=root:',
        '-i', ADDRESS, '-e', 'file', '-m', creds['management_key'], '-k', creds['database_key'])


def services():
    logging = Path('/etc/cloudstack/management/log4j-cloud.xml')
    save(logging, logging.read_text().replace('level="DEBUG"', 'level="INFO"'))
    logging = Path('/etc/cloudstack/agent/log4j-cloud.xml')
    save(logging, logging.read_text().replace('level="DEBUG"', 'level="INFO"'))
    properties('/etc/cloudstack/management/server.properties', {'bind.interface': ADDRESS, 'http.port': '8080'})
    properties('/etc/cloudstack/management/db.properties', {'cluster.node.IP': ADDRESS})
    for path in ['/var/lib/libvirt/images/dirigentenstab', '/var/lib/dirigentenstab/secondary']:
        Path(path).mkdir(parents=True, exist_ok=True)
    # Keep libvirt on its authenticated Unix socket: no unauthenticated TCP listener.
    properties('/etc/cloudstack/agent/agent.properties', {
        'host': ADDRESS, 'private.network.device': BRIDGE, 'public.network.device': BRIDGE,
        'guest.network.device': BRIDGE, 'hypervisor.uri': 'qemu:///system',
        'local.storage.path': '/var/lib/libvirt/images/dirigentenstab',
        'local.storage.uuid': str(__import__('uuid').uuid4()), 'image.server.listen.address': ADDRESS,
        'guest.cpu.mode': 'host-passthrough',
    })
    Path('/etc/cloudstack/agent/agent.properties').chmod(0o600)
    run('systemctl', 'unmask', 'cloudstack-management')
    run('systemctl', 'enable', '--now', 'cloudstack-management', 'libvirtd')
    for _ in range(120):
        try:
            with urllib.request.urlopen(f'http://{ADDRESS}:8080/client/', timeout=5) as result:
                if result.status == 200:
                    print('Private native CloudStack management UI is ready.')
                    break
        except (OSError, TimeoutError):
            time.sleep(3)
    else:
        raise RuntimeError('Management server did not become ready; inspect journalctl -u cloudstack-management.')
    download('https://github.com/apache/cloudstack-cloudmonkey/releases/download/6.6.0/cmk.linux.x86-64',
             '/usr/local/bin/cmk', sha256=CMK_SHA256)
    Path('/usr/local/bin/cmk').chmod(0o755)


def verify():
    for service in ['cloudstack-management', 'cloudstack-agent', 'mysql', 'libvirtd']:
        if run('systemctl', 'is-active', service, check=False).strip() != 'active':
            raise RuntimeError(f'{service} is not active; see docs/RECOVERY.md')
    run('virsh', '-c', 'qemu:///system', 'capabilities')
    print('Native services and real libvirt/KVM are running.')
    if (STATE / 'cloudstack-admin.json').exists():
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/zone_setup.py'), '--verify'], check=False)
        if result.returncode:
            raise RuntimeError('CloudStack API/zone verification failed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ['preflight', 'install', 'verify', 'existing']:
        modes.add_argument('--' + name, action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo. Preflight reads protected virtualization and network state.')
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    if args.preflight:
        preflight()
    elif args.verify:
        verify()
    elif args.existing:
        print('Existing mode: CloudStack services and networking are not modified.')
        print('Configure CLOUDSTACK_URL and PUBLIC_ORIGIN in .env, then run the application bootstrap command in README.md.')
    else:
        preflight()
        for name, action in [('repositories', repositories), ('packages', packages), ('network', network),
                             ('database', database), ('services', services)]:
            step(name, action)
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/zone_setup.py')], check=False)
        if result.returncode:
            raise RuntimeError('Zone setup incomplete; safe to retry after resolving the reported prerequisite.')
        verify()


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
