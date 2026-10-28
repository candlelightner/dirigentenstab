#!/usr/bin/env python3
"""Conservative native Ubuntu installer. Does not change the host uplink or SSH."""
import argparse
import hashlib
import ipaddress
import json
import os
import pwd
import platform
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request

from network_config import load_network

ROOT = Path(__file__).resolve().parent.parent
NETWORK_CONFIG = load_network(ROOT / '.env')
STATE = Path('/var/lib/dirigentenstab/setup')
VERSION = '4.23.0.0'
BRIDGE = NETWORK_CONFIG['CLOUDSTACK_BRIDGE']
NETWORK = ipaddress.ip_network(NETWORK_CONFIG['CLOUDSTACK_NETWORK'])
ADDRESS = NETWORK_CONFIG['CLOUDSTACK_GATEWAY']
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


def check_routes(routes):
    for route in routes:
        if route.get('dst') == 'default' or route.get('dev') == BRIDGE:
            continue
        subnet = ipaddress.ip_network(route['dst'], strict=False)
        if subnet.overlaps(NETWORK):
            raise RuntimeError(f'Private network {NETWORK} conflicts with route {route["dst"]}. Use a separately prepared CloudStack network/host.')
        if route.get('dev') != 'cloud0' and subnet.overlaps(ipaddress.ip_network('169.254.0.0/16')):
            raise RuntimeError('Existing link-local route conflicts with the CloudStack control network; prepare a separate KVM host.')


def preflight(existing=False):
    osinfo = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if osinfo.get('ID', '').strip('"') != 'ubuntu' or osinfo.get('VERSION_ID', '').strip('"') != '24.04':
        raise RuntimeError('Native installation supports Ubuntu 24.04 LTS. Use --existing for another CloudStack host.')
    if platform.machine() not in {'x86_64', 'amd64'}:
        raise RuntimeError('This native installer pins the x86-64 CloudMonkey/system templates. Use --existing with a separately prepared host.')
    if not existing and (not Path('/dev/kvm').exists() or not re.search(r'\b(vmx|svm)\b', Path('/proc/cpuinfo').read_text())):
        raise RuntimeError('Hardware KVM is unavailable; enable CPU virtualization in firmware.')
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    available = int(memory['MemAvailable'].split()[0]) // 1024
    disk = shutil.disk_usage('/var/lib').free // 2**30
    if not existing and (available < 8192 or disk < 50):
        raise RuntimeError(f'Insufficient resources: {available} MiB available RAM, {disk} GiB free disk. Need 8 GiB and 50 GiB.')
    routes = json.loads(run('ip', '-json', 'route'))
    check_routes(routes)
    if not existing and shutil.which('virsh'):
        domains = run('virsh', '-c', 'qemu:///system', 'list', '--all', '--name', check=False).strip()
        if domains and not (STATE / 'packages.done').exists():
            raise RuntimeError('Existing libvirt VMs detected; use an empty KVM host or --existing. No VM is adopted or deleted.')
    mysql_data = Path('/var/lib/mysql')
    if not existing and mysql_data.is_dir() and any(mysql_data.iterdir()) and not (STATE / 'packages.started').exists() and not (STATE / 'packages.done').exists():
        raise RuntimeError('Existing MySQL data detected. Use --existing or a separately prepared CloudStack host; no database is adopted or upgraded.')
    if not existing and not (STATE / 'packages.started').exists() and not (STATE / 'packages.done').exists():
        for service in ['nfs-server', 'rpcbind']:
            if run('systemctl', 'is-active', service, check=False).strip() == 'active':
                raise RuntimeError(f'Existing {service} service detected; use --existing or a separate CloudStack host to preserve it.')
    print(f'Ubuntu 24.04; KVM={Path("/dev/kvm").exists()}; available RAM={available} MiB; free disk={disk} GiB')
    print('Existing virtualization:', run('pgrep', '-a', 'qemu-system', check=False).split(' -')[0] or 'none')
    print('Existing ports:', run('ss', '-lnt').strip())
    print('PCI/NVIDIA inventory:', run('lspci', '-nn', check=False).strip())
    print(f'Native plan: dedicated {BRIDGE} {ADDRESS}/{NETWORK.prefixlen}, local storage, private native CloudStack services.')
    print('Host uplink, SSH, Incus, NVIDIA/vGPU, Cloudflare Tunnel and Tailscale are preserved.')


def step(name, action):
    marker = STATE / f'{name}.done'
    if marker.exists():
        print(f'{name}: already completed', flush=True)
        return
    print(f'{name}: starting', flush=True)
    (STATE / f'{name}.started').touch(mode=0o600)
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
    for service in ['cloudstack-management', 'cloudstack-agent', 'mysql', 'nfs-server', 'rpcbind', 'rpcbind.socket']:
        unit = service if service.endswith('.socket') else service + '.service'
        override = Path('/etc/systemd/system') / unit
        if override.exists() and not (override.is_symlink() and os.readlink(override) == '/dev/null'):
            raise RuntimeError(f'Existing override for {service}; inspect manually before native installation.')
        run('systemctl', 'mask', unit)
    run('apt-get', 'install', '-y', '--no-install-recommends',
        f'cloudstack-management={VERSION}', f'cloudstack-agent={VERSION}',
        f'cloudstack-common={VERSION}', 'mysql-community-server', 'nfs-kernel-server',
        'python3.12-venv', 'curl', 'ca-certificates', 'nftables', 'jq', 'xmlstarlet', 'bridge-utils')
    mysql = run('mysql', '--version')
    if '8.4.' not in mysql:
        raise RuntimeError('MySQL 8.4 is required by the pinned CloudStack compatibility matrix.')


def network():
    save('/etc/systemd/network/80-dirigentenstab.netdev', f'[NetDev]\nName={BRIDGE}\nKind=bridge\n')
    save('/etc/systemd/network/80-dirigentenstab.network',
         f'[Match]\nName={BRIDGE}\n\n[Network]\nAddress={ADDRESS}/{NETWORK.prefixlen}\nConfigureWithoutCarrier=yes\nLinkLocalAddressing=no\n')
    save('/etc/systemd/network/81-dirigentenstab-anchor.netdev', '[NetDev]\nName=dummyds0\nKind=dummy\n')
    save('/etc/systemd/network/81-dirigentenstab-anchor.network',
         f'[Match]\nName=dummyds0\n\n[Network]\nBridge={BRIDGE}\nLinkLocalAddressing=no\n')
    if not Path(f'/sys/class/net/{BRIDGE}').exists():
        run('ip', 'link', 'add', BRIDGE, 'type', 'bridge')
    if not Path('/sys/class/net/dummyds0').exists():
        run('ip', 'link', 'add', 'dummyds0', 'type', 'dummy')
    run('ip', 'link', 'set', 'dummyds0', 'master', BRIDGE)
    run('ip', 'link', 'set', 'dummyds0', 'up')
    run('ip', 'address', 'replace', f'{ADDRESS}/{NETWORK.prefixlen}', 'dev', BRIDGE)
    run('ip', 'link', 'set', BRIDGE, 'up')
    # Separate chain: never flush an existing firewall or alter its default policy.
    save('/etc/dirigentenstab-network.nft',
         'table ip dirigentenstab {\n'
         ' chain nat { type nat hook postrouting priority srcnat; policy accept;\n'
         f'  ip saddr {NETWORK} ip daddr != {NETWORK} masquerade\n }}\n'
         '}\n'
         'table inet dirigentenstab_private {\n'
         ' chain private_services { type filter hook input priority -10; policy accept;\n'
         f"  ip saddr {NETWORK_CONFIG['APP_ADDRESS']} ip daddr {ADDRESS} tcp dport 8080 accept\n"
         f'  iifname != "lo" iifname != "{BRIDGE}" tcp dport {{ 111, 2049, 3306, 8080, 8250, 9090, 16509, 16514, 33060 }} drop\n'
         f'  iifname != "lo" iifname != "{BRIDGE}" udp dport {{ 111, 2049 }} drop\n'
         ' }\n}\n')
    save('/etc/systemd/system/dirigentenstab-network.service',
         '[Unit]\nDescription=Dirigentenstab isolated CloudStack network rules\nAfter=network-online.target\n'
         'Before=cloudstack-management.service cloudstack-agent.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
         'ExecStart=/usr/sbin/nft -f /etc/dirigentenstab-network.nft\n'
         'ExecStop=/usr/sbin/nft delete table ip dirigentenstab\n'
         'ExecStop=/usr/sbin/nft delete table inet dirigentenstab_private\n\n[Install]\nWantedBy=multi-user.target\n')
    for unit in ['cloudstack-management.service', 'cloudstack-agent.service', 'nfs-server.service', 'rpcbind.socket']:
        save(f'/etc/systemd/system/{unit}.d/dirigentenstab-network.conf',
             '[Unit]\nRequires=dirigentenstab-network.service\nAfter=dirigentenstab-network.service\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'dirigentenstab-network')


def install_network_config():
    save('/usr/local/libexec/network_config.py', (ROOT / 'scripts/network_config.py').read_text(), 0o644)
    save('/etc/dirigentenstab-network.env',
         ''.join(f'{key}={value}\n' for key, value in NETWORK_CONFIG.items()), 0o600)


def guest_ssh():
    """Install scoped SSH and native-SG routed guest forwarding without restarting native services."""
    install_network_config()
    save('/usr/local/libexec/dirigentenstab-guest-ssh.py',
         (ROOT / 'scripts/guest_ssh_forwarding.py').read_text(), 0o755)
    for kind in ('service', 'timer'):
        save(f'/etc/systemd/system/dirigentenstab-guest-ssh.{kind}',
             (ROOT / f'scripts/guest-ssh-forwarding.{kind}').read_text())
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'dirigentenstab-guest-ssh.timer')
    run('systemctl', 'start', 'dirigentenstab-guest-ssh.service')


def gpu_control():
    result = subprocess.run([str(ROOT / '.venv/bin/python'), str(ROOT / 'scripts/install_gpu_helper.py'), '--auto'], check=False)
    if result.returncode:
        raise RuntimeError('GPU controller setup incomplete; no policy was granted. Resolve the reported prerequisite and retry.')


def database():
    save('/etc/mysql/mysql.conf.d/dirigentenstab.cnf',
         '[mysqld]\nbind-address=127.0.0.1\nmysqlx-bind-address=127.0.0.1\n'
         'server-id=1\ninnodb_rollback_on_timeout=1\ninnodb_lock_wait_timeout=600\n'
         'max_connections=350\nlog_bin=mysql-bin\nbinlog_format=ROW\n'
         'sql_mode=STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION\n')
    run('systemctl', 'unmask', 'mysql')
    run('systemctl', 'enable', '--now', 'mysql')
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
    os.chown('/var/lib/libvirt/images/dirigentenstab', 0, pwd.getpwnam('libvirt-qemu').pw_gid)
    Path('/var/lib/libvirt/images/dirigentenstab').chmod(0o750)
    # Keep libvirt on its authenticated Unix socket: no unauthenticated TCP listener.
    properties('/etc/cloudstack/agent/agent.properties', {
        'host': f'{ADDRESS}@static', 'private.network.device': BRIDGE, 'public.network.device': BRIDGE,
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
    install_cmk()


def install_cmk():
    binary = Path('/usr/local/bin/cmk')
    if binary.exists() and hashlib.sha256(binary.read_bytes()).hexdigest() == CMK_SHA256:
        return
    original = STATE / 'originals/usr/local/bin/cmk'
    if binary.exists() and not original.exists():
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, original)
    download('https://github.com/apache/cloudstack-cloudmonkey/releases/download/6.6.0/cmk.linux.x86-64',
             binary, sha256=CMK_SHA256)
    binary.chmod(0o755)


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


def prepare_application():
    install_cmk()
    if subprocess.run([sys.executable, '-c', 'import ensurepip'], capture_output=True, check=False).returncode:
        run('apt-get', 'update')
        run('apt-get', 'install', '-y', 'python3.12-venv')
    if not shutil.which('docker'):
        if shutil.which('containerd'):
            raise RuntimeError('Existing containerd detected. Install a compatible Docker Engine/Compose without replacing that service, then retry.')
        run('apt-get', 'update')
        run('apt-get', 'install', '-y', 'docker.io', 'docker-compose-v2', 'python3.12-venv')
        run('systemctl', 'enable', '--now', 'docker')
    run('docker', 'compose', 'version')
    environment = ROOT / '.venv'
    if not (environment / 'bin/python').exists():
        run(sys.executable, '-m', 'venv', str(environment))
    run(str(environment / 'bin/pip'), 'install', '-r', str(ROOT / 'requirements.lock'))
    run(str(environment / 'bin/pip'), 'install', '--no-deps', '-e', str(ROOT))
    # The application owns .env, master-key creation and its CloudStack identity bootstrap.
    result = subprocess.run([str(environment / 'bin/python'), str(ROOT / 'scripts/configure_app.py'), '--resume'], check=False)
    if result.returncode:
        raise RuntimeError('Application configuration incomplete. Correct .env/prerequisites and rerun --existing; CloudStack is preserved.')


def verify_existing():
    python = ROOT / '.venv/bin/python'
    if not python.exists():
        raise RuntimeError('Run --install --existing to prepare the application first.')
    code = '''import asyncio,json
from pathlib import Path
from dotenv import dotenv_values
from dirigentenstab.cloud import Cloud
from dirigentenstab.settings import Settings
v=dotenv_values('.env')
p=Path(v['CLOUDSTACK_BOOTSTRAP_CREDENTIALS_FILE'])
if p.stat().st_mode & 0o077: raise SystemExit('Bootstrap credentials must remain private (chmod 600).')
k=json.loads(p.read_text())
c=Cloud(Settings(v['CLOUDSTACK_URL'],v['PUBLIC_ORIGIN']),{n:k[n] for n in ('apikey','secretkey')})
asyncio.run(c.raw('listCapabilities'))
print('Existing CloudStack API verified through CloudMonkey; native services were not changed.')
'''
    if subprocess.run([str(python), '-c', code], cwd=ROOT, check=False).returncode:
        raise RuntimeError('Existing CloudStack API verification failed; check the private endpoint and bootstrap credential validity.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    for name in ['preflight', 'install', 'verify', 'guest-ssh']:
        modes.add_argument('--' + name, action='store_true')
    parser.add_argument('--existing', action='store_true', help='Connect to an existing private CloudStack installation')
    args = parser.parse_args()
    if not any([args.preflight, args.install, args.verify, args.existing, args.guest_ssh]):
        parser.error('Choose --preflight, --install, --verify, --guest-ssh or --existing')
    if os.geteuid() != 0:
        parser.error('Run with sudo. Preflight reads protected virtualization and network state.')
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    if args.guest_ssh:
        guest_ssh()
    elif args.preflight:
        preflight(existing=args.existing)
    elif args.verify:
        verify_existing() if args.existing else verify()
    elif args.existing:
        print('Existing mode: CloudStack services and networking are not modified.')
        prepare_application()
        gpu_control()
    else:
        preflight()
        for name, action in [('repositories', repositories), ('packages', packages), ('network', network),
                             ('database', database), ('services', services)]:
            step(name, action)
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/zone_setup.py')], check=False)
        if result.returncode:
            raise RuntimeError('Zone setup incomplete; safe to retry after resolving the reported prerequisite.')
        verify()
        prepare_application()
        guest_ssh()
        gpu_control()


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
