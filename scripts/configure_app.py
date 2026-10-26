#!/usr/bin/env python3
"""Run with the project's Python environment; credentials are read only from private files."""
import argparse
import asyncio
import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dotenv import dotenv_values

from dirigentenstab.limits import GLOBAL_ADMIN_AGENT
from dirigentenstab.service import Service
from dirigentenstab.settings import Settings
from dirigentenstab.store import Store
from network_config import load_network

ROOT = Path(__file__).resolve().parent.parent


def private(path, content, *, owner=10001):
    if not path.exists():
        with path.open('xb') as file:
            file.write(content)
        path.chmod(0o400)
        os.chown(path, owner, owner)


def configure(args):
    env_path = ROOT / '.env'
    if not env_path.exists():
        raise SystemExit('Copy .env.example to .env and configure the private endpoint and HTTPS origin first.')
    env_path.chmod(0o600)
    values = dotenv_values(env_path)
    origin, api = values['PUBLIC_ORIGIN'], values['CLOUDSTACK_URL']
    settings = Settings(api, origin)
    if urlsplit(origin).scheme != 'https':
        raise SystemExit('PUBLIC_ORIGIN must use HTTPS. See docs/INSTALLATION.md.')
    network = load_network(env_path)
    for net in json.loads(subprocess.check_output(['ip', '-json', 'route'])):
        if (net.get('dst') != 'default' and net.get('dst')
                and ipaddress.ip_network(net['dst']).overlaps(ipaddress.ip_network(network['APP_NETWORK']))
                and not net.get('dev', '').startswith('br-')):
            raise SystemExit('Application Docker subnet conflicts with an existing route.')
    port = int(values.get('BIND_PORT', 3000))
    try:
        with socket.socket() as listener:
            listener.bind((values.get('BIND_ADDRESS', '127.0.0.1'), port))
    except OSError:
        containers = json.loads(subprocess.check_output(['docker', 'ps', '--filter',
                                 'label=com.docker.compose.project=dirigentenstab', '--filter',
                                 'label=com.docker.compose.service=app', '--format', '{{json .}}']).decode()
                                .strip() or '{}')
        owned = bool(containers and f':{port}->8088/tcp' in containers.get('Ports', ''))
        if not args.resume or not owned:
            raise SystemExit(f'Application port {port} is occupied. Set BIND_PORT and PUBLIC_ORIGIN to a free port.') from None
    secret_dir = ROOT / 'secrets'
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    master = Path(values.get('MASTER_KEY_PATH', './secrets/master_key'))
    master = master if master.is_absolute() else ROOT / master
    subprocess.run(['docker', 'volume', 'create', 'dirigentenstab_data'], check=True, stdout=subprocess.DEVNULL)
    volume = json.loads(subprocess.check_output(['docker', 'volume', 'inspect', 'dirigentenstab_data']))[0]
    data = Path(volume['Mountpoint'])
    if (data / 'dirigentenstab.db').exists() and not master.exists():
        raise SystemExit('Existing database has no master key. Restore its matching key; no replacement was generated.')
    master.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(master, Fernet.generate_key() + b'\n')
    cert_path = ROOT / values.get('TLS_CERT_PATH', './secrets/tls.crt')
    tls_path = ROOT / values.get('TLS_KEY_PATH', './secrets/tls.key')
    if not cert_path.exists() and not tls_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        host = urlsplit(origin).hostname
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        names = [x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
        now = datetime.datetime.now(datetime.UTC)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName(names), critical=False).sign(key, hashes.SHA256()))
        private(tls_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        private(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    if not cert_path.exists() or not tls_path.exists():
        raise SystemExit('TLS certificate/key pair is incomplete; restore the missing file before continuing.')
    settings.database, settings.key_file = str(data / 'dirigentenstab.db'), str(master)
    settings.cmk = '/usr/local/bin/cmk'
    store = Store(settings.database, settings.key_file)
    service = Service(store, settings)
    if not store.one('SELECT id FROM agents WHERE id=?', (GLOBAL_ADMIN_AGENT,)):
        credentials_file = args.credentials_file or values.get('CLOUDSTACK_BOOTSTRAP_CREDENTIALS_FILE')
        if not credentials_file:
            raise SystemExit('Provide a root-private CloudStack administrator API credential JSON file.')
        path = Path(credentials_file)
        if path.stat().st_mode & 0o077:
            raise SystemExit('Bootstrap credentials file must be private (chmod 600).')
        credentials = json.loads(path.read_text())
        asyncio.run(service.bootstrap({key: credentials[key] for key in ('apikey', 'secretkey')}))
    zone_file = Path('/var/lib/dirigentenstab/setup/zone.json')
    if zone_file.exists():
        zone = json.loads(zone_file.read_text())
        if zone.get('template_id'):
            store.execute('INSERT OR IGNORE INTO managed_templates(id,name) VALUES(?,?)',
                          (zone['template_id'], 'Managed Ubuntu cloud-init template'))
    for path in [data, *data.iterdir()]:
        os.chown(path, 10001, 10001)
    print(f'Application configured. Keep {master} backed up separately from the database.')
    print(f'Run docker compose up -d. Browser origin: {origin}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--credentials-file')
    parser.add_argument('--resume', action='store_true')
    options = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit('Run application setup as root to prepare private Docker secrets and volume ownership.')
    configure(options)
