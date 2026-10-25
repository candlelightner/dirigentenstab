#!/usr/bin/env python3
"""CI-only browser fixture: real application/auth/runtime, fake CloudStack and model."""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from nicegui import app, ui
from pydantic_ai.models.function import DeltaToolCall, FunctionModel

from dirigentenstab import runtime as runtime_module
from dirigentenstab.auth import Auth, attach
from dirigentenstab.cloud import Cloud
from dirigentenstab.service import Service
from dirigentenstab.settings import Settings
from dirigentenstab.store import Store
from dirigentenstab.web import build_ui

ROOT_DOMAIN = '00000000-0000-0000-0000-000000000001'
AGENT_DOMAIN = '00000000-0000-0000-0000-000000000002'
HUMAN_ID = '00000000-0000-0000-0000-000000000003'
AGENT_ID = 'research'
PRIVATE_VALUES = ('fixture-runtime-api-DO-NOT-EXPOSE', 'fixture-runtime-secret-DO-NOT-EXPOSE',
                  'fixture-provision-api-DO-NOT-EXPOSE', 'fixture-provision-secret-DO-NOT-EXPOSE',
                  'fixture-provider-key-DO-NOT-EXPOSE', 'fixture-VM-password-DO-NOT-EXPOSE')
DOMAINS = [{'id': ROOT_DOMAIN, 'name': 'ROOT', 'path': 'ROOT', 'level': 0},
           {'id': 'main-domain', 'name': 'Agents--ds-00000000000000000000', 'path': 'ROOT/Agents',
            'parentdomainid': ROOT_DOMAIN, 'level': 1},
           {'id': AGENT_DOMAIN, 'name': 'Research', 'path': 'ROOT/Agents/Research', 'parentdomainid': 'main-domain'}]
for branch in range(12):
    parent = AGENT_DOMAIN
    for depth in range(4):
        identifier = f'domain-{branch}-{depth}'
        DOMAINS.append({'id': identifier, 'name': f'Team {branch} Level {depth}', 'parentdomainid': parent,
                        'path': f'ROOT/Agents/Research/Team-{branch}/Level-{depth}'})
        parent = identifier


def fake_api(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == '/v1/models':
                value, status = {'data': [{'id': 'fixture-model'}, {'id': 'second-model'}]}, 200
            elif self.path == '/empty/models':
                value, status = {'data': []}, 200
            elif self.path == '/unauthorized/models':
                value, status = {'error': 'private provider error'}, 401
            else:
                value, status = {}, 404
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            params = {key: values[-1] for key, values in parse_qs(
                self.rfile.read(int(self.headers.get('Content-Length', '0'))).decode()).items()}
            command = params.get('command', '')
            enabled = not (state / 'human-disabled').exists()
            if command == 'login':
                if params.get('username') != 'alice' or params.get('password') != 'browser-fixture-password' or not enabled:
                    value = {'errorcode': 401}
                else:
                    value = {'userid': HUMAN_ID, 'username': 'alice', 'domainid': ROOT_DOMAIN, 'account': 'alice',
                             'type': 1, 'sessionkey': 'fixture-human-session-DO-NOT-EXPOSE'}
            elif command == 'listUsers':
                value = {'user': [{'id': HUMAN_ID, 'username': 'alice', 'domainid': ROOT_DOMAIN,
                                   'state': 'enabled' if enabled else 'disabled'}]}
            elif command == 'listAccounts':
                value = {'account': [{'id': HUMAN_ID, 'name': 'alice', 'domainid': ROOT_DOMAIN,
                                      'state': 'enabled', 'accounttype': 1}]}
            elif command == 'listDomains':
                value = {'domain': [d for d in DOMAINS if not params.get('id') or d['id'] == params['id']]}
            elif command == 'logout':
                value = {'success': True}
            else:
                value = {'errorcode': 431}
            data = json.dumps({command.lower() + 'response': value}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            if command == 'login':
                self.send_header('Set-Cookie', 'JSESSIONID=fixture-cloudstack-session; HttpOnly; Path=/')
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


class FixtureCloud(Cloud):
    async def raw(self, command, params=None):
        params = params or {}
        if command == 'listDomains':
            return {'domain': [d for d in DOMAINS if not params.get('id') or d['id'] == params['id']]}
        if command == 'listVirtualMachines':
            return {'virtualmachine': [{'id': '00000000-0000-0000-0000-000000000004', 'name': 'research-vm',
                                        'state': 'Running', 'password': PRIVATE_VALUES[-1],
                                        'note': PRIVATE_VALUES[0]}]}
        raise ValueError('This CI fixture only supports listing domains and VMs')

    async def catalogue(self):
        return {'listVirtualMachines': {'name': 'listVirtualMachines', 'description': 'List authorized guest VMs',
                                        'params': [], 'isasync': False, 'response': []}}


class FixtureService(Service):
    def client(self, credentials):
        self._remember(credentials)
        return FixtureCloud(self.settings, credentials)


async def fake_model(messages, info):
    assert all(secret not in str(messages) + str(info.instructions) for secret in PRIVATE_VALUES)
    prompt = next((str(part.content) for message in reversed(messages) for part in message.parts
                   if part.part_kind == 'user-prompt'), '')
    if 'markdown stress' in prompt:
        yield ('## Infrastructure report\n\n**Ready** and *checked*. `inline` [CloudStack](https://cloudstack.apache.org)\n\n'
               '> Bounded details\n\n1. First\n2. Second\n\n- Safe\n- Readable\n\n'
               '```python\n' + 'print("long line") ' * 100 + '\n```\n\n'
               '| Name | ' + ' | '.join(f'Column {n}' for n in range(20)) + ' |\n' +
               '| --- ' * 21 + '|\n' + ('| example ' * 21 + '|\n') * 40 +
               '\n<script>window.injected=true</script>\n<img src=x onerror="window.injected=true">')
    elif any(part.part_kind == 'tool-return' for part in messages[-1].parts):
        yield 'Infrastructure '
        yield 'checked. The research VM is running.'
    else:
        yield {0: DeltaToolCall(name='execute_api', json_args=json.dumps(
            {'command': 'listVirtualMachines', 'params': {}}))}


def certificate(directory):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(
        now + timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),
                                              critical=False).sign(private, hashes.SHA256())
    key_path, cert_path = directory / 'tls.key', directory / 'tls.crt'
    key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(key_path), str(cert_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    if os.environ.get('DIRIGENTENSTAB_BROWSER_FIXTURE') != '1':
        parser.error('Set DIRIGENTENSTAB_BROWSER_FIXTURE=1 only for isolated browser testing')
    os.umask(0o077)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    master = args.state_dir / 'master'
    master.write_bytes(Fernet.generate_key())
    store = Store(str(args.state_dir / 'browser.db'), str(master))
    store.execute('INSERT INTO providers(id,name,protocol,base_url,api_key,default_model) VALUES(?,?,?,?,?,?)',
                  ('fixture', 'Local fixture', 'chat', 'http://127.0.0.1/v1', store.seal(PRIVATE_VALUES[4]), 'fixture-model'))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,provider_id,model) '
                  'VALUES(?,?,?,?,?,?,?,?,?)',
                  (AGENT_ID, 'Research Admin', AGENT_DOMAIN, 'research-account', 'research-user',
                   store.seal({'apikey': PRIVATE_VALUES[0], 'secretkey': PRIVATE_VALUES[1]}),
                   store.seal({'apikey': PRIVATE_VALUES[2], 'secretkey': PRIVATE_VALUES[3]}), 'fixture', 'fixture-model'))
    api_port = fake_api(args.state_dir)
    store.execute('UPDATE providers SET base_url=? WHERE id=?', (f'http://127.0.0.1:{api_port}/v1', 'fixture'))
    for identifier, endpoint in [('unsupported', 'unsupported'), ('empty', 'empty'), ('unauthorized', 'unauthorized')]:
        store.execute('INSERT INTO providers VALUES(?,?,?,?,?,?)',
                      (identifier, identifier.title(), 'chat', f'http://127.0.0.1:{api_port}/{endpoint}',
                       store.seal(''), ''))
    for identifier, domain, name in [('main', 'main-domain', 'Agents'), *[
            (f'agent-{b}-{d}', f'domain-{b}-{d}', f'Team {b} Level {d}') for b in range(12) for d in range(4)]]:
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,provider_id,model) '
                      'VALUES(?,?,?,?,?,?,?,?,?)', (identifier, name, domain, identifier+'-account', identifier+'-user',
                       store.seal({'apikey': PRIVATE_VALUES[0], 'secretkey': PRIVATE_VALUES[1]}),
                       store.seal({'apikey': PRIVATE_VALUES[2], 'secretkey': PRIVATE_VALUES[3]}), 'fixture', 'fixture-model'))
    store.execute('INSERT INTO provisioning(id,name,model,instructions,phase,updated) VALUES(?,?,?,?,?,?)',
                  ('main', 'Agents', 'fixture-model', '', 'complete', 0))
    settings = Settings(f'http://127.0.0.1:{api_port}/client/api', f'https://localhost:{args.port}',
                        database=str(store.path), key_file=str(master))
    service = FixtureService(store, settings)
    auth = Auth(service)
    runtime_module.build_model = lambda *args: FunctionModel(stream_function=fake_model)
    attach(app, auth, settings)
    build_ui(service, auth)
    key_file, cert_file = certificate(args.state_dir)
    ui.run(host='127.0.0.1', port=args.port, title='Dirigentenstab browser fixture', reload=False, show=False,
           show_welcome_message=False, ssl_keyfile=key_file, ssl_certfile=cert_file)


if __name__ == '__main__':
    main()
