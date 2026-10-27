#!/usr/bin/env python3
"""CI-only browser fixture: real application/auth/runtime, fake CloudStack and model."""

import argparse
import asyncio
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
from websockets.sync.server import serve
from pydantic_ai.models.function import DeltaToolCall, FunctionModel

from dirigentenstab import runtime as runtime_module
from dirigentenstab.auth import Auth, attach
from dirigentenstab.cloud import Cloud
from dirigentenstab.limits import APP_ROOT_AGENT, GLOBAL_ADMIN_AGENT
from dirigentenstab.mcp import MCP
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
           {'id': AGENT_DOMAIN, 'name': 'Research', 'path': 'ROOT/Agents/Research', 'parentdomainid': 'main-domain', 'level': 2}]
for branch in range(12):
    parent = AGENT_DOMAIN
    for depth in range(4):
        identifier = f'domain-{branch}-{depth}'
        DOMAINS.append({'id': identifier, 'name': f'Team {branch} Level {depth}', 'parentdomainid': parent,
                        'path': f'ROOT/Agents/Research/Team-{branch}/Level-{depth}', 'level': depth + 3})
        parent = identifier


def fake_api(state):
    def echo(socket):
        for message in socket:
            socket.send(message)

    websocket = serve(echo, '127.0.0.1', 0, subprotocols=['binary'])
    websocket_port = websocket.socket.getsockname()[1]
    Thread(target=websocket.serve_forever, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path.startswith('/resource/noVNC/'):
                if self.path == '/resource/noVNC/vnc.html':
                    content = '<body style="margin:0;background:#111;color:white">Fixture noVNC console<div id="status"></div><script src="fixture.js"></script></body>'
                    mime = 'text/html'
                elif self.path == '/resource/noVNC/fixture.js':
                    content = '''const q = new URLSearchParams(location.search);
const ws = new WebSocket('wss://' + q.get('host') + ':' + q.get('port') + '/' + q.get('path') + '?token=' + q.get('token'), ['binary']);
ws.onopen = () => ws.send('Connected through console proxy');
ws.onmessage = e => document.getElementById('status').textContent = e.data;
'''
                    mime = 'text/javascript'
                else:
                    self.send_error(404)
                    return
                data = content.encode()
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if self.path == '/v1/models':
                value, status = {'data': [
                    {'id': 'fixture-model', 'context_window': 65536, 'effort': {'supported_levels': ['low', 'high', 'max'], 'default_level': 'high'}},
                    {'id': 'second-model', 'max_model_len': 32768, 'effort': {'supported_levels': ['low', 'high']}}]}, 200
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
            elif command == 'listVirtualMachines':
                value = {'virtualmachine': [{'id': '00000000-0000-0000-0000-000000000004', 'name': 'research-vm',
                                             'displayname': 'Research Worker',
                                             'state': 'Running'}]}
            elif command == 'createConsoleEndpoint':
                count_file = state / 'console-count'
                count = int(count_file.read_text()) + 1 if count_file.exists() else 1
                count_file.write_text(str(count))
                if (state / 'console-delay').exists():
                    import time
                    time.sleep(0.8)
                value = {'consoleendpoint': {'success': not (state / 'console-error').exists(),
                         'details': 'Console fixture denied',
                         'url': f'http://127.0.0.1:{self.server.server_address[1]}/resource/noVNC/vnc.html'
                                f'?host=127.0.0.1&port={websocket_port}&encrypt=0&path=websockify&token=ticket-{count}'}}
            elif command == 'listApis':
                value = {'api': [{'name': 'updateVirtualMachine', 'params': [
                    {'name': 'id', 'type': 'uuid', 'required': True},
                    {'name': 'name', 'type': 'string'}], 'isasync': False}]}
            elif command == 'updateVirtualMachine':
                (state / 'escalation-executed.json').write_text(json.dumps({
                    'command': command, 'params': {key: value for key, value in params.items()
                    if key not in {'command', 'response', 'sessionkey'}}}))
                value = {'virtualmachine': {'id': params['id'], 'name': params['name']}}
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
                                        'displayname': 'Research Worker',
                                        'state': 'Running', 'password': PRIVATE_VALUES[-1],
                                        'note': PRIVATE_VALUES[0]}]}
        raise ValueError('This CI fixture only supports listing domains and VMs')

    async def catalogue(self, *, refresh=False):
        return {'listVirtualMachines': {'name': 'listVirtualMachines', 'description': 'List authorized guest VMs',
                                        'params': [{'name': 'listall', 'type': 'boolean', 'required': False}], 'isasync': False, 'response': []},
                **{name: {'name': name, 'params': [], 'isasync': False, 'response': []}
                   for name in ('createDomain', 'createAccount', 'registerUserKeys')}}


class FixtureService(Service):
    sftp_root = None
    sftp_server = None

    async def open_vm_connection(self, identity, vm_id, operation=None):
        # Stand-in for the guest: a local SFTP-only server rooted at <state>/vm-files, still behind the authorization path.
        import asyncssh
        if not self.sftp_server:
            class Server(asyncssh.SSHServer):
                def begin_auth(self, username):
                    return False

            self.sftp_server = await asyncssh.create_server(
                Server, '127.0.0.1', 0, server_host_keys=[asyncssh.generate_private_key('ssh-ed25519')],
                sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=self.sftp_root))
        if operation:
            self.store.audit(identity['userid'], operation, vm_id)
        conn = await asyncssh.connect('127.0.0.1', self.sftp_server.get_port(), username='dirigent',
                                      known_hosts=None, config=None, agent_path=None)
        return conn, {'id': vm_id, 'name': 'research-vm'}

    def client(self, credentials):
        self._remember(credentials)
        return FixtureCloud(self.settings, credentials)

    async def gpu_admin(self, identity, action='status', **payload):
        from dirigentenstab.gpu import effective_policy, narrows, validate_policy
        from dirigentenstab.gpu_control import Controller
        if identity.get('type') != 1:
            raise PermissionError('Human platform administrator required')
        row = self.store.one("SELECT value FROM platform_settings WHERE name='fixture_gpu_policies'")
        policies = json.loads(row['value']) if row else {}
        profiles = [{'id': 'nvidia-51', 'name': 'GRID P40-8Q'}, {'id': 'nvidia-53', 'name': 'GRID P40-24Q'}]
        if action == 'set_policy':
            policy = validate_policy(payload['policy'], [p['id'] for p in profiles])
            chain = Controller.chain(DOMAINS, payload['domain_id'])
            if len(chain) > 1 and not narrows(policy, effective_policy(chain[:-1], policies)):
                raise PermissionError('Child policy cannot expand ancestor permissions')
            policies[payload['domain_id']] = policy
            self.store.execute("INSERT INTO platform_settings VALUES('fixture_gpu_policies',?) "
                               'ON CONFLICT(name) DO UPDATE SET value=excluded.value', (json.dumps(policies),))
            return {'saved': True}
        if action != 'status':
            raise PermissionError('Fixture GPU operation unavailable')
        return {'domains': DOMAINS, 'profiles': profiles, 'policies': policies,
                'pools': [], 'devices': [], 'operations': []}


async def fake_model(messages, info):
    assert all(secret not in str(messages) + str(info.instructions) for secret in PRIVATE_VALUES)
    prompt = next((str(part.content) for message in reversed(messages) for part in message.parts
                   if part.part_kind == 'user-prompt'), '')
    if 'Summarize the user request' in str(info.instructions):
        yield 'Summarized Chat Title'
    elif 'escalation fixture' in prompt:
        requested = any(part.part_kind == 'tool-return' and part.tool_name == 'request_escalation'
                        for message in messages for part in message.parts)
        if requested:
            yield 'Escalation requested.'
        else:
            yield {0: DeltaToolCall(name='request_escalation', json_args=json.dumps({
                'description': 'Rename the research VM so the owner can identify the production analysis workspace',
                'reason': 'My current CloudStack account cannot update this VM because its native role does not allow updateVirtualMachine',
                'command': 'updateVirtualMachine', 'params': {
                'id': '00000000-0000-0000-0000-000000000004', 'name': 'Research revised'}}),
                tool_call_id='escalation-fixture')}
    elif 'heartbeat fixture' in prompt:
        loop = asyncio.get_running_loop()
        deadline, index = loop.time() + 40, 0
        while loop.time() < deadline:
            yield f'Heartbeat {index}. '
            index += 1
            await asyncio.sleep(1)
        yield 'Streaming complete.'
    elif 'background fixture' in prompt:
        yield 'Background work accepted.'
        await asyncio.sleep(2)
        yield ' Background work completed.'
    elif 'stop fixture' in prompt:
        yield 'Partial reply retained'
        await asyncio.sleep(60)
        yield 'This response should be stopped'
    elif 'thinking indicator' in prompt:
        await asyncio.sleep(0.5)
        yield 'Pending response complete.'
    elif 'bounded lifecycle' in prompt:
        await asyncio.sleep(0.15)
        completed = sum(part.part_kind == 'tool-return' for message in messages for part in message.parts)
        if completed >= 5:
            yield 'Bounded lifecycle complete'
        else:
            yield {0: DeltaToolCall(name='execute_api', json_args=json.dumps(
                {'command': 'listVirtualMachines', 'params': {}}), tool_call_id=f'bounded-{completed}')}
    elif 'markdown stress' in prompt:
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
    with store.connect() as conn:
        conn.execute('INSERT INTO providers(id,name,protocol,base_url,api_key,default_model) VALUES(?,?,?,?,?,?)',
                      ('fixture', 'Local fixture', 'chat', 'http://127.0.0.1/v1', store.seal(PRIVATE_VALUES[4]), 'fixture-model'))
        conn.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,provider_id,model) '
                      'VALUES(?,?,?,?,?,?,?,?)',
                      (AGENT_ID, 'Research Admin', AGENT_DOMAIN, 'research-account', 'research-user',
                       store.seal({'apikey': PRIVATE_VALUES[0], 'secretkey': PRIVATE_VALUES[1]}),
                       'fixture', 'fixture-model'))
        api_port = fake_api(args.state_dir)
        conn.execute('UPDATE providers SET base_url=? WHERE id=?', (f'http://127.0.0.1:{api_port}/v1', 'fixture'))
        for identifier, endpoint in [('unsupported', 'unsupported'), ('empty', 'empty'), ('unauthorized', 'unauthorized')]:
            conn.execute('INSERT INTO providers VALUES(?,?,?,?,?,?)',
                          (identifier, identifier.title(), 'chat', f'http://127.0.0.1:{api_port}/{endpoint}',
                           store.seal(''), ''))
        for identifier, domain, name in [(APP_ROOT_AGENT, 'main-domain', 'Agents'),
                                         (GLOBAL_ADMIN_AGENT, ROOT_DOMAIN, 'Global Admin'), *[
                (f'agent-{b}-{d}', f'domain-{b}-{d}', f'Team {b} Level {d}') for b in range(12) for d in range(4)]]:
            conn.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,provider_id,model) '
                          'VALUES(?,?,?,?,?,?,?,?)', (identifier, name, domain, identifier+'-account', identifier+'-user',
                           store.seal({'apikey': PRIVATE_VALUES[0], 'secretkey': PRIVATE_VALUES[1]}),
                           'fixture', 'fixture-model'))
        conn.execute('INSERT INTO provisioning(id,name,model,instructions,phase,updated) VALUES(?,?,?,?,?,?)',
                      (APP_ROOT_AGENT, 'Agents', 'fixture-model', '', 'complete', 0))
        conn.execute(
            'INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) VALUES(?,?,?,?,?,?)',
            ('00000000-0000-0000-0000-000000000004', AGENT_ID, 'dirigent',
             store.seal('fixture-vm-key'), 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGSLVRtZbt6j3blQyUYXi5uLqk2MmNJc3wB7hc4PKlkV', 22),
        )
    settings = Settings(f'http://127.0.0.1:{api_port}/client/api', f'https://localhost:{args.port}',
                        database=str(store.path), key_file=str(master),
                        cloudstack_ui_url='https://cloudstack.tailnet.invalid/client')
    service = FixtureService(store, settings)
    service.sftp_root = args.state_dir / 'vm-files'
    (service.sftp_root / 'docs').mkdir(parents=True)
    (service.sftp_root / 'docs' / 'report.txt').write_text('fixture report\n')
    (service.sftp_root / f'long-name-{"x" * 120}.txt').write_text('long\n')

    async def discover_mcp(self, identity, agent_id, server_id):
        configuration = await self.configuration(identity, agent_id)
        server = next((row for row in configuration['servers'] if row['id'] == server_id and row['enabled']), None)
        if not server:
            raise PermissionError('MCP server is unavailable')
        if (args.state_dir / 'mcp-unavailable').exists():
            raise RuntimeError('MCP server discovery failed in browser fixture')
        tools = [{'name': 'tavily_search', 'description': 'Search the web for relevant sources.'},
                 {'name': 'tavily_extract', 'description': 'Extract content from selected URLs.'}]
        allowed = server['allowed_tools']
        return [tool for tool in tools if allowed is None or tool['name'] in allowed]

    MCP.discover = discover_mcp
    auth = Auth(service)
    runtime_module.build_model = lambda *args: FunctionModel(stream_function=fake_model)
    attach(app, auth, settings)
    app.on_startup(build_ui(service, auth).start)
    key_file, cert_file = certificate(args.state_dir)
    ui.run(host='127.0.0.1', port=args.port, title='Dirigentenstab browser fixture', reload=False, show=False,
           show_welcome_message=False, ssl_keyfile=key_file, ssl_certfile=cert_file)


if __name__ == '__main__':
    main()
