import asyncio
from contextlib import contextmanager
from threading import Event, Thread
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest
from starlette.websockets import WebSocketDisconnect
from websockets.sync.server import serve

from dirigentenstab.auth import SessionGuard
from dirigentenstab.console import ConsoleProxy, _NoRedirectConnect


class Store:
    def __init__(self):
        self.sessions = {'one': time.time() + 3600, 'two': time.time() + 3600}

    def one(self, sql, params):
        return self.sessions.get(params[0], 0) > params[1]


@pytest.fixture
def setup():
    store = Store()
    calls = []

    async def native(identity, vm):
        calls.append((identity, vm))
        return 'http://cpvm/resource/noVNC/vnc.html?autoconnect=true&show_dot=true&port=8080&token=native+secret%2Fticket%3D'

    service = SimpleNamespace(store=store, settings=SimpleNamespace(origin='https://app.example:3001'),
                              vm_console_url=native)
    proxy = ConsoleProxy(service)

    async def identity(token):
        if token not in store.sessions:
            raise PermissionError()
        return {'userid': 'same-human', '_session': token}

    app = FastAPI()
    app.add_middleware(SessionGuard, auth=SimpleNamespace(identity=identity), origin=service.settings.origin)
    proxy.install(app)

    @app.get('/other')
    def other():
        return 'other'

    path = asyncio.run(proxy.open({'userid': 'same-human', '_session': 'one'}, 'vm-1'))
    return proxy, app, path, calls


def mock_http(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr('dirigentenstab.console.httpx.AsyncClient',
                        lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(handler)))


def test_native_authorization_and_local_transport_rewrite(setup):
    proxy, _, path, calls = setup
    assert calls == [({'userid': 'same-human', '_session': 'one'}, 'vm-1')]
    query = parse_qs(urlsplit(path).query)
    assert 'native+secret' not in path and 'cpvm' not in path
    assert query['host'] == ['app.example'] and query['port'] == ['3001']
    assert query['encrypt'] == ['1'] and query['autoconnect'] == ['true'] and query['reconnect'] == ['false']
    ticket = path.split('/')[2]
    assert query['path'] == ['vm-console/' + ticket + '/ws']
    assert proxy.grants[ticket].websocket == 'ws://cpvm:8080/websockify?token=native+secret/ticket='


def test_static_resources_session_binding_headers_and_query_isolation(setup, monkeypatch):
    proxy, app, path, _ = setup
    requested = []

    def handler(request):
        requested.append(str(request.url))
        assert 'cookie' not in request.headers
        return httpx.Response(200, content=b'console', headers={'content-type': 'text/html',
                                                             'set-cookie': 'upstream=secret'})

    mock_http(monkeypatch, handler)
    with TestClient(app, base_url='https://app.example:3001') as client:
        assert client.get(path).status_code == 401
        client.cookies.set('ds_session', 'two')
        assert client.get(path).status_code == 403
        client.cookies.set('ds_session', 'one')
        response = client.get(path)
        assert response.status_code == 200 and response.content == b'console'
        assert response.headers['x-frame-options'] == 'SAMEORIGIN'
        assert response.headers['cache-control'] == 'no-store'
        assert 'set-cookie' not in response.headers
        assert client.get('/other').headers['x-frame-options'] == 'DENY'
        assert client.get('/vm-console-other').headers['x-frame-options'] == 'DENY'
        root = path.split('vnc.html')[0]
        assert client.get(root + 'app/ui.js?url=http://evil/&token=evil').status_code == 200
        assert requested == ['http://cpvm/resource/noVNC/vnc.html', 'http://cpvm/resource/noVNC/app/ui.js']
        proxy.grants[path.split('/')[2]].expires = 0
        assert client.get(path).status_code == 403


@pytest.mark.parametrize('resource', ['%252e%252e/secret', '%2e%2e%2fsecret', 'app%5csecret',
                                     'http:evil', '%2f%2fevil', 'app//secret', 'app/%00secret'])
def test_traversal_and_ssrf_never_reach_upstream(setup, monkeypatch, resource):
    _, app, path, _ = setup

    def unexpected(request):
        pytest.fail('Unsafe path reached upstream')

    mock_http(monkeypatch, unexpected)
    with TestClient(app, base_url='https://app.example:3001') as client:
        client.cookies.set('ds_session', 'one')
        assert client.get(path.split('vnc.html')[0] + resource).status_code in {403, 404}


def test_upstream_redirect_and_errors_are_not_forwarded(setup, monkeypatch):
    _, app, path, _ = setup
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={'location': 'http://evil/?token=native-secret'})

    mock_http(monkeypatch, handler)
    with TestClient(app, base_url='https://app.example:3001') as client:
        client.cookies.set('ds_session', 'one')
        response = client.get(path)
        assert response.status_code == 502 and 'native-secret' not in response.text
        assert len(requests) == 1
    error = RuntimeError('redirect')
    assert _NoRedirectConnect('ws://cpvm').process_redirect(error) is error


@pytest.mark.parametrize('native', [
    'http://cpvm/other?token=secret',
    'http://cpvm/resource/noVNC/vnc.html?host=evil&token=secret',
    'http://cpvm/resource/noVNC/vnc.html?port=0&token=secret',
    'http://cpvm/resource/noVNC/vnc.html?path=../../private&token=secret',
    'http://cpvm/resource/noVNC/vnc.html?port=8080',
])
async def test_reject_unsupported_native_transport(setup, native):
    proxy, _, _, _ = setup

    async def endpoint(*args):
        return native

    proxy.service.vm_console_url = endpoint
    with pytest.raises(ValueError):
        await proxy.open({'_session': 'one'}, 'vm')
    with pytest.raises(PermissionError):
        await proxy.open({'_session': 'missing'}, 'vm')


@contextmanager
def echo_server():
    requests = []
    closed = Event()

    def echo(socket):
        requests.append(socket.request.path)
        try:
            for message in socket:
                socket.send(message)
        finally:
            closed.set()

    with serve(echo, '127.0.0.1', 0, subprotocols=['binary']) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.socket.getsockname()[1], requests, closed
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.mark.parametrize('duplicate', [False, True])
@pytest.mark.parametrize('revocation', ['logout', 'expiry', 'native'])
def test_bidirectional_websocket_origin_session_and_active_revocation(setup, monkeypatch, duplicate, revocation):
    proxy, app, path, _ = setup
    ticket = path.split('/')[2]
    ws_path = '/vm-console/' + ticket + '/ws'
    if duplicate:
        ws_path += '/vm-console/' + ticket + '/ws'
    ws_path += '?token=client-cannot-select-upstream'
    monkeypatch.setattr('dirigentenstab.console.SESSION_POLL_SECONDS', 0.01)
    monkeypatch.setattr('dirigentenstab.console.NATIVE_POLL_SECONDS', 0.01)
    revoked = False

    async def revalidate(session):
        assert session == 'one'
        if revoked:
            raise PermissionError('Revoked native session')

    proxy.auth.identity_from_session = revalidate
    with echo_server() as (port, requests, closed), TestClient(app, base_url='https://app.example:3001') as client:
        proxy.grants[ticket].websocket = f'ws://127.0.0.1:{port}/websockify?token=native-secret'
        client.cookies.set('ds_session', 'one')
        with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect(ws_path):
            pass
        assert exc.value.code == 4403
        client.cookies.set('ds_session', 'two')
        with pytest.raises(WebSocketDisconnect), client.websocket_connect(ws_path, headers={'origin': 'https://app.example:3001'}):
            pass
        client.cookies.set('ds_session', 'one')
        with client.websocket_connect(ws_path, headers={'origin': 'https://app.example:3001'}, subprotocols=['binary']) as ws:
            ws.send_bytes(b'\x00\xffbinary')
            assert ws.receive_bytes() == b'\x00\xffbinary'
            ws.send_text('text')
            assert ws.receive_text() == 'text'
            assert requests == ['/websockify?token=native-secret']
            # Ticket expiry limits new handshakes, not an already authorized console.
            proxy.grants[ticket].expires = 0
            ws.send_bytes(b'still active')
            assert ws.receive_bytes() == b'still active'
            if revocation == 'logout':
                proxy.service.store.sessions.pop('one')
            elif revocation == 'expiry':
                proxy.service.store.sessions['one'] = 0
            else:
                revoked = True
            with pytest.raises(WebSocketDisconnect):
                ws.receive_bytes()
        assert closed.wait(timeout=2)


def test_duplicate_websocket_alias_requires_same_ticket(setup):
    _, app, path, _ = setup
    ticket = path.split('/')[2]
    with TestClient(app, base_url='https://app.example:3001') as client:
        client.cookies.set('ds_session', 'one')
        with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect(
                '/vm-console/' + ticket + '/ws/vm-console/another-ticket/ws',
                headers={'origin': 'https://app.example:3001'}):
            pass
        assert exc.value.code == 4403


def test_unreachable_upstream_has_sanitized_error(setup, monkeypatch):
    _, app, path, _ = setup

    def handler(request):
        raise httpx.ConnectError('private upstream details', request=request)

    mock_http(monkeypatch, handler)
    with TestClient(app, base_url='https://app.example:3001') as client:
        client.cookies.set('ds_session', 'one')
        response = client.get(path)
        assert response.status_code == 502
        assert 'private' not in response.text and 'cpvm' not in response.text


def test_upstream_keepalive_pings_are_disabled(setup, monkeypatch):
    _, app, path, _ = setup
    ticket = path.split('/')[2]
    seen = {}

    class Fake:
        def __init__(self, uri, **kwargs):
            seen.update(kwargs)
            raise OSError('stop')

    monkeypatch.setattr('dirigentenstab.console._NoRedirectConnect', Fake)
    with TestClient(app, base_url='https://app.example:3001') as client:
        client.cookies.set('ds_session', 'one')
        with pytest.raises(WebSocketDisconnect), client.websocket_connect(
                '/vm-console/' + ticket + '/ws', headers={'origin': 'https://app.example:3001'}):
            pass
    assert seen['ping_interval'] is None


def test_static_resources_are_cached_per_origin_and_bounded(setup, monkeypatch):
    proxy, app, path, _ = setup
    requested = []
    status = [200]

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(status[0], content=b'x' * 10, headers={'content-type': 'text/css'})

    mock_http(monkeypatch, handler)
    root = path.split('vnc.html')[0]
    with TestClient(app, base_url='https://app.example:3001') as client:
        client.cookies.set('ds_session', 'one')
        assert client.get(root + 'a.css').content == b'x' * 10
        assert client.get(root + 'a.css').headers['content-type'] == 'text/css'
        assert len(requested) == 1
        status[0] = 404
        assert client.get(root + 'missing.css').status_code == 502
        assert client.get(root + 'missing.css').status_code == 502
        assert len(requested) == 3
        # A grant for another CPVM must not reuse the first origin's entries.
        status[0] = 200
        other = asyncio.run(proxy.open({'userid': 'same-human', '_session': 'one'}, 'vm-2'))
        proxy.grants[other.split('/')[2]].origin = 'http://other-cpvm'
        assert client.get(other.split('vnc.html')[0] + 'a.css').status_code == 200
        assert requested[-1] == 'http://other-cpvm/resource/noVNC/a.css'
        monkeypatch.setattr('dirigentenstab.console.CACHE_BYTES', 25)
        for name in ('b.css', 'c.css', 'd.css'):
            assert client.get(root + name).status_code == 200
        assert sum(len(body) for body, _ in proxy.assets.values()) <= 25


def test_console_session_end_is_logged_without_ticket(setup, monkeypatch, caplog):
    proxy, app, path, _ = setup
    ticket = path.split('/')[2]
    caplog.set_level('INFO', logger='dirigentenstab.console')
    with echo_server() as (port, _, closed), TestClient(app, base_url='https://app.example:3001') as client:
        proxy.grants[ticket].websocket = f'ws://127.0.0.1:{port}/websockify?token=native-secret'
        client.cookies.set('ds_session', 'one')
        with client.websocket_connect('/vm-console/' + ticket + '/ws', headers={'origin': 'https://app.example:3001'},
                                     subprotocols=['binary']) as ws:
            ws.send_bytes(b'12345')
            assert ws.receive_bytes() == b'12345'
        assert closed.wait(timeout=2)
    for _ in range(100):
        if any('session ended' in r.message for r in caplog.records):
            break
        time.sleep(0.02)
    lines = [r.getMessage() for r in caplog.records if 'session ended' in r.message]
    assert len(lines) == 1 and 'client-closed' in lines[0]
    assert [r.levelname for r in caplog.records if 'session ended' in r.message] == ['INFO'] and '5 B up, 5 B down' in lines[0]
    assert 'native-secret' not in caplog.text and ticket not in caplog.text and '127.0.0.1' not in caplog.text


def test_unexpected_console_end_is_logged_as_warning(setup, caplog):
    proxy, app, path, _ = setup
    ticket = path.split('/')[2]
    caplog.set_level('INFO', logger='dirigentenstab.console')

    def drop(socket):
        socket.recv()  # close upstream after the first client message

    with serve(drop, '127.0.0.1', 0, subprotocols=['binary']) as server, \
            TestClient(app, base_url='https://app.example:3001') as client:
        Thread(target=server.serve_forever, daemon=True).start()
        proxy.grants[ticket].websocket = f'ws://127.0.0.1:{server.socket.getsockname()[1]}/websockify?token=t'
        client.cookies.set('ds_session', 'one')
        with client.websocket_connect('/vm-console/' + ticket + '/ws', headers={'origin': 'https://app.example:3001'},
                                     subprotocols=['binary']) as ws:
            ws.send_bytes(b'x')
            for _ in range(100):
                if any('session ended' in r.message for r in caplog.records):
                    break
                time.sleep(0.02)
        server.shutdown()
    ended = [r for r in caplog.records if 'session ended' in r.message]
    assert [(r.levelname, 'upstream-closed' in r.getMessage()) for r in ended] == [('WARNING', True)]
