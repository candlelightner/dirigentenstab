import hashlib
import hmac
import inspect
import secrets
import time
from urllib.parse import parse_qs

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.datastructures import Headers

COOKIE = 'ds_session'


class Auth:
    def __init__(self, service):
        self.service, self.store = service, service.store

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    async def login(self, username, password, domain, client_ip):
        now = time.time()
        buckets = ['ip:' + client_ip, 'user:' + domain + '/' + username]
        buckets = [self.digest(bucket) for bucket in buckets]
        with self.store.connect() as conn:
            conn.execute('DELETE FROM login_attempts WHERE created<?', (now - 900,))
            for bucket in buckets:
                if conn.execute('SELECT COUNT(*) FROM login_attempts WHERE bucket=?', (bucket,)).fetchone()[0] >= 8:
                    raise PermissionError('Too many login attempts; retry in 15 minutes')
            conn.executemany('INSERT INTO login_attempts(bucket,created) VALUES(?,?)', [(b, now) for b in buckets])
        if not username or not password or len(username) > 255 or len(password) > 4096 or len(domain) > 1024:
            raise PermissionError('Invalid login')
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            response = await client.post(self.service.settings.cloudstack_url,
                                         data={'command': 'login', 'username': username, 'password': password,
                                               'domain': domain or '/', 'response': 'json'})
            try:
                private = response.json()['loginresponse']
                if response.is_error or not private.get('sessionkey') or not private.get('userid'):
                    raise PermissionError('Invalid CloudStack login')
                private['cookies'] = dict(client.cookies)
                private['type'] = int(private['type'])
            except (KeyError, ValueError, TypeError):
                raise PermissionError('Invalid CloudStack login') from None
        if private['type'] not in {1, 2}:
            raise PermissionError('Use a CloudStack root or domain administrator account')
        self.store.execute('DELETE FROM login_attempts WHERE bucket IN (?,?)', tuple(buckets))
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.store.execute('DELETE FROM sessions WHERE expires<?', (now,))
        self.store.execute('INSERT INTO sessions(token_hash,csrf,identity,expires) VALUES(?,?,?,?)',
                           (self.digest(token), csrf, self.store.seal(private),
                            now + self.service.settings.session_seconds))
        self.store.audit(private['userid'], 'login')
        return token, csrf

    async def identity(self, token):
        if not token or len(token) > 100:
            raise PermissionError('Login required')
        hashed = self.digest(token)
        session = self.store.one('SELECT * FROM sessions WHERE token_hash=? AND expires>?', (hashed, time.time()))
        if not session:
            raise PermissionError('Session expired')
        private = self.store.open(session['identity'])
        identity = {key: private.get(key) for key in ('userid', 'username', 'domainid', 'account', 'type')}
        identity.update(csrf=session['csrf'], _session=hashed)
        try:
            users = await self.service.human_call(identity, 'listUsers', {'id': identity['userid']})
            user = next((u for u in users.get('user', []) if u['id'] == identity['userid']), None)
            accounts = await self.service.human_call(identity, 'listAccounts',
                                                      {'name': identity['account'], 'domainid': identity['domainid']})
            account = next((a for a in accounts.get('account', []) if a['name'] == identity['account']
                            and a['domainid'] == identity['domainid']), None)
            if not user or user.get('state') != 'enabled' or not account or account.get('state') != 'enabled':
                raise PermissionError('CloudStack account disabled or revoked')
            if int(account.get('accounttype', -1)) != identity['type']:
                raise PermissionError('CloudStack role changed; log in again')
        except (PermissionError, httpx.HTTPError):
            self.store.execute('DELETE FROM sessions WHERE token_hash=?', (hashed,))
            raise PermissionError('CloudStack session no longer valid') from None
        return identity

    def csrf(self, token, value):
        session = self.store.one('SELECT csrf FROM sessions WHERE token_hash=? AND expires>?',
                                 (self.digest(token), time.time()))
        if not session or not value or not hmac.compare_digest(session['csrf'], value):
            raise PermissionError('Invalid CSRF token')

    async def revoke(self, token):
        hashed = self.digest(token)
        session = self.store.one('SELECT identity FROM sessions WHERE token_hash=?', (hashed,))
        self.store.execute('DELETE FROM sessions WHERE token_hash=?', (hashed,))
        if session:
            private = self.store.open(session['identity'])
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    await client.post(self.service.settings.cloudstack_url,
                                      data={'command': 'logout', 'response': 'json', 'sessionkey': private['sessionkey']},
                                      cookies=private['cookies'])
            except httpx.HTTPError:
                pass  # Local revocation remains effective if CloudStack is unavailable.
            self.store.audit(private['userid'], 'logout')


class SessionGuard:
    def __init__(self, app, auth, origin):
        self.app, self.auth, self.origin = app, auth, origin

    async def __call__(self, scope, receive, send):
        if scope['type'] not in {'http', 'websocket'}:
            return await self.app(scope, receive, send)
        request = Request({**scope, 'type': 'http'})
        path = scope['path']
        public = path in {'/login', '/auth/login', '/healthz'}
        headers = Headers(scope=scope)
        unsafe = scope['type'] == 'websocket' or scope.get('method') not in {'GET', 'HEAD', 'OPTIONS'}
        if unsafe and headers.get('origin') != self.origin:
            return await self.reject(scope, receive, send, 403)
        if not public:
            try:
                scope['ds_identity'] = await self.auth.identity(request.cookies.get(COOKIE))
            except (PermissionError, httpx.HTTPError):
                if scope['type'] == 'http' and path == '/' and scope.get('method') == 'GET':
                    return await RedirectResponse('/login', status_code=303)(scope, receive, send)
                return await self.reject(scope, receive, send, 401)
        async def secure_send(message):
            if message['type'] == 'http.response.start':
                message.setdefault('headers', []).extend([
                    (b'cache-control', b'no-store'), (b'x-content-type-options', b'nosniff'),
                    (b'referrer-policy', b'same-origin'), (b'x-frame-options', b'DENY'),
                    (b'permissions-policy', b'camera=(), microphone=(), geolocation=()'),
                ])
            await send(message)
        await self.app(scope, receive, secure_send)

    @staticmethod
    async def reject(scope, receive, send, status):
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 4401 if status == 401 else 4403})
        else:
            await JSONResponse({'detail': 'Authentication or origin verification failed'}, status_code=status)(
                scope, receive, send)


def attach(app, auth, settings):
    app.add_middleware(SessionGuard, auth=auth, origin=settings.origin)
    bind_sockets(auth)

    async def fields(request):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 8192:
                raise ValueError('Form too large')
        return {key: values[-1] for key, values in parse_qs(body.decode(), max_num_fields=8).items()}

    @app.post('/auth/login')
    async def login(request: Request):
        try:
            form = await fields(request)
            token, _ = await auth.login(form.get('username', ''), form.get('password', ''),
                                        form.get('domain', '/'), request.client.host)
            old = request.cookies.get(COOKIE)
            if old:
                await auth.revoke(old)
            response = RedirectResponse('/', status_code=303)
            response.set_cookie(COOKIE, token, httponly=True, secure=True, samesite='strict',
                                max_age=settings.session_seconds, path='/')
            return response
        except (PermissionError, httpx.HTTPError, ValueError):
            return RedirectResponse('/login?failed=1', status_code=303)

    @app.post('/auth/logout')
    async def logout(request: Request):
        try:
            form = await fields(request)
            token = request.cookies.get(COOKIE, '')
            auth.csrf(token, form.get('csrf', ''))
            await auth.revoke(token)
        except (PermissionError, ValueError):
            return JSONResponse({'detail': 'Invalid logout request'}, status_code=403)
        response = RedirectResponse('/login', status_code=303)
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite='strict')
        return response

    @app.get('/healthz')
    async def health():
        auth.store.one('SELECT 1')
        return {'status': 'ok'}


def bind_sockets(auth):
    """Bind NiceGUI's client IDs to authenticated sessions, including every inbound event."""
    from nicegui import core
    from nicegui.client import Client

    original_connect = core.sio.handlers['/']['connect']

    async def connect(sid, environ, data=None):
        query = parse_qs(environ.get('QUERY_STRING', ''), max_num_fields=20)
        client_id = query.get('client_id', [''])[0]
        client = Client.instances.get(client_id)
        sender = environ.get('asgi.scope', {}).get('ds_identity', {}).get('_session')
        owner = client.request.scope.get('ds_identity', {}).get('_session') if client and client.request else None
        if not sender or sender != owner:
            return False
        if not auth.store.one('SELECT 1 FROM sessions WHERE token_hash=? AND expires>?', (sender, time.time())):
            return False
        result = original_connect(sid, environ, data)
        return await result if inspect.isawaitable(result) else result
    core.sio.on('connect', handler=connect)

    for name in ('handshake', 'event', 'javascript_response', 'ack', 'log'):
        original = core.sio.handlers['/'][name]

        def bind(handler, handshake):
            async def guarded(sid, message):
                if not isinstance(message, dict):
                    return False
                client = Client.instances.get(message.get('client_id'))
                environ = core.sio.get_environ(sid)
                scope = environ.get('asgi.scope', {}) if environ else {}
                sender = scope.get('ds_identity', {}).get('_session')
                owner = client.request.scope.get('ds_identity', {}).get('_session') if client and client.request else None
                if not sender or sender != owner:
                    return False
                if not auth.store.one('SELECT 1 FROM sessions WHERE token_hash=? AND expires>?', (sender, time.time())):
                    return False
                if not handshake and sid not in client._socket_to_document_id:
                    return False
                result = handler(sid, message)
                return await result if inspect.isawaitable(result) else result
            return guarded
        core.sio.on(name, handler=bind(original, name == 'handshake'))
