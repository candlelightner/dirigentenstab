import asyncio
import hashlib
import hmac
import inspect
import logging
import secrets
import time
from urllib.parse import parse_qs

import httpx
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.datastructures import Headers

from .cloud import CloudError

COOKIE = 'ds_session'
NATIVE_POLL_SECONDS = 30
# CloudStack idles out its own login session after 30 minutes without calls, and a sleeping phone sends none,
# so the server touches every live session this often to keep the wrapped CloudStack session alive.
KEEPALIVE_SECONDS = 300
# During a transient CloudStack outage a session last verified within this window is let through unchanged;
# beyond it requests fail with a retryable error. The session itself is never deleted for a transient error.
# At least two keepalive periods, so a tab woken just after one failed keepalive still has a full period of grace.
TRANSIENT_GRACE_SECONDS = 900
# Failed logins per user per 15 minutes, and across all users. The client IP is not used: behind tailscale serve
# and the docker proxy every client shares one gateway address.
USER_LOGIN_ATTEMPTS, GLOBAL_LOGIN_ATTEMPTS = 8, 40
RETRY_PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Dirigentenstab</title></head>
<body style="font:16px system-ui,sans-serif;margin:2rem"><h1>CloudStack unreachable, retrying</h1>
<p role="status">You are still signed in. This page reloads every few seconds.</p></body></html>'''


def transient(exc):
    """True for CloudStack outages (unreachable, timeout, 5xx), which never end a session."""
    return isinstance(exc, httpx.HTTPError) or isinstance(exc, CloudError) and not exc.rejected


class Auth:
    def __init__(self, service):
        self.service, self.store = service, service.store
        self.verified = {}  # session hash -> monotonic time of the last successful native revalidation

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    async def login(self, username, password, domain):
        now = time.time()
        buckets = [self.digest(bucket) for bucket in ('all', 'user:' + domain + '/' + username)]
        with self.store.connect() as conn:
            conn.execute('DELETE FROM login_attempts WHERE created<?', (now - 900,))
            for bucket, limit in zip(buckets, (GLOBAL_LOGIN_ATTEMPTS, USER_LOGIN_ATTEMPTS), strict=True):
                if conn.execute('SELECT COUNT(*) FROM login_attempts WHERE bucket=?', (bucket,)).fetchone()[0] >= limit:
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
        self.store.execute('DELETE FROM login_attempts WHERE bucket=?', (buckets[1],))
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
        return await self.identity_from_session(self.digest(token))

    async def identity_from_session(self, hashed, fresh=False):
        session = self.store.one('SELECT * FROM sessions WHERE token_hash=? AND expires>?', (hashed, time.time()))
        if not session:
            raise PermissionError('Session expired')
        private = self.store.open(session['identity'])
        identity = {key: private.get(key) for key in ('userid', 'username', 'domainid', 'account', 'type')}
        identity.update(csrf=session['csrf'], _session=hashed)
        now = time.monotonic()
        if not fresh and now - self.verified.get(hashed, -NATIVE_POLL_SECONDS) < NATIVE_POLL_SECONDS:
            return identity
        self.verified = {k: t for k, t in self.verified.items() if now - t < TRANSIENT_GRACE_SECONDS}
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
        except (PermissionError, CloudError, httpx.HTTPError) as exc:
            if transient(exc):
                # Transient (unreachable, timeout, 5xx): keep the session; do not refresh `verified`.
                if now - self.verified.get(hashed, -TRANSIENT_GRACE_SECONDS) < TRANSIENT_GRACE_SECONDS:
                    return identity
                raise CloudError('CloudStack temporarily unreachable') from None
            self.store.execute('DELETE FROM sessions WHERE token_hash=?', (hashed,))
            if hasattr(self.service, 'close_user_terminal_sessions') and identity.get('userid'):
                self.service.close_user_terminal_sessions(identity['userid'])
            raise PermissionError('CloudStack session no longer valid') from None
        self.verified[hashed] = now
        return identity

    async def keepalive(self):
        """Revalidate every live session once; this also keeps its CloudStack session from idling out."""
        for row in self.store.all('SELECT token_hash FROM sessions WHERE expires>?', (time.time(),)):
            try:
                await self.identity_from_session(row['token_hash'], fresh=True)
            except (PermissionError, CloudError, httpx.HTTPError) as exc:
                logging.getLogger(__name__).warning('Session keepalive failed: %s', type(exc).__name__)
            except Exception:
                logging.getLogger(__name__).exception('Session keepalive crashed')

    async def keepalive_periodically(self, interval=KEEPALIVE_SECONDS):
        while True:
            await asyncio.sleep(interval)
            await self.keepalive()

    def csrf(self, token, value):
        session = self.store.one('SELECT csrf FROM sessions WHERE token_hash=? AND expires>?',
                                 (self.digest(token), time.time()))
        if not session or not value or not hmac.compare_digest(session['csrf'], value):
            raise PermissionError('Invalid CSRF token')

    async def revoke(self, token):
        hashed = self.digest(token)
        session = self.store.one('SELECT identity FROM sessions WHERE token_hash=?', (hashed,))
        self.store.execute('DELETE FROM sessions WHERE token_hash=?', (hashed,))
        self.verified.pop(hashed, None)
        if session:
            private = self.store.open(session['identity'])
            if hasattr(self.service, 'close_user_terminal_sessions') and private.get('userid'):
                self.service.close_user_terminal_sessions(private['userid'])
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
            except (PermissionError, CloudError, httpx.HTTPError) as exc:
                landing = scope['type'] == 'http' and path == '/' and scope.get('method') == 'GET'
                if transient(exc):
                    if landing:
                        return await HTMLResponse(RETRY_PAGE, status_code=503, headers={'Retry-After': '5'})(
                            scope, receive, send)
                    return await self.reject(scope, receive, send, 503)
                if landing:
                    return await RedirectResponse('/login', status_code=303)(scope, receive, send)
                return await self.reject(scope, receive, send, 401)
        async def secure_send(message):
            if message['type'] == 'http.response.start':
                message.setdefault('headers', []).extend([
                    (b'cache-control', b'no-store'), (b'x-content-type-options', b'nosniff'),
                    (b'referrer-policy', b'same-origin'),
                    (b'x-frame-options', b'SAMEORIGIN' if path.startswith('/vm-console/') else b'DENY'),
                    (b'permissions-policy', b'camera=(), microphone=(), geolocation=()'),
                ])
            await send(message)
        await self.app(scope, receive, secure_send)

    @staticmethod
    async def reject(scope, receive, send, status):
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': {401: 4401, 503: 1013}.get(status, 4403)})
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
                                        form.get('domain', '/'))
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
