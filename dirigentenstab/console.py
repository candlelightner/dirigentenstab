"""Session-bound transport for CloudStack's native noVNC console."""
import asyncio
from contextlib import suppress
from dataclasses import dataclass
import logging
import secrets
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from .auth import Auth

PREFIX = '/vm-console/'
RESOURCE = '/resource/noVNC/'
SESSION_POLL_SECONDS = 1
NATIVE_POLL_SECONDS = 30
CACHE_BYTES = 32 * 1024 * 1024
CACHE_ENTRIES = 256
logger = logging.getLogger('dirigentenstab.console')


class _NoRedirectConnect(connect):
    def process_redirect(self, exc):
        return exc  # A native ticket must never be forwarded to another target.


@dataclass
class _Grant:
    session: str
    expires: float
    origin: str
    websocket: str


class ConsoleProxy:
    def __init__(self, service):
        self.service = service
        self.auth = Auth(service)
        self.grants = {}
        self.assets = {}  # (CPVM origin, resource) -> (body, content type); static noVNC files only

    async def open(self, identity, vm_id):
        session = identity.get('_session')
        if not session or not self._session_alive(session):
            raise PermissionError('Session expired')
        native = urlsplit(await self.service.vm_console_url(identity, vm_id))
        # noVNC uses decodeURIComponent: literal '+' in native encrypted tickets is not a space.
        query = parse_qs(native.query.replace('+', '%2B'), keep_blank_values=True, max_num_fields=32)
        if (native.scheme not in {'http', 'https'} or not native.hostname or native.username or native.password
                or native.path != RESOURCE + 'vnc.html' or native.fragment
                or any(c.isspace() or ord(c) < 32 for c in native.netloc) or '\\' in native.netloc):
            raise ValueError('Unsupported native console endpoint')
        host = query.get('host', [native.hostname])[-1]
        port = query.get('port', ['443' if native.scheme == 'https' else '80'])[-1]
        path = query.get('path', ['websockify'])[-1]
        token = query.get('token', [''])[-1]
        if host != native.hostname or not port.isascii() or not port.isdecimal() or not 0 < int(port) < 65536 or path != 'websockify' or not token:
            raise ValueError('Unsupported native console transport')
        ws_query = {'token': token}
        if 'extra' in query:
            ws_query['extra'] = query['extra'][-1]
        ws_scheme = 'wss' if query.get('encrypt', ['1' if native.scheme == 'https' else '0'])[-1].lower() in {'1', 'true'} else 'ws'
        ws_host = '[' + host + ']' if ':' in host else host
        # CPVM consumes the Base64 ticket literally, as noVNC appends it (including '+', '/', '=').
        upstream = urlunsplit((ws_scheme, f'{ws_host}:{port}', '/websockify',
                               urlencode(ws_query, quote_via=quote, safe='+/='), ''))
        now = time.time()
        self.grants = {key: grant for key, grant in self.grants.items() if grant.expires > now}
        if len(self.grants) >= 256:
            raise ValueError('Too many open console tickets; retry shortly')
        ticket = secrets.token_urlsafe(32)
        self.grants[ticket] = _Grant(session, now + 300, urlunsplit((native.scheme, native.netloc, '', '', '')), upstream)
        public = urlsplit(self.service.settings.origin)
        local_query = {key: query[key][-1] for key in ('autoconnect', 'show_dot') if key in query}
        local_query.update(host=public.hostname, port=str(public.port or 443), encrypt='1',
                           path=PREFIX.lstrip('/') + ticket + '/ws', token=ticket)
        return PREFIX + ticket + '/vnc.html?' + urlencode(local_query)

    def _session_alive(self, session):
        return bool(self.service.store.one('SELECT 1 FROM sessions WHERE token_hash=? AND expires>?',
                                           (session, time.time())))

    def _grant(self, scope, ticket):
        grant = self.grants.get(ticket)
        session = scope.get('ds_identity', {}).get('_session')
        if not grant or grant.expires <= time.time():
            self.grants.pop(ticket, None)
            raise PermissionError('Console ticket expired')
        if not session or session != grant.session or not self._session_alive(session):
            raise PermissionError('Console session mismatch')
        return grant

    @staticmethod
    def _asset(body, content_type):
        return Response(body, headers={'content-type': content_type, 'referrer-policy': 'no-referrer'})

    def install(self, app):
        """Install behind the application's existing SessionGuard middleware."""
        @app.api_route(PREFIX + '{ticket}/{resource:path}', methods=['GET', 'HEAD'])
        async def resource(request: Request, ticket: str, resource: str):
            try:
                grant = self._grant(request.scope, ticket)
            except PermissionError:
                raise HTTPException(403, 'Console ticket unavailable') from None
            # ASGI has already decoded once; reject residual escapes rather than decoding twice.
            if (not resource or any(part in {'', '.', '..'} for part in resource.split('/'))
                    or any(c in resource for c in '\\%?#:') or any(ord(c) < 32 for c in resource)):
                raise HTTPException(404, 'Console resource unavailable')
            key = (grant.origin, resource)
            if request.method == 'GET' and key in self.assets:
                return self._asset(*self.assets[key])
            try:
                async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
                    async with client.stream(request.method, grant.origin + RESOURCE + resource) as upstream:
                        if upstream.status_code != 200:
                            raise HTTPException(502, 'Console resource unavailable')
                        body = bytearray()
                        async for chunk in upstream.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > 8 * 1024 * 1024:
                                raise HTTPException(502, 'Console resource too large')
                        asset = bytes(body), upstream.headers.get('content-type', 'application/octet-stream')
                        if request.method == 'GET':
                            self.assets[key] = asset
                            while len(self.assets) > CACHE_ENTRIES or sum(len(a[0]) for a in self.assets.values()) > CACHE_BYTES:
                                del self.assets[next(iter(self.assets))]
                        return self._asset(*asset)
            except httpx.HTTPError:
                raise HTTPException(502, 'Console upstream unavailable') from None

        # CloudStack's bundled ui.js appends its path twice; accept only the exact repeated ticket.
        @app.websocket(PREFIX + '{ticket}/ws/vm-console/{duplicate_ticket}/ws')
        @app.websocket(PREFIX + '{ticket}/ws')
        async def websocket(socket: WebSocket, ticket: str, duplicate_ticket: str = ''):
            try:
                if duplicate_ticket and duplicate_ticket != ticket:
                    raise PermissionError('Console ticket mismatch')
                grant = self._grant(socket.scope, ticket)
            except PermissionError:
                await socket.close(code=4403)
                return
            tasks = []
            upstream = None
            reason = 'error'
            started = time.monotonic()
            sent = [0, 0]  # bytes client->upstream, upstream->client
            try:
                offered = socket.scope.get('subprotocols', [])
                protocols = ['binary'] if 'binary' in offered else None
                async with _NoRedirectConnect(grant.websocket, origin=grant.origin, subprotocols=protocols,
                                              proxy=None, compression=None, open_timeout=10,
                                              ping_interval=None,  # CPVM does not answer pings; VNC traffic and watch_session show liveness

                                              close_timeout=2, max_size=16 * 1024 * 1024) as upstream:
                    await socket.accept(subprotocol=upstream.subprotocol)

                    async def incoming():
                        while True:
                            message = await socket.receive()
                            if message['type'] == 'websocket.disconnect':
                                return
                            data = message['bytes'] if message.get('bytes') is not None else message['text']
                            sent[0] += len(data)
                            await upstream.send(data)

                    async def outgoing():
                        async for message in upstream:
                            sent[1] += len(message)
                            if isinstance(message, bytes):
                                await socket.send_bytes(message)
                            else:
                                await socket.send_text(message)

                    async def watch_session():
                        next_native_check = time.monotonic() + NATIVE_POLL_SECONDS
                        while True:
                            await asyncio.sleep(SESSION_POLL_SECONDS)
                            if not self._session_alive(grant.session):
                                return
                            if time.monotonic() >= next_native_check:
                                await self.auth.identity_from_session(grant.session)
                                next_native_check = time.monotonic() + NATIVE_POLL_SECONDS

                    tasks = [asyncio.create_task(work()) for work in (incoming, outgoing, watch_session)]
                    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    reason = ('client-closed', 'upstream-closed', 'session-ended')[min(tasks.index(t) for t in done)]
                    for task in done:
                        task.result()
            except (OSError, TimeoutError, WebSocketException, WebSocketDisconnect, PermissionError, httpx.HTTPError) as exc:
                reason = ('upstream-closed' if isinstance(exc, ConnectionClosed) else
                          'client-closed' if isinstance(exc, WebSocketDisconnect) else 'error ' + type(exc).__name__)
                # Do not expose ticketed upstream URLs in errors sent to the client.
            finally:
                logger.info('console session ended: %s, upstream close %s %r, %.1f s, %d B up, %d B down',
                            reason, getattr(upstream, 'close_code', None), getattr(upstream, 'close_reason', ''),
                            time.monotonic() - started, *sent)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                with suppress(RuntimeError, WebSocketDisconnect):
                    await socket.close(code=1000)
