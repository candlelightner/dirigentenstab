"""Session-bound transport for CloudStack's native noVNC console."""
import asyncio
from contextlib import suppress
from dataclasses import dataclass
import secrets
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from .auth import Auth

PREFIX = '/vm-console/'
RESOURCE = '/resource/noVNC/'
SESSION_POLL_SECONDS = 1
NATIVE_POLL_SECONDS = 30


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
                        return Response(bytes(body), headers={
                            'content-type': upstream.headers.get('content-type', 'application/octet-stream'),
                            'referrer-policy': 'no-referrer',
                        })
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
            try:
                offered = socket.scope.get('subprotocols', [])
                protocols = ['binary'] if 'binary' in offered else None
                async with _NoRedirectConnect(grant.websocket, origin=grant.origin, subprotocols=protocols,
                                              proxy=None, compression=None, open_timeout=10,
                                              close_timeout=2, max_size=16 * 1024 * 1024) as upstream:
                    await socket.accept(subprotocol=upstream.subprotocol)

                    async def incoming():
                        while True:
                            message = await socket.receive()
                            if message['type'] == 'websocket.disconnect':
                                return
                            await upstream.send(message['bytes'] if message.get('bytes') is not None else message['text'])

                    async def outgoing():
                        async for message in upstream:
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
                    for task in done:
                        task.result()
            except (OSError, TimeoutError, WebSocketException, WebSocketDisconnect, PermissionError, httpx.HTTPError):
                pass  # Do not expose ticketed upstream URLs in errors sent to the client.
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                with suppress(RuntimeError, WebSocketDisconnect):
                    await socket.close(code=1000)
