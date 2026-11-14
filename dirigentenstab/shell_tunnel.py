"""Hub-held reverse SSH forward that lets agent-shell containers reach the hub's MCP endpoint however the hub is exposed.

The hub keeps one SSH connection to the designated shell host and asks sshd to listen on the shell network's gateway
address. Each forwarded connection is handled here and piped to a restricted in-process server (MCP export and /healthz only) on a private unix socket, so containers speak plain
HTTP over the VM-local bridge while SSH carries it to the hub. Per-agent bearer keys still authorize every call.
"""

import asyncio
import logging
import os
import shutil
import tempfile

import asyncssh
import uvicorn
from starlette.responses import PlainTextResponse

SHELL_TUNNEL_PORT = 3901
GATEWAY = "{{(index .IPAM.Config 0).Gateway}}"
log = logging.getLogger(__name__)


class Restricted:
    """Forward only the MCP export and /healthz to the app; everything else (login, UI, websockets) is a 404."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        if scope['type'] == 'http' and (path == '/healthz' or path == '/mcp' or path.startswith('/mcp/')):
            return await self.app(scope, receive, send)
        if scope['type'] == 'http':
            return await PlainTextResponse('Not found', status_code=404)(scope, receive, send)
        if scope['type'] == 'websocket':
            await receive()
            await send({'type': 'websocket.close', 'code': 1008})


class ShellTunnel:
    def __init__(self, service, interval=15):
        self.service, self.interval = service, interval
        self.supervisor = self.worker = self.local = self.socket = None
        self.host, self.up, self.error = '', False, 'not connected yet'
        self.retry = asyncio.Event()

    async def start(self, app):
        """Serve `app` (restricted) on a private unix socket and start following the designated host."""
        if not self.local:
            directory = tempfile.mkdtemp(prefix='dirigentenstab-tunnel-')  # mode 0700
            self.socket = os.path.join(directory, 'app.sock')
            config = uvicorn.Config(Restricted(app), uds=self.socket, lifespan='off', log_level='warning')
            config.load()
            self.local = uvicorn.Server(config)  # startup/shutdown only: serve() would take over the process's signal handlers
            self.local.lifespan = config.lifespan_class(config)
            await self.local.startup()
        if not self.supervisor or self.supervisor.done():
            self.supervisor = asyncio.create_task(self._supervise())

    async def stop(self):
        for task in (self.supervisor, self.worker):
            if task:
                task.cancel()
        self.supervisor = self.worker = None
        self.host, self.up = '', False
        if self.local:
            self.local.should_exit = True
            await self.local.shutdown()
            shutil.rmtree(os.path.dirname(self.socket), ignore_errors=True)
            self.local = self.socket = None

    async def pipe(self, reader, writer):
        """Relay one forwarded connection to the restricted local server."""
        try:
            upstream_reader, upstream_writer = await asyncio.open_unix_connection(self.socket)
        except OSError:
            writer.close()
            return

        async def copy(source, target):
            try:
                while data := await source.read(65536):
                    target.write(data)
                    await target.drain()
            except (OSError, asyncssh.Error):
                pass
            finally:
                target.close()
        await asyncio.gather(copy(reader, upstream_writer), copy(upstream_reader, writer))

    async def follow(self, host):
        """Hold the tunnel to `host` (restart when it changes or died); stop when empty."""
        if host == self.host and (not host or (self.worker and not self.worker.done())):
            return
        if self.worker:
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)
        self.host, self.up, self.error, self.worker = host, False, 'not connected yet', None
        if host:
            self.retry.set()
            self.worker = asyncio.create_task(self._hold(host))

    async def wait_ready(self, seconds=10):
        """'' once the tunnel is up, else the last reason, after waiting up to `seconds`."""
        self.retry.set()
        for _ in range(int(seconds * 5)):
            if self.up:
                return ''
            await asyncio.sleep(0.2)
        return self.error

    async def _supervise(self):
        while True:
            try:
                await self.follow(await self.service.agent_shell_host())
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # ambiguous or unresolvable designation: no tunnel until it is settled
                log.warning('Shell tunnel host lookup failed: %s', exc)
                await self.follow('')
            await asyncio.sleep(self.interval)

    async def _hold(self, host):
        delay = 2
        while True:
            try:
                await self._serve(host)
                self.error, delay = 'the SSH connection to the shell host closed', 2
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.error = (str(exc) or type(exc).__name__)[:200]
                log.warning('Shell tunnel: %s', self.error)
            self.up = False
            self.retry.clear()
            try:
                await asyncio.wait_for(self.retry.wait(), delay)
            except TimeoutError:
                pass
            delay = min(delay * 2, 30)

    async def _serve(self, host):
        record = self.service.store.one('SELECT * FROM vm_access WHERE vm_id=?', (host,))
        if not record:
            raise RuntimeError('the shell host has no managed SSH access')
        from .service import SHELL_NETWORK
        address, _ = await self.service.vm_address(await self.service.agent(record['owner_agent']), host)
        conn = await self.service.ssh_connect(address, record, keepalive_interval=15, keepalive_count_max=3)
        try:
            found = await conn.run(f"sudo -n docker network inspect -f '{GATEWAY}' {SHELL_NETWORK}", check=False)
            gateway = found.stdout.strip()
            if found.returncode or not gateway:
                raise RuntimeError('the shell network does not exist')
            try:
                await conn.start_server(lambda *_: self.pipe, gateway, SHELL_TUNNEL_PORT)
            except asyncssh.ChannelListenError:
                raise RuntimeError(f'sshd refused to listen on {gateway}:{SHELL_TUNNEL_PORT}') from None
            bound = await conn.run(f"ss -H -ltn 'sport = :{SHELL_TUNNEL_PORT}'", check=False)
            if not bound.returncode and gateway not in bound.stdout:
                raise RuntimeError('sshd did not listen on the shell network gateway (GatewayPorts clientspecified missing)')
            self.up, self.error = True, ''
            await conn.wait_closed()
        finally:
            conn.close()
