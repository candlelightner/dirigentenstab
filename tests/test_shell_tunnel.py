import asyncio
from types import SimpleNamespace

import asyncssh
import pytest

from dirigentenstab import shell_tunnel
from dirigentenstab.shell_tunnel import SHELL_TUNNEL_PORT, ShellTunnel


class Conn:
    def __init__(self, gateway='172.30.0.1', bound=None, refuse=False):
        self.gateway, self.refuse, self.commands, self.closed = gateway, refuse, [], asyncio.Event()
        self.bound = f'LISTEN 0 128 {gateway}:{SHELL_TUNNEL_PORT} 0.0.0.0:*\n' if bound is None else bound
        self.listened = None

    async def run(self, command, check=True):
        self.commands.append(command)
        if 'network inspect' in command:
            return SimpleNamespace(returncode=0 if self.gateway else 1, stdout=self.gateway + '\n', stderr='')
        return SimpleNamespace(returncode=0, stdout=self.bound, stderr='')

    async def start_server(self, factory, host, port):
        if self.refuse:
            raise asyncssh.ChannelListenError('no')
        self.listened = (factory, host, port)

    async def wait_closed(self):
        await self.closed.wait()

    def close(self):
        self.closed.set()


def tunnel(conns, host='vm1'):
    service = SimpleNamespace(
        store=SimpleNamespace(one=lambda *a: {'owner_agent': 'root'}), host=host, connects=[],
        vm_address=None, agent=None, ssh_connect=None, agent_shell_host=None)

    async def agent(_):
        return {}

    async def vm_address(_agent, _host):
        return '10.0.0.5', {}

    async def ssh_connect(address, record, **options):
        service.connects.append(options)
        conn = conns.pop(0)
        if isinstance(conn, Exception):
            raise conn
        return conn

    async def agent_shell_host():
        return service.host
    service.agent, service.vm_address, service.ssh_connect, service.agent_shell_host = agent, vm_address, ssh_connect, agent_shell_host
    return service, ShellTunnel(service, interval=0.05)


async def test_forward_listens_on_gateway_and_reports_up():
    conn = Conn()
    service, t = tunnel([conn])
    await t.follow('vm1')
    assert await t.wait_ready(2) == ''
    assert conn.listened[1:] == ('172.30.0.1', SHELL_TUNNEL_PORT) and conn.listened[0]() is shell_tunnel.pipe
    assert service.connects[0]['keepalive_interval'] == 15
    await t.stop()


@pytest.mark.parametrize('conn, message', [
    (Conn(refuse=True), 'sshd refused'),
    (Conn(bound='LISTEN 0 128 127.0.0.1:3901 0.0.0.0:*\n'), 'GatewayPorts clientspecified'),
    (Conn(gateway=''), 'network does not exist'),
    (OSError('no route'), 'no route'),
])
async def test_failures_surface_a_reason_and_keep_retrying(conn, message):
    service, t = tunnel([conn, Conn()])
    await t.follow('vm1')
    assert message in await t.wait_ready(0.5)
    t.retry.set()  # backoff over: the next attempt succeeds
    assert await t.wait_ready(3) == ''
    await t.stop()


async def test_reconnects_after_the_connection_drops():
    first, second = Conn(), Conn()
    service, t = tunnel([first, second])
    await t.follow('vm1')
    assert await t.wait_ready(2) == ''
    first.close()
    await asyncio.sleep(0.1)
    assert not t.up
    assert await t.wait_ready(5) == '' and second.listened


async def test_supervisor_follows_host_changes_and_stops_when_none():
    one, two = Conn(), Conn()
    service, t = tunnel([one, two])
    t.start()
    assert await t.wait_ready(2) == '' and t.host == 'vm1'
    service.host = 'vm2'
    for _ in range(40):
        await asyncio.sleep(0.05)
        if one.closed.is_set() and t.up:
            break
    assert one.closed.is_set() and t.host == 'vm2' and two.listened
    service.host = ''
    await asyncio.sleep(0.2)
    assert two.closed.is_set() and not t.up and t.host == '' and t.worker is None
    await t.stop()


async def test_pipe_relays_to_the_app_listener(monkeypatch):
    async def echo(reader, writer):
        writer.write((await reader.read(100)).upper())
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(echo, '127.0.0.1', 0)
    monkeypatch.setenv('APP_PORT', str(server.sockets[0].getsockname()[1]))
    monkeypatch.delenv('APP_TLS_CERT', raising=False)
    front = await asyncio.start_server(shell_tunnel.pipe, '127.0.0.1', 0)
    reader, writer = await asyncio.open_connection('127.0.0.1', front.sockets[0].getsockname()[1])
    writer.write(b'ping')
    assert await reader.read(100) == b'PING'
    writer.close()
    server.close()
    front.close()
