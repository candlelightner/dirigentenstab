#!/usr/bin/env python3
"""Socket-activated human-operated GPU host controller; native VM calls keep the agent identity."""
import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
import socket
import struct

from admin import service
from dirigentenstab.diagnostics import diagnose
from dirigentenstab.gpu_control import Controller, Journal, NativeHost
from dirigentenstab.gpu import operation_id


async def main():
    if os.geteuid() != 0 or int(os.getenv('LISTEN_FDS', '0')) != 1:
        raise SystemExit('Start through dirigentenstab-gpu.socket as the platform administrator')
    config = json.loads(await asyncio.to_thread(Path('/var/lib/dirigentenstab/setup/gpu-controller.json').read_text))
    app = service()
    credentials = json.loads(await asyncio.to_thread(Path('/var/lib/dirigentenstab/setup/cloudstack-admin.json').read_text))
    cloud = app.client({k: credentials[k] for k in ('apikey', 'secretkey')})
    controller = Controller(app, cloud, Journal('/var/lib/dirigentenstab/gpu-control.db'),
                            NativeHost(config['parent']), config['host_id'])

    async def connection(reader, writer):
        peer = struct.unpack('3i', writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        request = {}
        try:
            async with asyncio.timeout(10):
                data = await reader.readline()
            if not data:
                writer.close()
                return
            if len(data) > 65536:
                raise ValueError('GPU controller request too large')
            request = json.loads(data)
            async with asyncio.timeout(660):
                result = await controller.dispatch(request, peer)
            response = {'result': result}
        except Exception as exc:
            error = diagnose(exc, operation_id=(request.get('context') or {}).get('run_id'),
                             agent_id=request.get('agent_id'), tool='gpu-controller')
            safe = str(exc) if isinstance(exc, (PermissionError, ValueError)) else str(error)
            response = {'error': safe, 'denied': isinstance(exc, PermissionError)}
            if request.get('context'):
                rows = controller.journal.rows('SELECT phase,changed FROM operations WHERE id=?',
                                               (operation_id(request['context']),))
                if rows and rows[0]['phase'] in {'preparing', 'dispatching', 'reconciliation'}:
                    response['reconciliation'] = bool(rows[0]['changed'] or rows[0]['phase'] != 'preparing')
        try:
            writer.write(json.dumps(response).encode() + b'\n')
            await writer.drain()
        except (ConnectionError, OSError):
            pass  # The durable journal retains outcomes after a disconnected UI/backend.
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

    listener = socket.socket(fileno=3)
    async with await asyncio.start_unix_server(connection, sock=listener, limit=65537) as server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
