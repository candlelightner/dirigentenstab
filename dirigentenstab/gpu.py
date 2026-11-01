"""GPU policy semantics and the private, backend-only host-controller transport."""
import asyncio
from contextvars import ContextVar
import hashlib
import json
import socket
import struct
from .diagnostics import OperationError
from .cloud import CloudError

GPU_CONTEXT = ContextVar('gpu_context', default=None)
GPU_COMMANDS = frozenset({'deployVirtualMachine', 'startVirtualMachine', 'stopVirtualMachine',
                         'rebootVirtualMachine', 'destroyVirtualMachine', 'recoverVirtualMachine',
                         'restoreVirtualMachine', 'scaleVirtualMachine', 'changeServiceForVirtualMachine'})
FLAGS = ('release_on_stop', 'reconfigure_unused', 'subgroup_requests')
FLAG_LABELS = {'release_on_stop': 'Release GPU when its VM stops', 'reconfigure_unused': 'May switch unused GPU sizes',
               'subgroup_requests': 'GPU capacity requests'}


def validate_policy(value, available):
    if set(value) != {'profiles', 'max_allocations', *FLAGS}:
        raise ValueError('Specify every GPU policy permission explicitly')
    if (not isinstance(value['profiles'], list) or not set(value['profiles']) <= set(available)
            or type(value['max_allocations']) is not int or value['max_allocations'] < -1
            or any(type(value[flag]) is not bool for flag in FLAGS)):
        raise ValueError('Invalid GPU policy permissions or native quota')
    return value


def effective_policy(chain, policies):
    """Every ancestor is authoritative; missing documents and missing fields deny access."""
    effective = {'profiles': None, 'max_allocations': -1, **{flag: True for flag in FLAGS}}
    for domain in chain:
        policy = policies.get(domain['id'], {})
        profiles = set(policy.get('profiles', []))
        effective['profiles'] = profiles if effective['profiles'] is None else effective['profiles'] & profiles
        maximum = policy.get('max_allocations', 0)
        if maximum >= 0:
            effective['max_allocations'] = maximum if effective['max_allocations'] < 0 else min(effective['max_allocations'], maximum)
        for flag in FLAGS:
            effective[flag] &= policy.get(flag) is True
    if not chain:
        return {'profiles': set(), 'max_allocations': 0, **{flag: False for flag in FLAGS}}
    return effective


def narrows(policy, parent):
    return (set(policy['profiles']) <= parent['profiles'] and
            all(not policy[flag] or parent[flag] for flag in FLAGS) and
            (parent['max_allocations'] < 0 or 0 <= policy['max_allocations'] <= parent['max_allocations']))


def policy_gain(old, new, names):
    """What `new` allows beyond `old`: profile names, a larger max (-1 = unlimited) and newly enabled flags."""
    before, after = old['max_allocations'], new['max_allocations']
    return {'profiles': sorted(names.get(p, p) for p in set(new['profiles']) - set(old['profiles'])),
            'max': [before, after] if before != -1 and (after == -1 or after > before) else None,
            'flags': [flag for flag in FLAGS if new[flag] and not old[flag]]}


def describe_plan(plan):
    """Plain-text lines for the ancestors a policy change widens and the policies that become more effective."""
    def line(item):
        parts = ['allow ' + ', '.join(item['profiles'])] if item['profiles'] else []
        parts += [f"max {item['max'][0]} to {item['max'][1]}"] if item['max'] else []
        parts += [f"enable \"{FLAG_LABELS[flag]}\"" for flag in item['flags']]
        return f"{item['name']}: " + '; '.join(parts)
    return ([line(item) for item in plan['changes']]
            + ['Also becomes more effective for ' + line(item) for item in plan['activated']])


async def helper_call(settings, action, **payload):
    path = getattr(settings, 'gpu_helper_socket', '')
    if not path:
        raise PermissionError('Host GPU preparation requires the platform GPU controller and an explicit operator policy')
    request = {'action': action, **payload}
    data = json.dumps(request).encode() + b'\n'
    if len(data) > 65536:
        raise ValueError('GPU request exceeds its size limit')
    try:
        async with asyncio.timeout(720):
            reader, writer = await asyncio.open_unix_connection(path, limit=1048576)
            try:
                peer = struct.unpack('3i', writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                if peer != 0:
                    raise PermissionError('GPU controller peer is not the trusted root service')
                writer.write(data)
                await writer.drain()
                result = json.loads(await reader.readline())
            finally:
                writer.close()
                await writer.wait_closed()
    except PermissionError:
        raise
    except (OSError, TimeoutError):
        raise RuntimeError('GPU controller unavailable or operation interrupted; inspect its durable operation before retrying') from None
    if result.get('error'):
        if result.get('reconciliation'):
            raise OperationError('gpu', result['error'], (payload.get('context') or {}).get('run_id', 'gpu'),
                                 reconciliation=True)
        if result.get('cloudstack'):
            raise CloudError(result['error'], rejected=result.get('rejected') is True,
                             operation_id=result.get('operation_id'), public_detail=result.get('public_detail'))
        raise PermissionError(result['error']) if result.get('denied') else RuntimeError(result['error'])
    return result['result']


def operation_id(context):
    return hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()[:32]
