"""Validated deployment network values; usable before Python dependencies are installed."""
import ipaddress
import os
from pathlib import Path
import re
import shlex

DEFAULTS = {
    'CLOUDSTACK_BRIDGE': 'dscloud0',
    'CLOUDSTACK_NETWORK': '10.253.80.0/24',
    'CLOUDSTACK_GATEWAY': '10.253.80.1',
    'CLOUDSTACK_SYSTEM_START': '10.253.80.20',
    'CLOUDSTACK_SYSTEM_END': '10.253.80.40',
    'CLOUDSTACK_GUEST_START': '10.253.80.100',
    'CLOUDSTACK_GUEST_END': '10.253.80.220',
    'APP_NETWORK': '172.30.253.0/24',
    'APP_ADDRESS': '172.30.253.2',
    'TAILSCALE_INTERFACE': 'tailscale0',
}


def load_network(path=None):
    values = DEFAULTS.copy()
    path = Path(path) if path else Path(__file__).resolve().parent.parent / '.env'
    if path.exists():
        for line in path.read_text().splitlines():
            key, separator, value = line.strip().removeprefix('export ').partition('=')
            key = key.strip()
            if separator and key in values:
                # Network values are literal scalars, never shell code or interpolated secrets.
                tokens = shlex.split(value, comments=True)
                if len(tokens) != 1:
                    raise ValueError(f'{key} must be one literal network value')
                values[key] = tokens[0]
    values.update({key: os.environ[key] for key in values if key in os.environ})
    for key in ('CLOUDSTACK_BRIDGE', 'TAILSCALE_INTERFACE'):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', values[key]):
            raise ValueError(f'{key} must be a Linux interface name')
    if values['CLOUDSTACK_BRIDGE'] == values['TAILSCALE_INTERFACE']:
        raise ValueError('CloudStack and Tailscale interfaces must differ')
    cloud, app = (ipaddress.ip_network(values[key]) for key in ('CLOUDSTACK_NETWORK', 'APP_NETWORK'))
    private = [ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if any(net.version != 4 or net.prefixlen > 29
           or not any(net.subnet_of(block) for block in private) for net in (cloud, app)):
        raise ValueError('CloudStack and application networks must be private IPv4 subnets with usable hosts')
    if cloud.overlaps(app):
        raise ValueError('CloudStack and application networks must not overlap')
    for key in ('CLOUDSTACK_GATEWAY', 'CLOUDSTACK_SYSTEM_START', 'CLOUDSTACK_SYSTEM_END',
                'CLOUDSTACK_GUEST_START', 'CLOUDSTACK_GUEST_END', 'APP_ADDRESS'):
        address = ipaddress.ip_address(values[key])
        net = app if key == 'APP_ADDRESS' else cloud
        if address not in net or address in (net.network_address, net.broadcast_address):
            raise ValueError(f'{key} must be a usable address in {net}')
    system = [ipaddress.ip_address(values['CLOUDSTACK_SYSTEM_' + bound]) for bound in ('START', 'END')]
    guests = [ipaddress.ip_address(values['CLOUDSTACK_GUEST_' + bound]) for bound in ('START', 'END')]
    gateway = ipaddress.ip_address(values['CLOUDSTACK_GATEWAY'])
    if system[0] > system[1] or guests[0] > guests[1] or not (system[1] < guests[0] or guests[1] < system[0]):
        raise ValueError('System and guest address ranges must be ordered and disjoint')
    if any(start <= gateway <= end for start, end in (system, guests)):
        raise ValueError('Gateway must be outside the allocation ranges')
    return values
