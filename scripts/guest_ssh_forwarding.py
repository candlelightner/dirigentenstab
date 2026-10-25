#!/usr/bin/env python3
"""Maintain only the native application's two narrow guest-SSH forwarding rules."""

import argparse
import json
import shlex
import subprocess

APP = '172.30.253.2/32'
GUESTS = '10.253.80.0/24'
TAG = 'dirigentenstab-guest-ssh'


def rules(bridge):
    return [
        ['-i', bridge, '-o', 'dscloud0', '-s', APP, '-d', GUESTS, '-p', 'tcp', '--dport', '22',
         '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED', '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'],
        ['-i', 'dscloud0', '-o', bridge, '-s', GUESTS, '-d', APP, '-p', 'tcp', '--sport', '22',
         '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'],
    ]


def maintain(remove=False, run=subprocess.run):
    def call(*args, check=True):
        return run(args, check=check, capture_output=True, text=True, timeout=10)
    current = call('iptables', '-w', '-S', 'FORWARD').stdout.splitlines()
    owned = [shlex.split(line)[2:] for line in current if TAG in shlex.split(line)]
    desired = []
    if not remove:
        network = call('docker', 'network', 'inspect', 'dirigentenstab_management', check=False)
        if network.returncode:
            return
        desired = rules('br-' + json.loads(network.stdout)[0]['Id'][:12])
    if (desired and len(owned) == 2 and all(TAG in line for line in current[1:3]) and
            all(call('iptables', '-w', '-C', 'FORWARD', *rule, check=False).returncode == 0 for rule in desired)):
        return
    for rule in owned:
        call('iptables', '-w', '-D', 'FORWARD', *rule)
    for rule in reversed(desired):
        call('iptables', '-w', '-I', 'FORWARD', '1', *rule)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remove', action='store_true', help='Remove only rules owned by this helper')
    maintain(parser.parse_args().remove)
