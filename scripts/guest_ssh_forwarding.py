#!/usr/bin/env python3
"""Maintain scoped guest SSH and native security-group checks on routed guest egress."""

import argparse
import json
import re
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


def maintain_ssh(remove=False, run=subprocess.run):
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


EGRESS_TAG = 'dirigentenstab-guest-egress'
EGRESS_CHAIN = 'DS-GUEST-EGRESS'


def routed_policy(chains):
    """Adapt native bridge guards while retaining live CloudStack SG chains and IP sets."""
    result = []
    for dispatch in chains.get('BF-dscloud0-IN', []):
        if len(dispatch) != 7 or dispatch[:3] != ['-m', 'physdev', '--physdev-in'] or dispatch[4:6] != [
                '--physdev-is-bridged', '-j']:
            continue
        port, target = dispatch[3], dispatch[-1]
        if not re.fullmatch(r'vnet[0-9]+', port):
            continue
        if re.fullmatch(r'[srv]-[0-9]+-VM', target) and target in chains:
            result.append(['-m', 'physdev', '--physdev-in', port, '-j', target])
            continue
        if not re.fullmatch(r'i-[0-9]+-[0-9]+-def', target):
            continue
        ipset = target.removesuffix('-def') + '-VM'
        guard = ['-m', 'physdev', '--physdev-in', port, '--physdev-is-bridged',
                 '-m', 'set', '!', '--match-set', ipset, 'src', '-j', 'DROP']
        if guard not in chains.get(target, []) or ipset + '-eg' not in chains:
            continue
        # DHCP's native exception precedes anti-spoofing; routed uplink traffic needs the guard first.
        result.append([token for token in guard if token != '--physdev-is-bridged'])
        for rule in chains[target]:
            if '--physdev-in' in rule and rule[rule.index('--physdev-in') + 1] == port:
                result.append([token for token in rule if token != '--physdev-is-bridged'])
    return [*result, ['-j', 'DROP']]


def restore_rule(rule):
    # iptables-restore parses double quotes, not shell quotes (notably the ! matcher).
    return ' '.join(json.dumps(token) if any(c.isspace() or c in {'"', '\\'} for c in token) else token
                    for token in rule)


def maintain_routed(remove=False, run=subprocess.run):
    def call(*args, input=None, check=True):
        return run(args, check=check, input=input, capture_output=True, text=True, timeout=10)

    chains = {}
    for line in call('iptables', '-w', '5', '-S').stdout.splitlines():
        tokens = shlex.split(line)
        if tokens[:1] == ['-N']:
            chains.setdefault(tokens[1], [])
        elif tokens[:1] == ['-A']:
            chains.setdefault(tokens[1], []).append(tokens[2:])
    current = chains.get('FORWARD', [])
    owned = [rule for rule in current if EGRESS_TAG in rule]
    desired, policy = [], None
    if not remove and 'BF-dscloud0-IN' in chains:
        routes = json.loads(call('ip', '-j', '-4', 'route', 'show', 'default').stdout)
        routes = [route for route in routes if route.get('dev') and route['dev'] != 'dscloud0']
        if routes:
            uplink = min(routes, key=lambda route: route.get('metric', 0))['dev']
            tag = ['-m', 'comment', '--comment', EGRESS_TAG]
            desired = [
                ['-i', 'dscloud0', '-o', uplink, '-s', GUESTS, '!', '-d', GUESTS, *tag, '-j', EGRESS_CHAIN],
                ['-i', uplink, '-o', 'dscloud0', '-d', GUESTS, '-m', 'conntrack', '--ctstate',
                 'ESTABLISHED,RELATED', *tag, '-j', 'ACCEPT'],
            ]
            policy = routed_policy(chains)
    barriers = [i for i, rule in enumerate(current) if rule in (
        ['-i', 'dscloud0', '-j', 'DROP'], ['-o', 'dscloud0', '-j', 'DROP'])]
    positioned = bool(desired and barriers and all(current.index(rule) < min(barriers) for rule in owned))
    present = len(owned) == len(desired) and all(
        call('iptables', '-w', '5', '-C', 'FORWARD', *rule, check=False).returncode == 0 for rule in desired)
    if present and (not desired or positioned) and chains.get(EGRESS_CHAIN) == policy:
        return
    operations = []
    if policy is not None:
        operations.append(('-F ' if EGRESS_CHAIN in chains else '-N ') + EGRESS_CHAIN)
        operations += ['-A ' + EGRESS_CHAIN + ' ' + restore_rule(rule) for rule in policy]
    operations += ['-D FORWARD ' + restore_rule(rule) for rule in owned]
    operations += ['-I FORWARD 1 ' + restore_rule(rule) for rule in reversed(desired)]
    if policy is None and EGRESS_CHAIN in chains:
        operations += ['-F ' + EGRESS_CHAIN, '-X ' + EGRESS_CHAIN]
    if operations:
        # One atomic transaction edits only our chain/jumps; native chains and unrelated rules stay intact.
        call('iptables-restore', '--wait', '5', '--noflush',
             input='*filter\n' + '\n'.join(operations) + '\nCOMMIT\n')


def maintain(remove=False, run=subprocess.run):
    maintain_ssh(remove, run)
    maintain_routed(remove, run)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remove', action='store_true', help='Remove only rules owned by this helper')
    maintain(parser.parse_args().remove)
