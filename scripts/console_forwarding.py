#!/usr/bin/env python3
"""Maintain only Tailscale access to the reference host's Console Proxy VM."""

import argparse
import shlex
import subprocess

TAG = 'dirigentenstab-console'
TABLE = 'dirigentenstab_console'
# shortcut: this CPVM address is pinned, review it if CloudStack replaces the CPVM.
CPVM = '10.253.80.100/32'
TAILNET = '100.64.0.0/10'
GUARD = f'''table inet {TABLE} {{
 chain forward {{
  type filter hook forward priority -10; policy accept;
  iifname "tailscale0" oifname "dscloud0" ip saddr {TAILNET} ip daddr 10.253.80.100 tcp dport {{ 80, 8080 }} accept
  iifname "tailscale0" oifname "dscloud0" drop
 }}
}}
'''


def rules(tagged=True):
    tag = ['-m', 'comment', '--comment', TAG] if tagged else []
    return [
        ['-s', TAILNET, '-d', CPVM, '-i', 'tailscale0', '-o', 'dscloud0', '-p', 'tcp',
         '-m', 'multiport', '--dports', '80,8080', '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED',
         *tag, '-j', 'ts-forward'],
        ['-s', CPVM, '-d', TAILNET, '-i', 'dscloud0', '-o', 'tailscale0', '-p', 'tcp',
         '-m', 'multiport', '--sports', '80,8080', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED',
         *tag, '-j', 'ACCEPT'],
    ]


def maintain(remove=False, run=subprocess.run):
    def call(*args, check=True, input=None):
        return run(args, check=check, input=input, capture_output=True, text=True, timeout=10)

    current = [shlex.split(line)[2:] for line in call('iptables', '-w', '5', '-S', 'FORWARD').stdout.splitlines()
               if line.startswith('-A FORWARD ')]
    owned = [rule for rule in current if TAG in rule]
    if remove:
        for rule in owned:
            call('iptables', '-w', '5', '-D', 'FORWARD', *rule)
        call('nft', '-f', '-', input=f'destroy table inet {TABLE}\n')
        return

    # Simple services can be active before asynchronous CloudStack/Tailscale setup finishes.
    for rule in (['-o', 'dscloud0', '-j', 'DROP'], ['-i', 'dscloud0', '-j', 'DROP']):
        call('iptables', '-w', '5', '-C', 'FORWARD', *rule)
    call('iptables', '-w', '5', '-C', 'ts-forward', '-i', 'tailscale0', '-j', 'MARK',
         '--set-xmark', '0x40000/0xff0000')
    call('iptables', '-w', '5', '-C', 'ts-forward', '-m', 'mark', '--mark', '0x40000/0xff0000', '-j', 'ACCEPT')
    call('iptables', '-w', '5', '-t', 'nat', '-C', 'POSTROUTING', '-j', 'ts-postrouting')
    call('iptables', '-w', '5', '-t', 'nat', '-C', 'ts-postrouting', '-m', 'mark',
         '--mark', '0x40000/0xff0000', '-j', 'MASQUERADE')

    guard = call('nft', '-s', '-y', 'list', 'table', 'inet', TABLE, check=False)
    if guard.returncode or guard.stdout.split() != GUARD.split():
        # One atomic transaction replaces only our guard; never flush shared tables.
        call('nft', '-f', '-', input=f'add table inet {TABLE}\ndelete table inet {TABLE}\n' + GUARD)

    desired = rules()
    # Guest SSH has disjoint interfaces; its timer may legitimately insert before us.
    relevant = [rule for rule in current if not ('dirigentenstab-guest-ssh' in rule and 'tailscale0' not in rule)]
    legacy = [rule for rule in current if rule in rules(tagged=False)]
    if owned != desired or relevant[:2] != desired or legacy:
        operations = ['-D FORWARD ' + shlex.join(rule) for rule in owned + legacy]
        operations += ['-I FORWARD 1 ' + shlex.join(rule) for rule in reversed(desired)]
        # Atomically edit only our rules, retaining all dynamic chains and counters.
        call('iptables-restore', '--wait', '5', '--noflush',
             input='*filter\n' + '\n'.join(operations) + '\nCOMMIT\n')
        print('Console forwarding rules applied.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remove', action='store_true', help='Remove only owned console rules and guard')
    maintain(parser.parse_args().remove)
