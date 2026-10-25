import importlib.util
from pathlib import Path
import shlex
from types import SimpleNamespace


spec = importlib.util.spec_from_file_location('guest_routing',
    Path(__file__).parents[1] / 'scripts/guest_ssh_forwarding.py')
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)


def native():
    prefix = ['-m', 'physdev', '--physdev-in', 'vnet41', '--physdev-is-bridged']
    return {'FORWARD': [['-o', 'dscloud0', '-j', 'DROP'], ['-i', 'dscloud0', '-j', 'DROP']],
            'BF-dscloud0-IN': [[*prefix, '-j', 'i-4-39-def'],
                              ['-m', 'physdev', '--physdev-in', 'vnet6', '--physdev-is-bridged', '-j', 'r-4-VM']],
            'i-4-39-def': [['-p', 'udp', *prefix, '--sport', '68', '--dport', '67', '-j', 'ACCEPT'],
                          [*prefix, '-m', 'set', '!', '--match-set', 'i-4-39-VM', 'src', '-j', 'DROP'],
                          [*prefix, '-j', 'i-4-39-VM-eg'],
                          [*prefix, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                          [*prefix, '-j', 'DROP']],
            'i-4-39-VM-eg': [['-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'], ['-j', 'RETURN']],
            'r-4-VM': [['-j', 'ACCEPT']]}


def fake(chains):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs.get('input')))
        if '-C' in command:
            return SimpleNamespace(returncode=0 if len(chains['FORWARD']) > 2 else 1, stdout='')
        if command[0] == 'ip':
            return SimpleNamespace(stdout='[{"dev":"enp0s31f6","metric":100}]')
        lines = ['-N ' + name for name in chains]
        lines += ['-A ' + name + ' ' + shlex.join(rule) for name, rules in chains.items() for rule in rules]
        return SimpleNamespace(stdout='\n'.join(lines))

    return calls, run


def test_routed_policy_keeps_live_native_policy_and_anti_spoof_before_dhcp():
    chains = native()
    policy = routing.routed_policy(chains)
    assert policy[0][-8:] == ['-m', 'set', '!', '--match-set', 'i-4-39-VM', 'src', '-j', 'DROP']
    assert policy[1][-2:] == ['-j', 'ACCEPT'] and '--dport' in policy[1]
    assert any(rule[-2:] == ['-j', 'i-4-39-VM-eg'] for rule in policy)
    assert any(rule[-2:] == ['-j', 'r-4-VM'] for rule in policy)
    assert policy[-1] == ['-j', 'DROP']
    assert all('--physdev-is-bridged' not in rule for rule in policy)
    assert all('vnet41' in rule for rule in policy[:-2])
    # Native SG edits are followed through live chain references, not copied ACCEPT rules.
    assert not any('--dport' in rule and '443' in rule for rule in policy)
    chains['i-4-39-def'].pop(1)
    assert routing.routed_policy(chains) == [['-m', 'physdev', '--physdev-in', 'vnet6', '-j', 'r-4-VM'], ['-j', 'DROP']]


def test_atomic_scoped_update_and_idempotence():
    chains = native()
    calls, run = fake(chains)
    routing.maintain_routed(run=run)
    command, transaction = next(call for call in calls if call[0][0] == 'iptables-restore')
    assert '--noflush' in command
    assert "'!'" not in transaction
    assert '! --match-set' in transaction
    assert '-i dscloud0 -o enp0s31f6 -s 10.253.80.0/24' in transaction
    assert '--ctstate ESTABLISHED,RELATED' in transaction
    assert '-F FORWARD' not in transaction and '-P ' not in transaction
    assert '-F i-' not in transaction and '-F BF-' not in transaction
    for line in transaction.splitlines():
        parts = shlex.split(line)
        if parts[:2] == ['-N', routing.EGRESS_CHAIN]:
            chains[routing.EGRESS_CHAIN] = []
        elif parts[:2] == ['-A', routing.EGRESS_CHAIN]:
            chains[routing.EGRESS_CHAIN].append(parts[2:])
        elif parts[:3] == ['-I', 'FORWARD', '1']:
            chains['FORWARD'].insert(0, parts[3:])
    calls, run = fake(chains)
    routing.maintain_routed(run=run)
    assert not any(command[0] == 'iptables-restore' for command, _ in calls)
    routing.maintain_routed(remove=True, run=run)
    transaction = next(data for command, data in calls if command[0] == 'iptables-restore')
    assert '-X ' + routing.EGRESS_CHAIN in transaction
    assert '-D FORWARD -o dscloud0 -j DROP' not in transaction


def test_removed_native_port_drops_all_adapter_references():
    chains = native()
    chains[routing.EGRESS_CHAIN] = routing.routed_policy(chains)
    chains['BF-dscloud0-IN'] = chains['BF-dscloud0-IN'][1:]
    calls, run = fake(chains)
    routing.maintain_routed(run=run)
    transaction = next(data for command, data in calls if command[0] == 'iptables-restore')
    assert '-F ' + routing.EGRESS_CHAIN in transaction
    assert 'vnet41' not in transaction and 'i-4-39-VM' not in transaction
    assert '-X i-4-39' not in transaction and '-F i-4-39' not in transaction
    assert '-j r-4-VM' in transaction
