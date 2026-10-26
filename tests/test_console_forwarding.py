import importlib.util
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


spec = importlib.util.spec_from_file_location('console_forwarding',
    Path(__file__).parents[1] / 'scripts/console_forwarding.py')
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


def fake_run(current, *, guard=True, ready=True):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs.get('input')))
        if '-C' in command and not ready:
            raise subprocess.CalledProcessError(1, command)
        if command[:5] == ('iptables', '-w', '5', '-S', 'FORWARD'):
            return SimpleNamespace(returncode=0, stdout='-P FORWARD ACCEPT\n' + '\n'.join(
                '-A FORWARD ' + shlex.join(rule) for rule in current))
        if command[:4] == ('nft', '-s', '-y', 'list'):
            return SimpleNamespace(returncode=0 if guard else 1, stdout=console.GUARD if guard else '')
        return SimpleNamespace(returncode=0, stdout='')

    return calls, run


def test_console_adopts_exact_working_rules_and_preserves_foreign_rules():
    legacy = console.rules(tagged=False)
    foreign = ['-o', 'dscloud0', '-j', 'DROP']
    calls, run = fake_run([*legacy, foreign], guard=False)
    console.maintain(run=run)
    transactions = [data for command, data in calls if command[0] == 'iptables-restore']
    assert len(transactions) == 1
    lines = transactions[0].splitlines()
    assert lines[0] == '*filter' and lines[-1] == 'COMMIT'
    assert len(lines) == 6
    assert lines[1:3] == ['-D FORWARD ' + shlex.join(rule) for rule in legacy]
    assert '--noflush' in next(c for c, _ in calls if c[0] == 'iptables-restore')
    assert all('-F' not in c and '-P' not in c for c, _ in calls)
    assert 'ip daddr 10.253.80.0/24 accept' in console.GUARD
    assert 'iifname "tailscale0" oifname "dscloud0" drop' in console.GUARD
    assert any('ts-postrouting' in c and 'MASQUERADE' in c for c, _ in calls)


def test_console_reapply_is_noop_with_disjoint_guest_ssh_first():
    guest = ['-i', 'br-app', '-o', 'dscloud0', '--comment', 'dirigentenstab-guest-ssh', '-j', 'ACCEPT']
    calls, run = fake_run([guest, *console.rules(), ['-j', 'ts-forward']])
    console.maintain(run=run)
    assert not any(c[0] == 'iptables-restore' or c[:2] == ('nft', '-f') for c, _ in calls)


def test_console_repairs_rules_below_broad_tailscale_hook():
    calls, run = fake_run([['-j', 'ts-forward'], *console.rules()])
    console.maintain(run=run)
    transaction = next(data for c, data in calls if c[0] == 'iptables-restore')
    assert '-D FORWARD -j ts-forward' not in transaction
    assert transaction.count('-D FORWARD') == 2
    assert transaction.count('-I FORWARD 1') == 2


def test_console_waits_for_initialization_without_mutating_rules():
    calls, run = fake_run([], ready=False)
    with pytest.raises(subprocess.CalledProcessError):
        console.maintain(run=run)
    assert not any(c[0] == 'iptables-restore' or c[:2] == ('nft', '-f') for c, _ in calls)


def test_console_remove_deletes_only_owned_rules_and_guard():
    calls, run = fake_run([*console.rules(), ['-j', 'DOCKER-FORWARD']])
    console.maintain(remove=True, run=run)
    deletes = [c for c, _ in calls if '-D' in c]
    assert len(deletes) == 2 and all(console.TAG in c for c in deletes)
    assert calls[-1][1] == 'destroy table inet dirigentenstab_console\n'


def test_console_installer_orders_and_enables_only_its_units(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / 'scripts'))
    import install_console_forwarding as installer
    writes, calls = {}, []
    monkeypatch.setattr(installer, 'STATE', tmp_path)
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(installer.os, 'umask', lambda value: None)
    monkeypatch.setattr(installer, 'save', lambda path, data, mode: writes.update({path: (data, mode)}))
    monkeypatch.setattr(installer, 'run', lambda *args: calls.append(args))
    installer.install()
    service = writes['/etc/systemd/system/dirigentenstab-console.service'][0]
    after = next(line for line in service.splitlines() if line.startswith('After='))
    assert all(name in after for name in ('network-online.target', 'tailscaled.service',
        'cloudstack-agent.service', 'cloudstack-management.service', 'dirigentenstab-network.service'))
    assert 'OnUnitInactiveSec=30s' in writes['/etc/systemd/system/dirigentenstab-console.timer'][0]
    assert writes['/usr/local/libexec/dirigentenstab-console.py'][1] == 0o755
    assert ('systemctl', 'enable', 'dirigentenstab-console.service') in calls
    assert ('systemctl', 'enable', '--now', 'dirigentenstab-console.timer') in calls
    assert all('restart' not in c and 'stop' not in c for c in calls)


def test_vm_access_is_scoped_to_tailscale_with_only_established_replies():
    inbound, reply = console.rules()
    assert inbound[inbound.index('-i') + 1] == 'tailscale0'
    assert inbound[inbound.index('-o') + 1] == 'dscloud0'
    assert inbound[inbound.index('-s') + 1] == '100.64.0.0/10'
    assert inbound[inbound.index('-d') + 1] == '10.253.80.0/24'
    assert inbound[-2:] == ['-j', 'ts-forward']
    assert reply[reply.index('-i') + 1] == 'dscloud0'
    assert reply[reply.index('-o') + 1] == 'tailscale0'
    assert reply[reply.index('-s') + 1] == '10.253.80.0/24'
    assert reply[reply.index('-d') + 1] == '100.64.0.0/10'
    assert set(reply[reply.index('--ctstate') + 1].split(',')) == {'ESTABLISHED', 'RELATED'}
    assert all('-p' not in rule for rule in (inbound, reply))
    assert 'iifname "tailscale0" oifname "dscloud0" ip saddr 100.64.0.0/10' in console.GUARD


def test_upgrading_console_only_policy_replaces_owned_rules_without_touching_vm_isolation():
    old = [
        ['-s', '100.64.0.0/10', '-d', '10.253.80.100/32', '-i', 'tailscale0', '-o', 'dscloud0',
         '-p', 'tcp', '-m', 'multiport', '--dports', '80,8080', '-m', 'conntrack',
         '--ctstate', 'NEW,ESTABLISHED', '-m', 'comment', '--comment', console.TAG, '-j', 'ts-forward'],
        ['-s', '10.253.80.100/32', '-d', '100.64.0.0/10', '-i', 'dscloud0', '-o', 'tailscale0',
         '-p', 'tcp', '-m', 'multiport', '--sports', '80,8080', '-m', 'conntrack',
         '--ctstate', 'RELATED,ESTABLISHED', '-m', 'comment', '--comment', console.TAG, '-j', 'ACCEPT'],
    ]
    isolation = ['-o', 'dscloud0', '-m', 'physdev', '--physdev-is-bridged', '-j', 'BF-dscloud0']
    calls, run = fake_run([*old, isolation, ['-o', 'dscloud0', '-j', 'DROP']], guard=False)
    console.maintain(run=run)
    transaction = next(data for c, data in calls if c[0] == 'iptables-restore')
    assert all('-D FORWARD ' + shlex.join(rule) in transaction for rule in old)
    assert all('-I FORWARD 1 ' + shlex.join(rule) in transaction for rule in console.rules())
    assert 'BF-dscloud0' not in transaction
    assert '-j DROP' not in transaction
    guard = next(data for c, data in calls if c[:2] == ('nft', '-f'))
    assert guard.endswith(console.GUARD)
