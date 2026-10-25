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
    assert 'tcp dport { 80, 8080 } accept' in console.GUARD
    assert 'ip daddr 10.253.80.100' in console.GUARD
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
