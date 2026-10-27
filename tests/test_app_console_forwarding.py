import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
from types import SimpleNamespace

import pytest


spec = importlib.util.spec_from_file_location('app_console_forwarding',
    Path(__file__).parents[1] / 'scripts/guest_ssh_forwarding.py')
forwarding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forwarding)


def fake_run(current, discovery='10.253.80.100\n169.254.1.2\n10.0.0.21\n', docker=True):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[0] == 'mysql':
            assert kwargs['check'] and kwargs['timeout'] == 10
            assert "v.type='ConsoleProxy'" in command[-1]
            assert 'v.removed IS NULL AND n.removed IS NULL' in command[-1]
            if isinstance(discovery, Exception):
                raise discovery
            return SimpleNamespace(returncode=0, stdout=discovery)
        if command[0] == 'docker':
            return SimpleNamespace(returncode=0 if docker else 1, stdout=json.dumps([{'Id': 'a' * 64}]))
        if '-S' in command:
            return SimpleNamespace(returncode=0, stdout='-P FORWARD ACCEPT\n' + '\n'.join(
                '-A FORWARD ' + shlex.join(rule) for rule in current))
        if '-C' in command:
            return SimpleNamespace(returncode=0 if list(command[4:]) in current else 1, stdout='')
        if '-D' in command:
            current.remove(list(command[4:]))
        if '-I' in command:
            current.insert(0, list(command[5:]))
        return SimpleNamespace(returncode=0, stdout='')

    return calls, run


def test_cpvm_rules_are_narrow_and_repeat_without_changes():
    foreign = ['-o', forwarding.BRIDGE, '-j', 'DROP']
    current = [foreign]
    calls, run = fake_run(current)
    forwarding.maintain_ssh(run=run)
    assert current[:2] == forwarding.rules('br-' + 'a' * 12)
    request, reply = current[2:4]
    assert current[4:] == [foreign]
    assert request[request.index('-s') + 1] == forwarding.APP
    assert request[request.index('-d') + 1] == '10.253.80.100/32'
    assert request[request.index('-i') + 1] == 'br-' + 'a' * 12
    assert request[request.index('-o') + 1] == forwarding.BRIDGE
    assert request[request.index('--dports') + 1] == '80,8080'
    assert request[request.index('--ctstate') + 1] == 'NEW,ESTABLISHED'
    assert reply[reply.index('-s') + 1] == '10.253.80.100/32'
    assert reply[reply.index('-d') + 1] == forwarding.APP
    assert reply[reply.index('-i') + 1] == forwarding.BRIDGE
    assert reply[reply.index('-o') + 1] == 'br-' + 'a' * 12
    assert reply[reply.index('--sports') + 1] == '80,8080'
    assert reply[reply.index('--ctstate') + 1] == 'ESTABLISHED'
    calls.clear()
    forwarding.maintain_ssh(run=run)
    assert not any('-D' in c or '-I' in c for c in calls)


def test_cpvm_replacement_reorders_only_owned_rules_and_remove_never_queries_db():
    foreign = ['-j', 'DOCKER-FORWARD']
    current = [foreign]
    _, run = fake_run(current)
    forwarding.maintain_ssh(run=run)
    current.insert(0, current.pop())
    calls, run = fake_run(current, '10.253.80.101\n10.253.80.101\n10.253.80.21\n')
    forwarding.maintain_ssh(run=run)
    assert len(current) == 7 and current[-1] == foreign
    assert not any('10.253.80.100/32' in rule for rule in current)
    assert sum('10.253.80.21/32' in rule for rule in current) == 2
    calls.clear()
    forwarding.maintain_ssh(remove=True, run=run)
    assert current == [foreign]
    assert not any(c[0] in ('mysql', 'docker') for c in calls)


@pytest.mark.parametrize('discovery', [
    '', 'bad-address', subprocess.CalledProcessError(1, 'mysql'),
    subprocess.TimeoutExpired('mysql', 10), FileNotFoundError('mysql'),
])
def test_discovery_failure_revokes_stale_cpvm_access_but_retains_ssh(discovery):
    foreign = ['-o', forwarding.BRIDGE, '-j', 'DROP']
    current = [foreign]
    _, run = fake_run(current)
    forwarding.maintain_ssh(run=run)
    _, run = fake_run(current, discovery)
    forwarding.maintain_ssh(run=run)
    assert current == [*forwarding.rules('br-' + 'a' * 12), foreign]


def test_missing_docker_network_revokes_owned_exceptions():
    current = []
    _, run = fake_run(current)
    forwarding.maintain_ssh(run=run)
    calls, run = fake_run(current, docker=False)
    forwarding.maintain_ssh(run=run)
    assert current == []
    assert not any(c[0] == 'mysql' for c in calls)


def test_discovery_uses_configured_native_network_and_excludes_nonhosts(monkeypatch):
    monkeypatch.setattr(forwarding, 'GUESTS', '10.42.0.0/24')
    current = []
    _, run = fake_run(current, '10.42.0.21\n10.253.80.100\n::1\n10.42.0.0\n10.42.0.255\n')
    forwarding.maintain_ssh(run=run)
    assert len(current) == 4
    assert all('10.42.0.21/32' in rule for rule in current[2:])
