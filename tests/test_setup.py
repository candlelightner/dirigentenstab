import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location('native_setup', Path(__file__).parents[1] / 'scripts/native_setup.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def test_native_network_rejects_overlapping_existing_route():
    with pytest.raises(RuntimeError, match='conflicts'):
        native.check_routes([{'dst': '10.253.0.0/16', 'dev': 'existing-bridge'}])


def test_default_route_and_owned_bridge_are_accepted_without_mutation():
    routes = [{'dst': 'default', 'gateway': '10.0.0.138', 'dev': 'eth0'},
              {'dst': '10.253.80.0/24', 'dev': native.BRIDGE},
              {'dst': '172.18.0.0/16', 'dev': 'docker0'}]
    previous = [dict(route) for route in routes]
    native.check_routes(routes)
    assert routes == previous


def test_existing_link_local_route_is_not_replaced():
    with pytest.raises(RuntimeError, match='link-local'):
        native.check_routes([{'dst': '169.254.169.254/32', 'dev': 'existing-metadata'}])


def test_properties_preserve_permissions_and_back_up_original_once(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir()
    monkeypatch.setattr(native, 'STATE', state)
    settings = tmp_path / 'agent.properties'
    settings.write_text('# host=old\nport=8250\n')
    settings.chmod(0o600)
    native.properties(settings, {'host': '10.253.80.1'})
    first = settings.stat().st_mtime_ns
    native.properties(settings, {'host': '10.253.80.1'})
    assert settings.stat().st_mtime_ns == first
    assert settings.stat().st_mode & 0o777 == 0o600
    assert (state / 'originals' / str(settings).lstrip('/')).read_text() == '# host=old\nport=8250\n'
    assert settings.read_text() == 'host=10.253.80.1\nport=8250\n'


def test_completed_install_step_is_not_repeated(tmp_path, monkeypatch):
    monkeypatch.setattr(native, 'STATE', tmp_path)
    (tmp_path / 'database.done').touch()
    native.step('database', lambda: pytest.fail('Completed database setup must not run again'))


def test_guest_ssh_rules_are_scoped_and_removal_preserves_other_rules():
    import json
    from types import SimpleNamespace
    spec = importlib.util.spec_from_file_location('guest_forwarding',
        Path(__file__).parents[1] / 'scripts/guest_ssh_forwarding.py')
    forwarding = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(forwarding)
    commands = []
    owned = '-A FORWARD ' + ' '.join(forwarding.rules('br-test')[0])
    def run(command, **kwargs):
        commands.append(command)
        if command[:3] == ('iptables', '-w', '-S'):
            return SimpleNamespace(returncode=0, stdout='-P FORWARD ACCEPT\n'+owned+'\n-A FORWARD -o dscloud0 -j DROP\n')
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'Id': 'a'*64}]))
    forwarding.maintain(remove=True, run=run)
    deletes = [c for c in commands if '-D' in c]
    assert len(deletes) == 1 and forwarding.TAG in deletes[0]
    assert all('-F' not in c and '-P' not in c for c in commands)
    outbound, inbound = forwarding.rules('br-test')
    assert '172.30.253.2/32' in outbound and '10.253.80.0/24' in outbound
    assert '--dport' in outbound and outbound[outbound.index('--dport')+1] == '22'
    assert 'ESTABLISHED,RELATED' in inbound and '--sport' in inbound


def test_guest_ssh_installer_does_not_restart_native_services(monkeypatch):
    writes, commands = {}, []
    monkeypatch.setattr(native, 'save', lambda path, text, *args: writes.update({path: text}))
    monkeypatch.setattr(native, 'run', lambda *args: commands.append(args))
    native.guest_ssh()
    assert '/usr/local/libexec/dirigentenstab-guest-ssh.py' in writes
    assert '/etc/systemd/system/dirigentenstab-guest-ssh.timer' in writes
    assert all('restart' not in command and 'stop' not in command for command in commands)
    assert commands[-1] == ('systemctl', 'start', 'dirigentenstab-guest-ssh.service')


def test_fresh_native_install_includes_guest_ssh_without_imports(tmp_path, monkeypatch):
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(native, 'STATE', tmp_path)
    monkeypatch.setattr(native.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(native.os, 'umask', lambda value: None)
    monkeypatch.setattr(native.sys, 'argv', ['setup.sh', '--install'])
    for name in ('preflight', 'repositories', 'packages', 'network', 'database', 'services',
                 'verify', 'prepare_application', 'guest_ssh'):
        monkeypatch.setattr(native, name, lambda name=name: calls.append(name))
    monkeypatch.setattr(native, 'step', lambda name, action: action())
    monkeypatch.setattr(native.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0))
    native.main()
    assert calls[-3:] == ['verify', 'prepare_application', 'guest_ssh']
    assert calls[:3] == ['preflight', 'repositories', 'packages']
