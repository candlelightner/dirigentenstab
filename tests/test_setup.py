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
