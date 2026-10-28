import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('platform_watchdog',
    Path(__file__).parents[1] / 'scripts/platform_watchdog.py')
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)

NOW = 1_000_000.0


def data(status='Up', resource='Enabled', api=True, vm='Running', agent_host=None):
    return {'hosts': [{'name': 'homeserver', 'status': status, 'resource_state': resource, 'address': '10.253.80.1'}],
            'system_vms': [{'name': 's-1-VM', 'type': 'SecondaryStorageVm', 'state': vm}],
            'capacity': {'cpu_allocated_pct': 50.0, 'memory_allocated_pct': 40.0, 'local_storage_used_pct': None,
                         'cpu_threshold_pct': 85.0, 'memory_threshold_pct': 85.0},
            'agent_host': agent_host or f'{wd.ADDRESS}@static', 'api': api}


@pytest.fixture(autouse=True)
def paths(tmp_path, monkeypatch):
    monkeypatch.setattr(wd, 'DIRECTORY', tmp_path)
    monkeypatch.setattr(wd, 'STATUS', tmp_path / 'status.json')
    monkeypatch.setattr(wd, 'STATE', tmp_path / 'state.json')
    props = tmp_path / 'agent.properties'
    props.write_text('zone=1\nhost=10.0.0.203@static\nport=8250\n')
    monkeypatch.setattr(wd, 'PROPERTIES', props)
    return tmp_path


def run(d, now=NOW, dry_run=False, restarts=None):
    restarts = [] if restarts is None else restarts
    status = wd.main(dry_run=dry_run, now=now, collector=lambda: d, restart=restarts.append)
    return status, restarts


def test_collect_parses_queries_and_shape(monkeypatch):
    def query(sql):
        if 'FROM host ' in sql:
            return [['homeserver', 'Up', 'Enabled', '10.253.80.1']]
        if 'vm_instance' in sql:
            return [['v-2-VM', 'ConsoleProxy', 'Running']]
        if 'op_host_capacity' in sql:
            return [['1', '1', '40', '5', '100'], ['1', '0', '10', '0', '100'], ['1', '9', '30', '0', '60']]
        return [['cluster.cpu.allocated.capacity.disablethreshold', '0.85'],
                ['cluster.memory.allocated.capacity.disablethreshold', '0.9']]
    result = wd.collect(query, lambda url: url.endswith(f'{wd.ADDRESS}:8080/client/'))
    assert result['api'] is True and result['agent_host'] == '10.0.0.203@static'
    assert result['capacity'] == {'cpu_allocated_pct': 45.0, 'memory_allocated_pct': 10.0,
                                  'local_storage_used_pct': 50.0, 'cpu_threshold_pct': 85.0,
                                  'memory_threshold_pct': 90.0}


def test_status_shape_and_file_modes(paths):
    status, _ = run(data())
    on_disk = json.loads((paths / 'status.json').read_text())
    assert on_disk == status
    assert set(status) == {'version', 'updated', 'healthy', 'hosts', 'management_api', 'system_vms',
                           'capacity', 'issues', 'actions'}
    assert set(status['hosts'][0]) == {'name', 'status', 'resource_state', 'since'}
    assert status['version'] == 1 and status['management_api'] == {'reachable': True}
    assert (paths / 'status.json').stat().st_mode & 0o777 == 0o644
    assert not list(paths.glob('*.tmp'))


@pytest.mark.parametrize('kwargs,healthy', [
    ({}, True),
    ({'status': 'Disconnected'}, False),
    ({'resource': 'Disabled'}, False),
    ({'api': False}, False),
    ({'vm': 'Stopped'}, False),
])
def test_healthy_computation(kwargs, healthy):
    status, _ = run(data(**kwargs))
    assert status['healthy'] is healthy
    assert bool(status['issues']) is (not healthy)


def test_capacity_issue_and_since_tracking():
    d = data()
    d['capacity']['cpu_allocated_pct'] = 87.0
    status, _ = run(d)
    assert status['issues'] == ['CPU allocation 87% >= threshold 85%'] and status['healthy']
    run(data(status='Disconnected'), now=NOW + 10)
    status, _ = run(data(status='Disconnected'), now=NOW + 70)
    assert status['hosts'][0]['since'] == NOW + 10
    status, _ = run(data(), now=NOW + 80)
    assert status['hosts'][0]['since'] == NOW + 80


def test_three_minute_threshold_then_fix_and_restart(paths):
    for offset in (0, 60, 120):
        _, restarts = run(data(status='Disconnected'), now=NOW + offset)
        assert restarts == []
    assert wd.PROPERTIES.read_text().count('10.0.0.203') == 1
    status, restarts = run(data(status='Disconnected', agent_host='10.0.0.203@static'), now=NOW + 180)
    assert restarts == ['cloudstack-agent']
    assert [a['action'] for a in status['actions']] == ['fix-agent-host', 'restart-cloudstack-agent']


def test_restart_rate_limited_to_fifteen_minutes():
    d = data(status='Disconnected')
    run(d, now=NOW)
    _, first = run(d, now=NOW + 180)
    _, early = run(d, now=NOW + 180 + 899)
    _, late = run(d, now=NOW + 180 + 900)
    assert (first, early, late) == (['cloudstack-agent'], [], ['cloudstack-agent'])


def test_agent_properties_fix_backs_up_and_preserves_other_lines():
    d = data(status='Disconnected', agent_host='10.0.0.203@static')
    run(d, now=NOW)
    run(d, now=NOW + 180)
    assert wd.PROPERTIES.read_text() == f'zone=1\nhost={wd.ADDRESS}@static\nport=8250\n'
    backups = list(wd.PROPERTIES.parent.glob('agent.properties.bak-*'))
    assert len(backups) == 1 and 'host=10.0.0.203@static' in backups[0].read_text()
    # Correct address: untouched, no further backups.
    run(data(status='Disconnected'), now=NOW + 2000)
    assert len(list(wd.PROPERTIES.parent.glob('agent.properties.bak-*'))) == 1


def test_no_remediation_for_api_or_system_vm_problems(paths):
    for offset in (0, 300):
        status, restarts = run(data(api=False, vm='Stopped'), now=NOW + offset)
        assert restarts == [] and status['actions'] == []
    assert 'host=10.0.0.203' in wd.PROPERTIES.read_text()


def test_database_failure_reports_without_remediation(paths):
    def broken():
        raise OSError('no socket')
    status = wd.main(now=NOW, collector=broken, restart=lambda s: pytest.fail('restart'))
    assert not status['healthy'] and 'database unreadable' in status['issues'][0]


def test_dry_run_changes_nothing(paths, capsys):
    d = data(status='Disconnected', agent_host='10.0.0.203@static')
    run(d, now=NOW)
    before = {p.name: p.read_bytes() for p in paths.iterdir()}
    status, restarts = run(d, now=NOW + 200, dry_run=True)
    out = json.loads(capsys.readouterr().out)
    assert [a['action'] for a in out['planned_actions']] == ['fix-agent-host', 'restart-cloudstack-agent']
    assert restarts == [] and {p.name: p.read_bytes() for p in paths.iterdir()} == before
