#!/usr/bin/env python3
"""Root-run host watchdog: publish CloudStack platform health and repair one known agent failure.

Read-only data sources: the CloudStack DB (root MySQL socket auth), the management API landing page and
agent.properties. The only changes it ever makes are fixing the agent's management address (with a
backup) and restarting cloudstack-agent, both rate limited. It never restarts cloudstack-management and
never touches VMs, volumes or the database.

CloudStack 4.23 capacity types (org.apache.cloudstack.api.ApiConstants / com.cloud.capacity.Capacity):
0 memory, 1 cpu (both: allocated, summed per cluster over hosts; total already includes overprovisioning),
2 storage (used), 3 storage allocated, 6 secondary storage, 9 local storage (used, per local pool).
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from network_config import load_network

CONFIG = load_network()
ADDRESS = CONFIG['CLOUDSTACK_GATEWAY']
DIRECTORY = Path('/var/lib/dirigentenstab/platform')
STATUS = DIRECTORY / 'status.json'
STATE = DIRECTORY / 'state.json'
PROPERTIES = Path('/etc/cloudstack/agent/agent.properties')
NOT_UP_SECONDS = 180
RESTART_INTERVAL = 900
MAX_ACTIONS = 20
CAPACITY_MEMORY, CAPACITY_CPU, CAPACITY_LOCAL_STORAGE = 0, 1, 9
SYSTEM_VM_TYPES = ('SecondaryStorageVm', 'ConsoleProxy', 'DomainRouter')


def mysql(sql):
    result = subprocess.run(['mysql', '-N', 'cloud', '-e', sql], capture_output=True, text=True,
                            timeout=20, check=True)
    return [line.split('\t') for line in result.stdout.splitlines()]


def http_ok(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status == 200
    except (OSError, ValueError):
        return False


def systemctl_restart(service):
    subprocess.run(['systemctl', 'restart', service], capture_output=True, text=True, timeout=120, check=True)


def clock(epoch):
    return datetime.fromtimestamp(epoch).strftime('%H:%M')


def pct(used, total):
    return round(100 * used / total, 1) if total else 0.0


def collect(query=mysql, reachable=http_ok):
    """Read the platform; raises on database failure so callers never act on missing data."""
    hosts = [{'name': n, 'status': s, 'resource_state': r, 'address': a} for n, s, r, a in query(
        "SELECT name, status, resource_state, private_ip_address FROM host "
        "WHERE type='Routing' AND removed IS NULL")]
    vms = [{'name': n, 'type': t, 'state': s} for n, t, s in query(
        "SELECT name, type, state FROM vm_instance WHERE removed IS NULL AND type IN ("
        + ','.join(f"'{t}'" for t in SYSTEM_VM_TYPES) + ')')]
    # Per cluster: allocated (used + reserved) over total; the worst cluster is reported.
    totals = {}
    for _cluster, kind, used, reserved, total in query(
            'SELECT cluster_id, capacity_type, SUM(used_capacity), SUM(reserved_capacity), SUM(total_capacity) '
            f'FROM op_host_capacity WHERE capacity_type IN ({CAPACITY_MEMORY},{CAPACITY_CPU},'
            f'{CAPACITY_LOCAL_STORAGE}) GROUP BY cluster_id, capacity_type'):
        value = pct(float(used) + float(reserved), float(total))
        kind = int(kind)
        totals[kind] = max(totals.get(kind, 0.0), value)
    thresholds = dict(query(
        "SELECT name, value FROM configuration WHERE name IN "
        "('cluster.cpu.allocated.capacity.disablethreshold','cluster.memory.allocated.capacity.disablethreshold')"))
    capacity = {
        'cpu_allocated_pct': totals.get(CAPACITY_CPU, 0.0),
        'memory_allocated_pct': totals.get(CAPACITY_MEMORY, 0.0),
        'local_storage_used_pct': totals.get(CAPACITY_LOCAL_STORAGE),
        'cpu_threshold_pct': round(100 * float(thresholds.get('cluster.cpu.allocated.capacity.disablethreshold', 0.85)), 1),
        'memory_threshold_pct': round(100 * float(thresholds.get('cluster.memory.allocated.capacity.disablethreshold', 0.85)), 1),
    }
    try:
        text = PROPERTIES.read_text()
        match = re.search(r'^host=(.*)$', text, re.M)
        agent_host = match.group(1).strip() if match else None
    except OSError:
        agent_host = None
    return {'hosts': hosts, 'system_vms': vms, 'capacity': capacity, 'agent_host': agent_host,
            'api': reachable(f'http://{ADDRESS}:8080/client/')}


def evaluate(data, state, now):
    """Pure: build the status document and the new state from collected data."""
    known = state.get('hosts', {})
    hosts, tracked, issues = [], {}, []
    for host in data['hosts']:
        old = known.get(host['name'], {})
        key = (host['status'],)
        since = old['since'] if old.get('key') == list(key) else now
        up = host['status'] == 'Up'
        not_up_since = None if up else old.get('not_up_since') or now
        tracked[host['name']] = {'key': list(key), 'since': since, 'not_up_since': not_up_since}
        hosts.append({'name': host['name'], 'status': host['status'],
                      'resource_state': host['resource_state'], 'since': since})
        if not up:
            issues.append(f"Host {host['name']} {host['status']} since {clock(since)}")
        elif host['resource_state'] != 'Enabled':
            issues.append(f"Host {host['name']} is {host['resource_state']}, not Enabled")
    if not data['hosts']:
        issues.append('No Routing hosts registered')
    if not data['api']:
        issues.append(f'Management API at {ADDRESS}:8080 unreachable')
    for vm in data['system_vms']:
        if vm['state'] != 'Running':
            issues.append(f"System VM {vm['name']} ({vm['type']}) is {vm['state']}")
    capacity = data['capacity']
    for label, key in (('CPU', 'cpu'), ('Memory', 'memory')):
        if capacity[f'{key}_allocated_pct'] >= capacity[f'{key}_threshold_pct']:
            issues.append(f"{label} allocation {capacity[f'{key}_allocated_pct']:.0f}% >= threshold "
                          f"{capacity[f'{key}_threshold_pct']:.0f}%")
    healthy = (bool(hosts) and all(h['status'] == 'Up' and h['resource_state'] == 'Enabled' for h in hosts)
               and data['api'] and all(v['state'] == 'Running' for v in data['system_vms']))
    status = {'version': 1, 'updated': now, 'healthy': healthy, 'hosts': hosts,
              'management_api': {'reachable': data['api']}, 'system_vms': data['system_vms'],
              'capacity': capacity, 'issues': issues, 'actions': list(state.get('actions', []))[-MAX_ACTIONS:]}
    return status, {**state, 'hosts': tracked}


def plan(data, state, now):
    """Pure: the remediations due now, as (name, detail) tuples."""
    stuck = [h['name'] for h in data['hosts']
             if state['hosts'][h['name']]['not_up_since'] is not None
             and now - state['hosts'][h['name']]['not_up_since'] >= NOT_UP_SECONDS]
    if not stuck:
        return []
    steps = []
    if data['agent_host'] is not None and not data['agent_host'].startswith(ADDRESS):
        steps.append(('fix-agent-host', f"agent.properties host={data['agent_host']} -> {ADDRESS}@static"))
    if now - state.get('last_agent_restart', 0) >= RESTART_INTERVAL:
        steps.append(('restart-cloudstack-agent', 'host(s) not Up for 3+ minutes: ' + ', '.join(stuck)))
    return steps


def fix_agent_host(now):
    text = PROPERTIES.read_text()
    stamp = datetime.fromtimestamp(now, timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = PROPERTIES.with_name(PROPERTIES.name + f'.bak-{stamp}')
    backup.write_text(text)
    os.chmod(backup, PROPERTIES.stat().st_mode & 0o777)
    fixed = re.sub(r'^host=.*$', f'host={ADDRESS}@static', text, flags=re.M)
    temp = PROPERTIES.with_name(PROPERTIES.name + '.watchdog-tmp')
    temp.write_text(fixed)
    os.chmod(temp, PROPERTIES.stat().st_mode & 0o777)
    temp.replace(PROPERTIES)
    return f'backup {backup.name}'


def execute(steps, state, now, restart=systemctl_restart):
    actions = []
    for name, detail in steps:
        try:
            if name == 'fix-agent-host':
                result = f'{detail}; ' + fix_agent_host(now)
            else:
                restart('cloudstack-agent')
                state['last_agent_restart'] = now
                result = f'{detail}; restarted'
        except (OSError, subprocess.SubprocessError) as error:
            result = f'failed: {error}'
            if name != 'fix-agent-host':
                state['last_agent_restart'] = now  # a failing restart must not be retried every minute
        actions.append({'at': now, 'action': name, 'result': result})
        print(f'platform-watchdog: {name}: {result}', file=sys.stderr, flush=True)
    return actions


def write_atomic(path, document, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(document, indent=2) + '\n')
    os.chmod(temp, mode)
    temp.replace(path)


def load_state():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def main(dry_run=False, now=None, collector=collect, restart=systemctl_restart):
    now = time.time() if now is None else now
    state = load_state()
    try:
        data = collector()
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        # Never remediate on missing data; just say so.
        status = {'version': 1, 'updated': now, 'healthy': False, 'hosts': [],
                  'management_api': {'reachable': False}, 'system_vms': [], 'capacity': {
                      'cpu_allocated_pct': 0.0, 'memory_allocated_pct': 0.0, 'local_storage_used_pct': None,
                      'cpu_threshold_pct': 0.0, 'memory_threshold_pct': 0.0},
                  'issues': [f'CloudStack database unreadable: {error}'],
                  'actions': list(state.get('actions', []))[-MAX_ACTIONS:]}
        steps, state = [], state
    else:
        status, state = evaluate(data, state, now)
        steps = plan(data, state, now)
    if dry_run:
        print(json.dumps({'status': status, 'planned_actions': [{'action': a, 'detail': d} for a, d in steps]},
                         indent=2))
        return status
    state['actions'] = (state.get('actions', []) + execute(steps, state, now, restart))[-MAX_ACTIONS:]
    status['actions'] = state['actions']
    write_atomic(STATE, state, 0o600)
    write_atomic(STATUS, status, 0o644)
    return status


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true', help='Print status and planned actions; change nothing')
    main(parser.parse_args().dry_run)
