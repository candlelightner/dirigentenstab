#!/usr/bin/env python3
"""Real, explicitly invoked CloudStack/KVM acceptance. Creates two tracked test VMs."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time

from dotenv import dotenv_values

from dirigentenstab.cloud import CloudError
from dirigentenstab.guest import Guest
from dirigentenstab.service import Service
from dirigentenstab.settings import Settings
from dirigentenstab.store import Store

ROOT = Path(__file__).resolve().parent.parent
STATE = Path('/var/lib/dirigentenstab/setup/live-acceptance.json')


def prepare():
    env = dotenv_values(ROOT / '.env')
    volume = json.loads(subprocess.check_output(['docker', 'volume', 'inspect', 'dirigentenstab_data']))[0]
    data = Path(volume['Mountpoint'])
    settings = Settings(env['CLOUDSTACK_URL'], env['PUBLIC_ORIGIN'], cmk='/usr/local/bin/cmk',
                        workspace=str(data / 'transfers'), ssh_networks=env.get('SSH_NETWORKS', '10.253.80.0/24'),
                        ssh_source_cidr=env.get('SSH_SOURCE_CIDR', '10.253.80.1/32'),
                        max_hierarchy_depth=int(env.get('MAX_HIERARCHY_DEPTH', '10')))
    store = Store(str(data / 'dirigentenstab.db'), str(ROOT / env.get('MASTER_KEY_PATH', 'secrets/master_key')))
    return Service(store, settings), json.loads(Path('/var/lib/dirigentenstab/setup/zone.json').read_text())


def save(state):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2))
    temporary.chmod(0o600)
    temporary.replace(STATE)


async def acceptance(app, zone):
    previous = await asyncio.to_thread(lambda: STATE.read_text() if STATE.exists() else '')
    state = json.loads(previous) if previous else {'started': time.time()}
    root = app.store.one('SELECT id FROM agents WHERE id=?', ('00000000000000000000000000000001',))
    if not root:
        raise RuntimeError('Complete application bootstrap before running acceptance')
    agents = {}
    for name in ('Research', 'Development'):
        agents[name] = await app.create_subgroup(root['id'], name)
    guest = Guest(app)
    for name, agent in agents.items():
        key = name.lower() + '_vm'
        if key not in state:
            previous = app.store.one("SELECT id,vm_id,phase FROM vm_deployments WHERE agent_id=? AND phase<>'rejected' "
                                     'ORDER BY updated DESC LIMIT 1', (agent['id'],))
            if previous:
                await app.recover_deployments()
                recovered = app.store.one("SELECT vm_id FROM vm_deployments WHERE id=? AND phase='complete'", (previous['id'],))
                if not recovered:
                    raise RuntimeError('A previous VM deployment is ambiguous. Use scripts/admin.py status and recovery.')
                state[key] = recovered['vm_id']
            else:
                result = await app.execute(agent['id'], 'deployVirtualMachine', {
                    'zoneid': zone['zone_id'], 'templateid': zone['template_id'],
                    'serviceofferingid': zone['service_offering_id'],
                    'displayname': 'Dirigentenstab acceptance ' + name,
                })
                vm = result['virtualmachine']
                state[key] = vm[0]['id'] if isinstance(vm, list) else vm['id']
            save(state)
            print(name + ' real KVM VM created', flush=True)
    research = agents['Research']['id']
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        result = await guest.run_vm_command(research, state['research_vm'], 'python3 -c "print(6 * 7)"', 30)
        if result['exit_code'] == 0 and result['stdout'].strip() == '42':
            break
        await asyncio.sleep(5)
    else:
        raise RuntimeError('Guest Python/SSH did not become ready; inspect private CloudStack Events and cloud-init')
    state['python'] = {'exit_code': result['exit_code'], 'stdout': result['stdout'].strip()}
    failure = await guest.run_vm_command(research, state['research_vm'],
                                         'python3 -c \'assert 2 + 2 == 5, "intentional acceptance failure"\'')
    assert failure['exit_code'] != 0 and 'AssertionError' in failure['stderr'], 'Failing test was not diagnosed'
    state['intentional_failure'] = {'exit_code': failure['exit_code'], 'assertion_error': True}
    workspace = guest._workspace(research)
    upload = workspace / 'acceptance-upload.txt'
    await asyncio.to_thread(upload.write_text, 'dirigentenstab real SFTP round trip\n')
    await guest.transfer_vm_file(research, state['research_vm'], upload.name, '/tmp/acceptance-transfer.txt', 'upload')
    await guest.transfer_vm_file(research, state['research_vm'], '/tmp/acceptance-transfer.txt',
                                 'acceptance-download.txt', 'download')
    assert await asyncio.to_thread((workspace / 'acceptance-download.txt').read_text) == await asyncio.to_thread(upload.read_text)
    state['file_roundtrip'] = True
    result = await guest.run_vm_command(research, state['research_vm'],
                                        'id -u; if sudo -n true 2>/dev/null; then exit 91; fi; '
                                        'test ! -e /var/run/docker.sock; test ! -e /run/libvirt/libvirt-sock')
    assert result['exit_code'] == 0 and result['stdout'].strip() != '0', 'Guest unexpectedly has privileged access'
    state['guest_nonroot_no_sudo_or_host_sockets'] = True
    try:
        await guest.run_vm_command(research, state['development_vm'], 'true')
    except (PermissionError, CloudError):
        state['unrelated_vm_denied'] = True
    else:
        raise AssertionError('Research agent accessed Development VM')
    for command, params in [('createStoragePool', {}), ('addHost', {}),
                            ('updateVirtualMachine', {'id': state['research_vm'], 'extraconfig': '/etc/shadow'})]:
        try:
            await app.execute(research, command, params)
        except (PermissionError, ValueError):
            pass
        else:
            raise AssertionError('Platform-only operation was permitted')
    state.update(host_operations_denied=True, passed=True, completed=time.time(), cloudstack='4.23.0.0')
    save(state)
    # Workspaces remain private and readable by the application's unprivileged container user.
    for path in [Path(app.settings.workspace), workspace, *workspace.iterdir()]:
        os.chown(path, 10001, 10001)
    print(json.dumps({key: state[key] for key in ('passed', 'cloudstack', 'python', 'intentional_failure',
                                                'file_roundtrip', 'guest_nonroot_no_sudo_or_host_sockets',
                                                'unrelated_vm_denied', 'host_operations_denied')}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='Explicitly create/use tracked acceptance VMs')
    args = parser.parse_args()
    if not args.run or os.geteuid() != 0:
        parser.error('Run as root with --run; this creates real test VMs in the configured cloud.')
    asyncio.run(acceptance(*prepare()))
