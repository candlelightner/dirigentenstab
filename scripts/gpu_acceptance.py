#!/usr/bin/env python3
"""Real GPU quota/domain tests. No GPU device assignment or driver changes."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import time
import uuid

from dirigentenstab.cloud import Cloud, CloudError, validate
from dirigentenstab.limits import APP_ROOT_AGENT, check_vm_policy
from dirigentenstab.settings import Settings
from live_acceptance import prepare

STATE = Path('/var/lib/dirigentenstab/setup/gpu-acceptance.json')
GPU_RESOURCE_TYPE = 16


def save(state):
    temporary = STATE.with_suffix('.tmp')
    with temporary.open('w') as handle:
        json.dump(state, handle, indent=2)
        handle.write('\n')
    temporary.chmod(0o600)
    temporary.replace(STATE)


async def acceptance(app, zone, platform, state):
    async def trace(command, params, result):
        state.setdefault('trace', []).append({'time': time.time(), 'command': command,
                                              'params': params, 'result': app.redact(result)})
        await asyncio.to_thread(save, state)

    async def admin(command, params):
        metadata = next((value for value in (await platform.raw('listApis', {'name': command})).get('api', [])
                         if value['name'] == command), None)
        if not metadata:
            raise RuntimeError('Required CloudStack API unavailable: ' + command)
        validate(metadata, params, runtime=False)
        result = await platform.raw(command, params)
        await trace(command, params, {'accepted': True})
        return result

    groups = {}
    for label, parent, name in [('parent', APP_ROOT_AGENT, 'GPU quota acceptance'),
                                 ('middle', 'parent', 'Nested'), ('leaf', 'middle', 'Leaf'),
                                 ('other', 'parent', 'Other')]:
        parent_id = groups[parent]['id'] if parent in groups else parent
        groups[label] = await app.create_subgroup(parent_id, name)
        state.setdefault('agents', {})[label] = groups[label]['id']
        await asyncio.to_thread(save, state)
    for label, maximum in [('parent', 0), ('middle', -1), ('leaf', -1)]:
        await admin('updateResourceLimit', {'domainid': groups[label]['domain_id'],
                                          'resourcetype': GPU_RESOURCE_TYPE, 'max': maximum})
        actual = await platform.raw('listResourceLimits', {'domainid': groups[label]['domain_id'],
                                                          'resourcetype': GPU_RESOURCE_TYPE})
        limits = actual.get('resourcelimit', [])
        if not any(int(limit['resourcetype']) == GPU_RESOURCE_TYPE and int(limit['max']) == maximum
                   for limit in limits):
            raise RuntimeError('CloudStack did not persist the requested GPU domain quota')
        await trace('listResourceLimits', {'domain': label},
                    {'resourcetype': GPU_RESOURCE_TYPE, 'max': maximum})

    profiles = (await platform.raw('listVgpuProfiles')).get('vgpuprofile', [])
    profile = next((value for value in profiles if value.get('name') == 'passthrough'), None)
    if not profile:
        raise RuntimeError('No real discovered GPU passthrough profile is available; do not fabricate a device')
    state['profile_id'] = profile['id']
    for label, domain in [('visible', 'parent'), ('restricted', 'other')]:
        name = 'Dirigentenstab-GPU-' + label + '-' + state['operation'][:12]
        offerings = (await platform.raw('listServiceOfferings', {'name': name, 'listall': True})).get('serviceoffering', [])
        offering = next((value for value in offerings if value.get('name') == name), None)
        if not offering:
            offering = (await admin('createServiceOffering', {
                'name': name, 'displaytext': 'Owned GPU quota acceptance; no hardware allocation',
                'cpunumber': 1, 'cpuspeed': 1000, 'memory': 512, 'storagetype': 'local',
                'domainid': groups[domain]['domain_id'], 'vgpuprofileid': profile['id'], 'gpucount': 1,
            }))['serviceoffering']
        state.setdefault('offerings', {})[label] = offering['id']
        await asyncio.to_thread(save, state)
    leaf = await app.agent(groups['leaf']['id'])
    leaf_cloud = await app.cloud_client(leaf)
    requests = {
        label: {'zoneid': zone['zone_id'], 'templateid': zone['template_id'],
                'serviceofferingid': offering_id, 'startvm': False,
                'name': 'ds-gpu-' + label + '-' + state['operation'][:12]}
        for label, offering_id in state['offerings'].items()
    }
    try:
        await check_vm_policy(app, leaf, requests['visible'])
    except PermissionError as exc:
        message = str(exc)
        if 'GPU quota exceeded' not in message or groups['parent']['domain_id'] not in message:
            raise
        await trace('backend GPU policy', {'offering': 'visible'}, {'denied': message})
    else:
        raise AssertionError('Backend accepted GPU allocation beneath an ancestor GPU quota of zero')
    for label in ('visible', 'restricted'):
        # startvm=false guarantees no hardware assignment even if a native quota regression is found.
        try:
            result = await leaf_cloud.execute('deployVirtualMachine', requests[label])
        except CloudError as exc:
            message = str(exc)
            if label == 'visible' and not all(word in message.lower() for word in ('gpu', 'limit', 'exceed')):
                raise AssertionError('Expected an actual GPU quota error, not missing GPU hardware: ' + message) from exc
            if label == 'restricted' and (not all(word in message.lower() for word in ('access', 'offering'))
                                         or all(word in message.lower() for word in ('gpu', 'limit', 'exceed'))):
                raise AssertionError('Restricted offering must fail explicit domain access, not quota or transport') from exc
            await trace('deployVirtualMachine', {'offering': label, 'actor': 'leaf DomainAdmin', 'startvm': False},
                        {'denied': message})
        else:
            vm = result.get('virtualmachine', {})
            vm = vm[0] if isinstance(vm, list) and vm else vm
            state.setdefault('unexpected_stopped_vms', []).append(vm.get('id'))
            await asyncio.to_thread(save, state)
            raise AssertionError('CloudStack unexpectedly accepted GPU deployment; stopped VM ID tracked for review')
    restricted = (await leaf_cloud.raw('listServiceOfferings', {'id': state['offerings']['restricted']})).get(
        'serviceoffering', [])
    if restricted:
        raise AssertionError('Leaf agent can list an unrelated-domain GPU compute offering')
    try:
        await check_vm_policy(app, leaf, requests['restricted'])
    except PermissionError:
        state['backend_restricted_offering_denied'] = True
    else:
        raise AssertionError('Backend accepted an unrelated-domain GPU compute offering')
    state.update(passed=True, completed=time.time(), cloudstack='4.23.0.0', gpu_resource_type=GPU_RESOURCE_TYPE,
                 ancestor_gpu_zero_native_denied=True, descendant_unlimited_did_not_bypass=True,
                 restricted_offering_native_denied=True, no_gpu_assignment_attempted=True)
    await asyncio.to_thread(save, state)
    print(json.dumps({key: state[key] for key in ('passed', 'cloudstack', 'gpu_resource_type',
                      'ancestor_gpu_zero_native_denied', 'descendant_unlimited_did_not_bypass',
                      'restricted_offering_native_denied', 'backend_restricted_offering_denied',
                      'no_gpu_assignment_attempted')}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='Create tracked test domains, quotas and GPU offering metadata')
    options = parser.parse_args()
    if not options.run or os.geteuid() != 0:
        parser.error('Run as root with --run; this changes only owned test domains and offering metadata')
    state = json.loads(STATE.read_text()) if STATE.exists() else {'operation': uuid.uuid4().hex, 'started': time.time()}
    save(state)
    credentials = json.loads(Path('/var/lib/dirigentenstab/setup/cloudstack-admin.json').read_text())
    platform = Cloud(Settings(credentials['url'], 'https://localhost', cmk='/usr/local/bin/cmk'),
                     {key: credentials[key] for key in ('apikey', 'secretkey')})
    app, zone = prepare()
    asyncio.run(acceptance(app, zone, platform, state))


if __name__ == '__main__':
    main()
