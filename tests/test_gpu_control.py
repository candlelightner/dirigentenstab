import asyncio
import copy
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from dirigentenstab.gpu import FLAGS, effective_policy, operation_id, validate_policy
from dirigentenstab.gpu_control import Controller, Journal
from dirigentenstab.limits import APP_ROOT_AGENT
from dirigentenstab.store import Store
from dirigentenstab.cloud import CloudError
from dirigentenstab.diagnostics import OperationError

ROOT, MAIN, CHILD, OTHER = 'root-domain', 'main-domain', 'child-domain', 'other-domain'
P8, P24, P2 = 'nvidia-51', 'nvidia-53', 'nvidia-47'
SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def policy(maximum=3, **overrides):
    return {'profiles': [P8, P24, P2], 'max_allocations': maximum,
            **{flag: True for flag in FLAGS}, **overrides}


class Host:
    def __init__(self):
        self.items, self.attached, self.calls = {}, set(), []
        self.fail_once = False

    def profiles(self):
        return {p: {'id': p, 'name': name, 'maximum': maximum, 'memory': memory, 'heads': 4,
                    'available': 0 if any(x['profile'] != p for x in self.items.values()) else maximum - len(self.items)}
                for p, name, maximum, memory in [(P8, 'GRID P40-8Q', 3, 8192),
                                                (P24, 'GRID P40-24Q', 1, 24576), (P2, 'GRID P40-2Q', 12, 2048)]}

    def devices(self):
        return copy.deepcopy(self.items)

    async def attachments(self):
        return set(self.attached)

    async def create(self, identifier, profile):
        if identifier not in self.items:
            assert self.profiles()[profile]['available'] > 0
            self.calls.append(('create', identifier, profile))
            self.items[identifier] = {'uuid': identifier, 'profile': profile}
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError('Interrupted after kernel mdev creation')

    async def remove(self, identifier):
        assert identifier not in self.attached
        self.calls.append(('remove', identifier, self.items[identifier]['profile']))
        del self.items[identifier]


class Native:
    def __init__(self, host):
        self.host, self.devices, self.vms = host, {}, {}
        self.quotas = {MAIN: 3, CHILD: 2, OTHER: 3}
        self.detach, self.calls, self.pending = {}, [], False
        self.offers = {'o8': {'id': 'o8', 'gpucount': 1, 'vgpuprofilename': 'GRID P40-8Q', 'vgpuprofileid': 'profile8'},
                       'o24': {'id': 'o24', 'gpucount': 1, 'vgpuprofilename': 'GRID P40-24Q', 'vgpuprofileid': 'profile24'},
                       'cpu': {'id': 'cpu', 'gpucount': 0}}
        self.scope = None

    def domains(self):
        result = [{'id': ROOT, 'name': 'ROOT', 'level': 0},
                  {'id': MAIN, 'name': 'Main', 'level': 1, 'parentdomainid': ROOT},
                  {'id': CHILD, 'name': 'Child', 'level': 2, 'parentdomainid': MAIN},
                  {'id': OTHER, 'name': 'Other', 'level': 1, 'parentdomainid': ROOT}]
        for item in result:
            item['gpulimit'] = self.quotas.get(item['id'], -1)
            item['gputotal'] = sum(1 for d in self.devices.values() if d.get('virtualmachineid') in self.vms and
                (self.vms[d['virtualmachineid']]['domainid'] == item['id'] or item['id'] == MAIN and
                 self.vms[d['virtualmachineid']]['domainid'] == CHILD))
        return result

    async def raw(self, command, params=None):
        params = params or {}
        self.calls.append((command, dict(params)))
        if command == 'listDomains':
            values = self.domains()
            if self.scope:
                values = [d for d in values if d['id'] == self.scope or self.scope == MAIN and d['id'] == CHILD]
            return {'domain': [d for d in values if not params.get('id') or d['id'] == params['id']]}
        if command == 'listResourceLimits':
            return {'resourcelimit': [{'max': self.quotas[params['domainid']]}]}
        if command == 'updateResourceLimit':
            self.quotas[params['domainid']] = params['max']
            return {'success': True}
        if command == 'listGpuDevices':
            return {'gpudevice': list(copy.deepcopy(self.devices).values())}
        if command == 'listAsyncJobs':
            return {'asyncjobs': [{'jobstatus': 0}] if self.pending else []}
        if command == 'unmanageGpuDevice':
            self.devices[params['ids']]['managedstate'] = 'Unmanaged'
            return {'success': True}
        if command == 'deleteGpuDevice':
            del self.devices[params['ids']]
            return {'success': True}
        if command == 'discoverGpuDevices':
            for key, item in self.host.items.items():
                self.devices.setdefault(key, {'id': key, 'busaddress': key, 'gpudevicetype': 'MDEV',
                    'hostid': 'host', 'vgpuprofilename': self.host.profiles()[item['profile']]['name'],
                    'state': 'Free', 'managedstate': 'Managed'})
            return {'success': True}
        if command == 'listServiceOfferings':
            return {'serviceoffering': [o for o in self.offers.values() if o['id'] == params.get('id')]}
        if command == 'listVirtualMachines':
            return {'virtualmachine': [copy.deepcopy(v) for v in self.vms.values() if v['id'] == params.get('id')]}
        if command == 'listAccounts':
            return {'account': [{'id': d + '-account', 'name': d + '-owner', 'domainid': d}
                                 for d in (MAIN, CHILD, OTHER) if d + '-account' == params.get('id')]}
        if command == 'updateConfiguration':
            self.detach[params['domainid']] = params['value'] == 'true'
            return {'success': True}
        raise AssertionError(command)

    async def catalogue(self):
        params = [{'name': k, 'type': 'string'} for k in ('id', 'serviceofferingid', 'templateid', 'zoneid')]
        return {name: {'params': params} for name in ('deployVirtualMachine', 'startVirtualMachine',
                'stopVirtualMachine', 'changeServiceForVirtualMachine')}


class Scoped:
    def __init__(self, native, domain):
        self.native, self.domain = native, domain

    async def raw(self, command, params=None):
        old = self.native.scope
        self.native.scope = self.domain
        try:
            return await self.native.raw(command, params)
        finally:
            self.native.scope = old

    async def catalogue(self):
        return await self.native.catalogue()


@pytest.fixture
async def controller(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'app.db'), str(key))
    agents = {APP_ROOT_AGENT: MAIN, 'child': CHILD, 'other': OTHER}
    for aid, domain in agents.items():
        store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                      (aid, aid, domain, domain+'-account', aid+'-user', store.seal({})))
        store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                      ('conversation-'+aid, aid, 'human', 'GPU task', 1, store.seal([])))
        store.execute('INSERT INTO chat_runs(id,conversation_id,status,agent_id,created,updated,events) VALUES(?,?,?,?,?,?,?)',
                      ('run-'+aid, 'conversation-'+aid, 'running', aid, 1, 1, store.seal([])))
    store.execute('INSERT INTO managed_templates(id,name) VALUES(?,?)', ('base', 'Synthetic base'))
    store.execute('INSERT INTO sessions VALUES(?,?,?,?)', ('human-session', 'csrf', store.seal(
                  {'userid': 'human', 'account': 'admin', 'domainid': ROOT, 'type': 1}), 99999999999))
    host, native = Host(), None
    native = Native(host)
    class Service:
        human_type = 1
        gpu_local = False
        async def agent(self, aid):
            value = store.one('SELECT * FROM agents WHERE id=?', (aid,))
            if not value:
                raise PermissionError('Unknown agent')
            return value
        async def cloud_client(self, agent):
            return Scoped(native, agent['domain_id'])
        async def authorize(self, identity, aid):
            agent = await self.agent(aid)
            allowed = {identity['domainid']}
            if identity['domainid'] == MAIN:
                allowed.add(CHILD)
            if identity['type'] != 1 and agent['domain_id'] not in allowed:
                raise PermissionError('Agent outside your CloudStack domain')
            return agent
        async def human_call(self, identity, command, params):
            if command == 'listUsers':
                return {'user': [{'id': identity['userid'], 'state': 'enabled'}]}
            return {'account': [{'name': identity['account'], 'domainid': identity['domainid'],
                                 'accounttype': self.human_type, 'state': 'enabled'}]}
        def redact(self, value):
            return value
        async def recover_deployments(self, operation_id=None):
            return
        async def execute(self, aid, command, params, *, managed=False):
            assert managed == (command == 'deployVirtualMachine')
            assert self.gpu_local, 'Controller native dispatch must not re-enter the GPU helper'
            await asyncio.sleep(.01)
            if command == 'deployVirtualMachine':
                agent = await self.agent(aid)
                vm_id = 'vm-'+str(len(native.vms))
                offering = native.offers[params['serviceofferingid']]
                device = next(d for d in native.devices.values() if d['state'] == 'Free' and
                              d['managedstate'] == 'Managed' and d['vgpuprofilename'] == offering['vgpuprofilename'])
                device.update(state='Allocated', virtualmachineid=vm_id)
                host.attached.add(device['busaddress'])
                vm = {'id': vm_id, 'state': 'Running', 'domainid': agent['domain_id'],
                      'account': agent['domain_id']+'-owner', 'serviceofferingid': offering['id']}
                native.vms[vm_id] = vm
                store.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key) VALUES(?,?,?,?)',
                              (vm_id, aid, 'dirigent', store.seal('synthetic')))
                store.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,?,?,?)',
                              (self.gpu_deployment_id, aid, 'managed-'+vm_id, store.seal(params), vm_id, 'complete', 1))
            else:
                vm = native.vms[params['id']]
                if command == 'stopVirtualMachine':
                    vm['state'] = 'Stopped'
                elif command == 'changeServiceForVirtualMachine':
                    vm['serviceofferingid'] = params['serviceofferingid']
                for device in native.devices.values():
                    if device.get('virtualmachineid') == vm['id']:
                        host.attached.discard(device['busaddress'])
                        if command == 'changeServiceForVirtualMachine' or native.detach.get(vm['domainid']):
                            device.pop('virtualmachineid', None)
                            device['state'] = 'Free'
            return {'virtualmachine': copy.deepcopy(vm)}
    service = Service()
    service.store = store
    c = Controller(service, native, Journal(tmp_path / 'root-policy.db'), host, 'host')
    for domain, maximum in ((ROOT, -1), (MAIN, 3), (CHILD, 2), (OTHER, 3)):
        await c.dispatch({'action': 'set_policy', 'session': 'human-session', 'domain_id': domain,
                          'policy': policy(maximum)}, 10001)
    return c


def request(call, command='deployVirtualMachine', agent=APP_ROOT_AGENT, **params):
    if command == 'deployVirtualMachine':
        params = {'templateid': 'base', 'serviceofferingid': 'o8', 'zoneid': 'zone', **params}
    return {'action': 'execute', 'session': 'human-session', 'agent_id': agent, 'command': command, 'params': params,
            'context': {'run_id': 'run-'+agent, 'call_id': call}}


@pytest.fixture
async def gpu_socket(controller, tmp_path, monkeypatch):
    from dirigentenstab import gpu

    monkeypatch.syspath_prepend(str(SCRIPTS))
    from gpu_helper import connection

    unpack = gpu.struct.unpack
    def root_peer(format, data):
        values = unpack(format, data)
        return (values[0], 0, values[2]) if format == '3i' else values
    monkeypatch.setattr(gpu.struct, 'unpack', root_peer)
    path = str(tmp_path / 's')
    async with await asyncio.start_unix_server(lambda r, w: connection(controller, r, w), path=path,
                                               limit=65537):
        yield SimpleNamespace(gpu_helper_socket=path)


@pytest.mark.parametrize('changed', [False, True])
async def test_definitive_gpu_rejection_crosses_socket_and_releases_operation_block(controller, gpu_socket,
                                                                                 monkeypatch, changed, caplog):
    from dirigentenstab.gpu import helper_call

    if not changed:
        identifier = '00000000-0000-0000-0000-000000000100'
        await controller.host.create(identifier, P8)
        controller.journal.write('INSERT INTO pools VALUES(?,?,?)', (identifier, MAIN, P8))
        await controller.cloud.raw('discoverGpuDevices')
    original = controller.service.execute
    reason = 'rootdisksize override (20 GB) is smaller than template size (25 GB)'

    async def rejected(aid, command, params, **options):
        controller.service.store.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,?,?,?)',
            (controller.service.gpu_deployment_id, aid, 'rejected-vm', controller.service.store.seal(params),
             None, 'rejected', 1))
        raise CloudError('private-payload', rejected=True, public_detail=reason)
    monkeypatch.setattr(controller.service, 'execute', rejected)
    payload = request('native-rejection')
    with pytest.raises(CloudError) as failure:
        await helper_call(gpu_socket, payload.pop('action'), **payload)
    assert failure.value.rejected and failure.value.public_detail == reason
    assert reason in str(failure.value) and 'private-payload' not in str(failure.value) + caplog.text
    receipt = controller.journal.rows('SELECT phase,changed FROM operations')[0]
    assert receipt == {'phase': 'failed', 'changed': int(changed)}
    assert not controller.cloud.vms and len(controller.host.items) == 1
    before = list(controller.host.calls)
    monkeypatch.setattr(controller.service, 'execute', original)
    corrected = request('corrected-deployment', templateid='smaller-base')
    result = await helper_call(gpu_socket, corrected.pop('action'), **corrected)
    assert result['virtualmachine']['state'] == 'Running' and controller.host.calls == before


@pytest.mark.parametrize('failure', ['transport', 'async-job', 'poll-denial'])
async def test_uncertain_gpu_dispatch_stays_blocked_across_socket(controller, gpu_socket, monkeypatch, failure):
    from dirigentenstab.gpu import helper_call

    calls = []
    async def uncertain(aid, command, params, **options):
        calls.append(command)
        controller.service.store.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,?,?,?)',
            (controller.service.gpu_deployment_id, aid, 'pending-vm', controller.service.store.seal(params),
             None, 'dispatched', 1))
        if failure == 'transport':
            raise RuntimeError('Native dispatch interrupted')
        raise CloudError('Native outcome needs review', rejected=failure == 'poll-denial',
                         public_detail='Polling denied' if failure == 'poll-denial' else 'No destination found')
    monkeypatch.setattr(controller.service, 'execute', uncertain)
    payload = request('uncertain-dispatch')
    with pytest.raises(OperationError) as error:
        await helper_call(gpu_socket, payload.pop('action'), **payload)
    assert error.value.reconciliation
    assert controller.journal.rows('SELECT phase FROM operations')[0]['phase'] == 'reconciliation'
    with pytest.raises(RuntimeError, match='Another GPU operation requires reconciliation'):
        await controller.dispatch(request('do-not-repeat'), 10001)
    assert calls == ['deployVirtualMachine']


async def test_gpu_rediscovery_rejection_after_success_does_not_close_dispatch_failed(controller, gpu_socket, monkeypatch):
    from dirigentenstab.gpu import helper_call

    original = controller.cloud.raw
    async def rediscovery(command, params=None):
        if command == 'discoverGpuDevices' and controller.cloud.vms:
            raise CloudError('Native discovery denied', rejected=True)
        return await original(command, params)
    monkeypatch.setattr(controller.cloud, 'raw', rediscovery)
    payload = request('post-dispatch-discovery')
    with pytest.raises(OperationError) as error:
        await helper_call(gpu_socket, payload.pop('action'), **payload)
    assert error.value.reconciliation and len(controller.cloud.vms) == 1
    assert controller.journal.rows('SELECT phase FROM operations')[0]['phase'] == 'reconciliation'


def test_policy_ancestors_only_narrow_and_missing_fields_deny():
    chain = [{'id': ROOT}, {'id': MAIN}, {'id': CHILD}]
    docs = {ROOT: policy(-1), MAIN: policy(3), CHILD: policy(1, profiles=[P8], reconfigure_unused=False)}
    effective = effective_policy(chain, docs)
    assert effective['profiles'] == {P8} and effective['max_allocations'] == 1 and not effective['reconfigure_unused']
    del docs[MAIN]
    effective = effective_policy(chain, docs)
    assert not effective['profiles'] and effective['max_allocations'] == 0 and not any(effective[f] for f in FLAGS)
    with pytest.raises(ValueError):
        validate_policy({'profiles': [P8]}, [P8])


async def test_helper_rejects_untrusted_peer_forged_role_and_child_escalation(controller):
    with pytest.raises(PermissionError, match='backend'):
        await controller.dispatch(request('bad-peer'), 1000)
    controller.service.human_type = 2
    with pytest.raises(PermissionError, match='human platform'):
        await controller.dispatch({'action': 'set_policy', 'session': 'human-session', 'domain_id': MAIN,
                                   'policy': policy(3)}, 10001)
    controller.service.human_type = 1
    with pytest.raises(PermissionError, match='ancestor'):
        await controller.dispatch({'action': 'set_policy', 'session': 'human-session', 'domain_id': CHILD,
                                   'policy': policy(4)}, 10001)
    with pytest.raises(PermissionError):
        await controller.dispatch({**request('bad'), 'policy': policy(99)}, 10001)
    forged = request('identity', agent='child')
    forged['context']['run_id'] = 'run-'+APP_ROOT_AGENT
    with pytest.raises(PermissionError, match='server-side'):
        await controller.dispatch(forged, 10001)


async def test_serialized_three_8q_to_one_24q_and_idempotence(controller):
    calls = [request('eight-'+str(i)) for i in range(3)]
    results = await asyncio.gather(*(controller.dispatch(r, 10001) for r in calls))
    assert len(controller.host.items) == 3 and len({r['virtualmachine']['id'] for r in results}) == 3
    assert all(x['profile'] == P8 for x in controller.host.items.values())
    assert await controller.dispatch(calls[0], 10001) == results[0]
    assert len(controller.cloud.vms) == 3
    for index, result in enumerate(results):
        vm = result['virtualmachine']
        await controller.dispatch(request('stop-'+str(index), 'stopVirtualMachine', id=vm['id']), 10001)
        await controller.dispatch(request('cpu-'+str(index), 'changeServiceForVirtualMachine',
                                           id=vm['id'], serviceofferingid='cpu'), 10001)
    result = await controller.dispatch(request('full', serviceofferingid='o24'), 10001)
    assert result['virtualmachine']['serviceofferingid'] == 'o24'
    assert len(controller.host.items) == 1 and next(iter(controller.host.items.values()))['profile'] == P24
    assert sum(c[0] == 'remove' for c in controller.host.calls) == 3


async def test_domain_admin_can_reconfigure_unused_owned_24q_for_managed_8q(controller):
    first = await controller.dispatch(request('full-first', serviceofferingid='o24'), 10001)
    vm_id = first['virtualmachine']['id']
    await controller.dispatch(request('stop-full', 'stopVirtualMachine', id=vm_id), 10001)
    await controller.dispatch(request('release-full', 'changeServiceForVirtualMachine',
                                      id=vm_id, serviceofferingid='cpu'), 10001)
    controller.service.human_type = 2
    controller.service.store.execute('UPDATE sessions SET identity=? WHERE token_hash=?', (
        controller.service.store.seal({'userid': 'human', 'account': 'admin', 'domainid': MAIN, 'type': 2}),
        'human-session'))
    new = request('registered-image', templateid='new-private-cloud-image')
    proof = await controller.dispatch({**new, 'action': 'authorize'}, 10001)
    assert proof['profile'] == P8
    assert len(controller.host.items) == 1 and next(iter(controller.host.items.values()))['profile'] == P24
    results = [await controller.dispatch(new, 10001)]
    results.extend([await controller.dispatch(request('eight-next-'+str(i)), 10001) for i in range(2)])
    assert len({r['virtualmachine']['id'] for r in results}) == 3
    assert len(controller.host.items) == 3 and all(d['profile'] == P8 for d in controller.host.items.values())
    assert sum(call[0] == 'remove' for call in controller.host.calls) == 1
    assert not controller.service.gpu_local and controller.service.gpu_deployment_id is None
    receipt = await controller.dispatch({'action': 'result', 'session': 'human-session',
        'operation_id': operation_id(new['context']), 'run_id': new['context']['run_id']}, 10001)
    assert receipt['phase'] == 'completed' and receipt['result'] == results[0]


@pytest.mark.parametrize('action', ['execute', 'authorize'])
async def test_gpu_dispatch_rejects_another_humans_durable_run(controller, action):
    original = request('human-owned')
    await controller.dispatch(original, 10001)
    controller.service.store.execute('INSERT INTO sessions VALUES(?,?,?,?)', (
        'another-session', 'csrf', controller.service.store.seal(
            {'userid': 'another-human', 'account': 'admin', 'domainid': ROOT, 'type': 1}), 99999999999))
    before = list(controller.host.calls)
    with pytest.raises(PermissionError, match='human conversation owner'):
        await controller.dispatch({**original, 'session': 'another-session', 'action': action}, 10001)
    assert controller.host.calls == before and len(controller.cloud.vms) == 1


async def test_domain_admin_gpu_dispatch_stays_within_human_scope(controller):
    controller.service.human_type = 2
    controller.service.store.execute('UPDATE sessions SET identity=? WHERE token_hash=?', (
        controller.service.store.seal({'userid': 'human', 'account': 'admin', 'domainid': OTHER, 'type': 2}),
        'human-session'))
    with pytest.raises(PermissionError, match='outside your CloudStack domain'):
        await controller.dispatch(request('outside-human-domain'), 10001)
    with pytest.raises(PermissionError, match='human platform'):
        await controller.dispatch({'action': 'set_policy', 'session': 'human-session', 'domain_id': OTHER,
                                   'policy': policy(3)}, 10001)
    assert not controller.host.calls


async def test_failed_native_dispatch_restores_controller_local_guard(controller, monkeypatch):
    async def fail(*args, **kwargs):
        assert controller.service.gpu_local
        raise RuntimeError('Native dispatch interrupted')
    monkeypatch.setattr(controller.service, 'execute', fail)
    with pytest.raises(RuntimeError, match='interrupted'):
        await controller.dispatch(request('native-failure'), 10001)
    assert not controller.service.gpu_local and controller.service.gpu_deployment_id is None
    assert controller.journal.rows('SELECT phase FROM operations')[0]['phase'] == 'reconciliation'


@pytest.mark.parametrize('blocked', ['foreign', 'unknown', 'allocated', 'reserved', 'attached'])
async def test_pool_transition_never_changes_foreign_unknown_allocated_or_reserved(controller, blocked):
    result = await controller.dispatch(request('first'), 10001)
    vm_id = result['virtualmachine']['id']
    await controller.dispatch(request('stop', 'stopVirtualMachine', id=vm_id), 10001)
    item = next(iter(controller.host.items))
    if blocked == 'foreign':
        controller.journal.write('UPDATE pools SET domain_id=?', (OTHER,))
    elif blocked == 'unknown':
        controller.journal.write('DELETE FROM pools')
    elif blocked == 'allocated':
        controller.cloud.devices[item].update(state='Allocated', virtualmachineid='unrelated-vm')
    elif blocked == 'reserved':
        controller.cloud.devices[item]['virtualmachineid'] = 'reserved-vm'
    else:
        controller.host.attached.add(item)
    before = list(controller.host.calls)
    with pytest.raises(PermissionError):
        await controller.dispatch(request('change', serviceofferingid='o24'), 10001)
    assert controller.host.calls == before and item in controller.host.items


async def test_stale_cloudstack_free_state_never_reuses_an_attached_device(controller):
    result = await controller.dispatch(request('first'), 10001)
    item = next(iter(controller.host.items))
    assert item in controller.host.attached
    controller.cloud.devices[item].update(state='Free', virtualmachineid=None)
    before = list(controller.host.calls)
    with pytest.raises(PermissionError, match='disagrees with libvirt'):
        await controller.dispatch(request('second'), 10001)
    assert controller.host.calls == before
    assert list(controller.cloud.vms) == [result['virtualmachine']['id']]


@pytest.mark.parametrize('action', ['execute', 'authorize'])
async def test_agent_context_cannot_trigger_host_controller_without_human_session(controller, action):
    request_without_session = {key: value for key, value in request('agent-only').items() if key != 'session'}
    request_without_session['action'] = action
    before = list(controller.cloud.calls)
    with pytest.raises(PermissionError, match='unauthorized operations or fields'):
        await controller.dispatch(request_without_session, 10001)
    with pytest.raises(PermissionError, match='current human platform-administrator'):
        await controller.dispatch({**request_without_session, 'session': 'missing-session'}, 10001)
    assert controller.cloud.calls == before
    assert controller.host.calls == []


async def test_subgroup_restrictions_and_native_quota_drift_fail_closed(controller):
    await controller.dispatch({'action': 'set_policy', 'session': 'human-session', 'domain_id': MAIN,
                               'policy': policy(3, subgroup_requests=False)}, 10001)
    with pytest.raises(PermissionError, match='Subgroup'):
        await controller.dispatch(request('child', agent='child'), 10001)
    controller.cloud.quotas[MAIN] = 20
    with pytest.raises(PermissionError, match='quota'):
        await controller.dispatch(request('drift'), 10001)
    assert not controller.host.calls


async def test_interrupted_mdev_creation_recovers_without_duplicate_devices(controller):
    controller.host.fail_once = True
    saved = request('interrupted')
    with pytest.raises(RuntimeError, match='Interrupted'):
        await controller.dispatch(saved, 10001)
    assert len(controller.host.items) == 1
    result = await controller.dispatch(saved, 10001)
    assert result['virtualmachine']['state'] == 'Running'
    assert len(controller.host.items) == 1 and len(controller.cloud.vms) == 1
    assert controller.journal.rows('SELECT phase FROM operations')[0]['phase'] == 'completed'


async def test_lost_completed_result_is_reconciled_without_another_vm(controller):
    saved = request('lost-result')
    result = await controller.dispatch(saved, 10001)
    identifier = operation_id(saved['context'])
    controller.journal.phase(identifier, 'reconciliation')
    restored = await controller.dispatch(saved, 10001)
    assert restored['recovered'] and restored['virtualmachine']['id'] == result['virtualmachine']['id']
    assert len(controller.cloud.vms) == 1


async def test_parent_can_release_subgroup_but_sibling_cannot_touch_its_device(controller):
    result = await controller.dispatch(request('child-owned', agent='child'), 10001)
    vm_id = result['virtualmachine']['id']
    with pytest.raises(PermissionError):
        await controller.dispatch(request('foreign-stop', 'stopVirtualMachine', agent='other', id=vm_id), 10001)
    stopped = await controller.dispatch(request('parent-stop', 'stopVirtualMachine', id=vm_id), 10001)
    assert stopped['virtualmachine']['state'] == 'Stopped'
    assert all(d['state'] == 'Free' for d in controller.cloud.devices.values())


async def test_allocated_device_cannot_race_pool_reconfiguration(controller, monkeypatch):
    result = await controller.dispatch(request('initial'), 10001)
    await controller.dispatch(request('stop', 'stopVirtualMachine', id=result['virtualmachine']['id']), 10001)
    original = controller.cloud.raw
    async def race(command, params=None):
        response = await original(command, params)
        if command == 'unmanageGpuDevice':
            controller.cloud.devices[params['ids']].update(state='Allocated', virtualmachineid='racing-job')
        return response
    monkeypatch.setattr(controller.cloud, 'raw', race)
    before = list(controller.host.calls)
    with pytest.raises(PermissionError, match='allocated'):
        await controller.dispatch(request('reconfigure', serviceofferingid='o24'), 10001)
    assert controller.host.calls == before
    assert controller.journal.rows("SELECT changed FROM operations WHERE phase='preparing'")[0]['changed'] == 1


async def test_context_cannot_change_arguments_and_unknown_actions_never_reach_host(controller):
    saved = request('stable')
    await controller.dispatch(saved, 10001)
    with pytest.raises(PermissionError, match='different arguments'):
        await controller.dispatch({**saved, 'params': {**saved['params'], 'zoneid': 'another-zone'}}, 10001)
    with pytest.raises(PermissionError):
        await controller.dispatch({'action': 'shell', 'command': 'arbitrary-host-command'}, 10001)
    assert len(controller.host.calls) == 1


async def test_controller_result_is_bound_to_the_original_human_and_agent(controller):
    saved = request('receipt')
    result = await controller.dispatch(saved, 10001)
    response = await controller.dispatch({'action': 'result', 'session': 'human-session',
        'operation_id': operation_id(saved['context']), 'run_id': saved['context']['run_id']}, 10001)
    assert response['result'] == result and response['phase'] == 'completed'
    with pytest.raises(PermissionError):
        await controller.dispatch({'action': 'result', 'session': 'human-session',
            'operation_id': operation_id(saved['context']), 'run_id': 'run-child'}, 10001)
