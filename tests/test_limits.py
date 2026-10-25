from types import SimpleNamespace

import pytest

from dirigentenstab.limits import APP_ROOT_AGENT, check_vm_policy, gpu_count


async def test_general_vm_tool_cannot_skip_the_gpu_policy_guard(monkeypatch):
    from dirigentenstab import service as service_module

    audited = []
    store = SimpleNamespace(all=lambda *args: [], audit=lambda *args, **kwargs: audited.append(args))
    service = service_module.Service(store, SimpleNamespace())
    trusted = {'id': 'trusted-agent', 'domain_id': 'leaf'}

    class Cloud:
        async def catalogue(self):
            return {'startVirtualMachine': {'params': [{'name': 'id', 'type': 'uuid', 'required': True}]}}

        async def execute(self, *args, **kwargs):
            pytest.fail('The CloudStack mutation must not run after a denied GPU policy check')

    async def agent(agent_id):
        assert agent_id == trusted['id']
        return trusted

    async def cloud_client(agent):
        return Cloud()

    async def guard(actual_service, actual_agent, params, *, command):
        assert actual_service is service and actual_agent is trusted and command == 'startVirtualMachine'
        raise PermissionError('GPU quota exceeded in ancestor')

    service.agent, service.cloud_client = agent, cloud_client
    monkeypatch.setattr(service_module, 'check_vm_policy', guard)
    with pytest.raises(PermissionError, match='GPU quota exceeded'):
        await service.execute(trusted['id'], 'startVirtualMachine', {'id': '00000000-0000-0000-0000-000000000001'})
    assert audited


@pytest.fixture
def environment():
    domains = {
        'leaf': {'id': 'leaf', 'parentdomainid': 'middle', 'level': 4, 'gpulimit': 'Unlimited', 'gputotal': 0},
        'middle': {'id': 'middle', 'parentdomainid': 'zero', 'level': 3, 'gpulimit': 'Unlimited', 'gputotal': 0},
        'zero': {'id': 'zero', 'parentdomainid': 'agents', 'level': 2, 'gpulimit': 0, 'gputotal': 0},
        'agents': {'id': 'agents', 'parentdomainid': 'native-root', 'level': 1,
                   'gpulimit': 'Unlimited', 'gputotal': 0},
    }
    offerings = {'gpu': {'id': 'gpu', 'gpucount': 1, 'vgpuprofileid': 'profile'},
                 'cpu': {'id': 'cpu', 'gpucount': 0}}
    vm = {'id': 'vm', 'domainid': 'leaf', 'serviceofferingid': 'gpu'}
    calls = []

    class Cloud:
        def __init__(self, root=False):
            self.root = root

        async def raw(self, command, params):
            calls.append((self.root, command, params.copy()))
            if command == 'listDomains':
                domain_id = params['id']
                domain = domains.get(domain_id) if self.root or domain_id == 'leaf' else None
                return {'domain': [domain] if domain else []}
            if command == 'listServiceOfferings':
                offering = offerings.get(params['id'])
                return {'serviceoffering': [offering] if offering else []}
            if command == 'listVirtualMachines':
                return {'virtualmachine': [vm] if params['id'] == vm['id'] else []}
            raise AssertionError(command)

    class Service:
        async def agent(self, agent_id):
            assert agent_id == APP_ROOT_AGENT
            return {'id': agent_id, 'domain_id': 'agents'}

        async def cloud_client(self, agent):
            return Cloud(root=agent['id'] == APP_ROOT_AGENT)

    return SimpleNamespace(service=Service(), agent={'id': 'leaf-agent', 'domain_id': 'leaf'},
                           domains=domains, offerings=offerings, vm=vm, calls=calls)


@pytest.mark.parametrize('command,params', [
    ('deployVirtualMachine', {'serviceofferingid': 'gpu'}),
    ('startVirtualMachine', {'id': 'vm'}),
    ('rebootVirtualMachine', {'id': 'vm'}),
    ('restoreVirtualMachine', {'id': 'vm'}),
    ('recoverVirtualMachine', {'id': 'vm'}),
    ('scaleVirtualMachine', {'id': 'vm', 'serviceofferingid': 'gpu'}),
])
async def test_unlimited_descendant_never_overrides_ancestor_zero(environment, command, params):
    with pytest.raises(PermissionError, match='GPU quota exceeded in ancestor domain zero'):
        await check_vm_policy(environment.service, environment.agent, params, command=command)
    assert not any(command not in {'listDomains', 'listServiceOfferings', 'listVirtualMachines'}
                   for _, command, _ in environment.calls)


async def test_offering_restriction_cannot_be_bypassed_by_a_parent_agents_visibility(environment):
    environment.offerings['gpu']['domainid'] = 'unrelated-domain'
    with pytest.raises(PermissionError, match='restricted to another'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})
    environment.offerings['gpu']['domainid'] = 'zero'
    with pytest.raises(PermissionError, match='GPU quota exceeded'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})


async def test_unknown_ancestor_or_quota_fails_closed(environment):
    environment.domains.pop('zero')
    with pytest.raises(PermissionError, match='every ancestor'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})


async def test_application_root_domain_zero_also_blocks_all_descendants(environment):
    environment.domains['zero']['gpulimit'] = 'Unlimited'
    environment.domains['agents']['gpulimit'] = 0
    with pytest.raises(PermissionError, match='ancestor domain agents'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})
    assert not any(params.get('id') == 'native-root' for _, _, params in environment.calls)


async def test_positive_quota_uses_remaining_allocation_and_native_counter_semantics(environment):
    environment.domains['zero'].update(gpulimit=2, gputotal=1)
    await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})
    environment.domains['zero']['gputotal'] = 2
    with pytest.raises(PermissionError, match='GPU quota exceeded'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})
    # Stopped VMs retain GPUs/count by default; starting an already counted VM does not allocate another.
    await check_vm_policy(environment.service, environment.agent, {'id': 'vm'}, command='startVirtualMachine')


async def test_cpu_operation_does_not_require_gpu_reader_or_gpu_quota(environment):
    await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'cpu'})
    assert not any(root for root, _, _ in environment.calls)


@pytest.mark.parametrize('offering', [
    {'details': {'pciDevice': 'Tesla P40', 'vgpuType': 'passthrough'}},
    {'vgpuprofileid': 'profile'}, {'gpucount': -1}, {'gpucount': 'unknown'},
])
def test_legacy_or_unknown_gpu_count_is_never_treated_as_cpu(offering):
    with pytest.raises(PermissionError):
        gpu_count(offering)


async def test_scale_and_start_resolve_the_vms_actual_owner_domain(environment):
    environment.agent['domain_id'] = 'agents'
    with pytest.raises(PermissionError, match='ancestor domain zero'):
        await check_vm_policy(environment.service, environment.agent, {'id': 'vm'}, command='startVirtualMachine')


async def test_domain_cycles_and_inconsistent_depths_fail_closed(environment):
    environment.domains['middle']['parentdomainid'] = 'leaf'
    with pytest.raises(PermissionError, match='ancestor domains'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})
    environment.domains['middle']['parentdomainid'] = 'zero'
    environment.domains['zero']['level'] = 3
    with pytest.raises(PermissionError, match='levels are inconsistent'):
        await check_vm_policy(environment.service, environment.agent, {'serviceofferingid': 'gpu'})
