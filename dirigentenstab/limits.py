"""GPU preflight checks; CloudStack retains atomic quota accounting and permissions."""

APP_ROOT_AGENT = '00000000000000000000000000000001'
VM_POLICY_COMMANDS = frozenset({'deployVirtualMachine', 'startVirtualMachine', 'rebootVirtualMachine', 'scaleVirtualMachine',
                                'restoreVirtualMachine', 'recoverVirtualMachine', 'changeServiceForVirtualMachine'})


def gpu_count(offering):
    details = offering.get('details') or {}
    if not isinstance(details, dict):
        raise PermissionError('Cannot establish the GPU requirements of this compute offering')
    legacy = any(str(key).lower() in {'pcidevice', 'vgputype'} for key in details)
    indicated = legacy or any(offering.get(key) for key in ('vgpuprofileid', 'gpucardid', 'gpuenabled'))
    try:
        count = int(offering.get('gpucount') or 0)
    except (ValueError, TypeError):
        raise PermissionError('Cannot establish the GPU count of this compute offering') from None
    if count < 0 or (indicated and count == 0):
        # Legacy pciDevice/vgpuType offerings do not enter CloudStack's native GPU resource counter.
        raise PermissionError('GPU offerings require a positive native GPU count; use a vGPU-profile offering')
    return count


def _one(response, key, object_id):
    return next((value for value in response.get(key, []) if value.get('id') == object_id), None)


async def _domain_chain(service, domain_id):
    root = await service.agent(APP_ROOT_AGENT)
    reader = await service.cloud_client(root)
    chain, seen = [], set()
    while domain_id:
        if domain_id in seen or len(seen) >= 64:
            raise PermissionError('Cannot verify CloudStack ancestor domains')
        seen.add(domain_id)
        domain = _one(await reader.raw('listDomains', {'id': domain_id, 'listall': True}), 'domain', domain_id)
        if not domain:
            raise PermissionError('Cannot verify every ancestor GPU quota')
        try:
            level = int(domain['level'])
        except (KeyError, ValueError, TypeError):
            raise PermissionError('CloudStack domain depth is unavailable') from None
        if chain and level != int(chain[-1]['level']) - 1:
            raise PermissionError('CloudStack ancestor domain levels are inconsistent')
        chain.append(domain)
        # Native ROOT is always unlimited and rejects updateResourceLimit. App /Agents is level one.
        if level in {0, 1}:
            return chain
        domain_id = domain.get('parentdomainid')
    raise PermissionError('Cannot verify every ancestor GPU quota')


async def check_vm_policy(service, agent, params, *, command='deployVirtualMachine'):
    if command not in VM_POLICY_COMMANDS:
        raise ValueError('Unsupported VM policy operation')
    cloud = await service.cloud_client(agent)
    vm = None
    target_domain = params.get('domainid') or agent['domain_id']
    if command != 'deployVirtualMachine':
        vm_id = params.get('id')
        vm = _one(await cloud.raw('listVirtualMachines', {'id': vm_id}), 'virtualmachine', vm_id)
        if not vm:
            raise PermissionError('VM is unavailable to this agent')
        target_domain = vm.get('domainid')
        if not target_domain:
            raise PermissionError('Cannot establish the VM owner domain')
    offering_id = params.get('serviceofferingid') or (vm or {}).get('serviceofferingid')
    if not offering_id:
        raise ValueError('An explicit compute offering is required')
    offering = _one(await cloud.raw('listServiceOfferings', {'id': offering_id}), 'serviceoffering', offering_id)
    if not offering:
        raise PermissionError('Compute offering is unavailable to this agent or domain')
    units = gpu_count(offering)
    restriction = offering.get('domainid') or []
    if isinstance(restriction, str):
        restriction = [value.strip() for value in restriction.split(',') if value.strip()]
    if not isinstance(restriction, list) or not all(isinstance(value, str) for value in restriction):
        raise PermissionError('Cannot verify compute offering domain restrictions')
    if not units and not restriction:
        return
    # Verify caller visibility before the trusted reader accesses ancestor-only information.
    if not _one(await cloud.raw('listDomains', {'id': target_domain, 'listall': True}), 'domain', target_domain):
        raise PermissionError('VM owner domain is outside this agent’s scope')
    chain = await _domain_chain(service, target_domain)
    if restriction and not set(restriction).intersection(domain['id'] for domain in chain):
        raise PermissionError('Compute offering is restricted to another CloudStack domain')
    if not units:
        return
    delta = units
    if vm and command in {'startVirtualMachine', 'rebootVirtualMachine', 'restoreVirtualMachine', 'scaleVirtualMachine', 'changeServiceForVirtualMachine'}:
        previous_id = vm.get('serviceofferingid')
        previous = offering if previous_id == offering_id else _one(
            await cloud.raw('listServiceOfferings', {'id': previous_id}), 'serviceoffering', previous_id)
        if not previous:
            raise PermissionError('Cannot establish current VM GPU allocation')
        delta = max(0, units - gpu_count(previous))
    for domain in chain:
        if int(domain['level']) == 0:
            continue
        raw_limit = domain.get('gpulimit')
        try:
            limit = -1 if str(raw_limit).lower() == 'unlimited' else int(raw_limit)
            used = int(domain['gputotal'])
        except (KeyError, ValueError, TypeError):
            raise PermissionError('Cannot verify every ancestor GPU quota') from None
        if limit < -1 or used < 0:
            raise PermissionError('CloudStack returned an invalid GPU quota')
        if limit == 0 or limit >= 0 and used + delta > limit:
            raise PermissionError(f"GPU quota exceeded in ancestor domain {domain['id']}: "
                                  f'limit={limit}, used={used}, additional={delta}')
