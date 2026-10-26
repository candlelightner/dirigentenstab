"""Policy-scoped GPU host preparation; VM dispatch keeps the agent identity."""
import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
import xml.etree.ElementTree as ET

from .cloud import CloudError, validate
from .gpu import GPU_COMMANDS, effective_policy, narrows, operation_id, validate_policy
from .limits import APP_ROOT_AGENT, gpu_count


class Journal:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS policies(domain_id TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS pools(uuid TEXT PRIMARY KEY, domain_id TEXT NOT NULL, profile TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    request TEXT NOT NULL, phase TEXT NOT NULL, result TEXT, updated REAL NOT NULL,
                    changed INTEGER NOT NULL DEFAULT 0);
            ''')
            db.execute("UPDATE operations SET phase='reconciliation' WHERE phase='dispatching'")
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            db.row_factory = sqlite3.Row
            with db:
                yield db
        finally:
            db.close()

    def rows(self, query, args=()):
        with self.connect() as db:
            return [dict(row) for row in db.execute(query, args)]

    def write(self, query, args=()):
        with self.connect() as db:
            db.execute(query, args)

    def policies(self):
        return {r['domain_id']: json.loads(r['document']) for r in self.rows('SELECT * FROM policies')}

    def owners(self):
        return {r['uuid']: r for r in self.rows('SELECT * FROM pools')}

    def phase(self, identifier, phase, result=None):
        self.write('UPDATE operations SET phase=?,result=?,updated=? WHERE id=?',
                   (phase, json.dumps(result) if result is not None else None, time.time(), identifier))


class NativeHost:
    def __init__(self, parent):
        if not re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', parent):
            raise ValueError('Configure a canonical physical GPU PCI address')
        self.parent = parent
        self.path = Path('/sys/bus/pci/devices') / parent

    async def command(self, *args):
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            async with asyncio.timeout(30):
                stdout, _ = await proc.communicate()
            if proc.returncode or len(stdout) > 1048576:
                raise RuntimeError('GPU host command failed; inspect the controller operation reference')
            return stdout.decode()
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.communicate()

    def profiles(self):
        result = {}
        for path in (self.path / 'mdev_supported_types').glob('*'):
            values = dict(re.findall(r'(\w+)=([^,\s]+)', (path / 'description').read_text()))
            result[path.name] = {'id': path.name, 'name': (path / 'name').read_text().strip(),
                                 'available': int((path / 'available_instances').read_text()),
                                 'maximum': int(values['max_instance']),
                                 'memory': int(values['framebuffer'].rstrip('M')),
                                 'heads': int(values.get('num_heads', '0'))}
        if not result:
            raise PermissionError('The configured GPU exposes no real mediated profiles')
        return result

    def devices(self):
        return {p.name: {'uuid': p.name, 'profile': p.parent.parent.name}
                for p in (self.path / 'mdev_supported_types').glob('*/devices/*') if p.is_dir()}

    async def attachments(self):
        attached = set()
        for name in (await self.command('virsh', '-c', 'qemu:///system', 'list', '--all', '--name')).split():
            xml = ET.fromstring(await self.command('virsh', '-c', 'qemu:///system', 'dumpxml', name))
            for device in xml.findall('.//hostdev'):
                address = device.find('source/address')
                if address is None:
                    continue
                if device.get('type') == 'mdev':
                    attached.add(address.get('uuid'))
                elif device.get('type') == 'pci':
                    bdf = '%04x:%02x:%02x.%x' % tuple(int(address.get(k, '0'), 16)
                                                    for k in ('domain', 'bus', 'slot', 'function'))
                    if bdf == self.parent:
                        raise PermissionError('The physical GPU is attached to a VM; no pool changes are permitted')
        return attached

    async def create(self, identifier, profile):
        if profile not in self.profiles():
            raise PermissionError('Unsupported physical vGPU profile')
        existing = self.devices().get(identifier)
        if existing:
            if existing['profile'] != profile:
                raise PermissionError('Device identity conflicts with the saved GPU operation')
            return
        defined = Path('/etc/mdevctl.d') / self.parent / identifier
        if defined.exists():
            if json.loads(defined.read_text())['mdev_type'] != profile:
                raise PermissionError('Persistent mdev identity has another profile')
        else:
            await self.command('mdevctl', 'define', '--uuid', identifier, '--parent', self.parent, '--type', profile, '--auto')
        await self.command('mdevctl', 'start', '--uuid', identifier)

    async def remove(self, identifier):
        uuid.UUID(identifier)
        if identifier in self.devices():
            await self.command('mdevctl', 'stop', '--uuid', identifier)
        if (Path('/etc/mdevctl.d') / self.parent / identifier).exists():
            await self.command('mdevctl', 'undefine', '--uuid', identifier)


class Controller:
    def __init__(self, service, cloud, journal, host, host_id):
        self.service, self.cloud, self.journal, self.host, self.host_id = service, cloud, journal, host, host_id
        self.lock = asyncio.Lock()

    async def domains(self):
        return (await self.cloud.raw('listDomains', {'listall': True})).get('domain', [])

    @staticmethod
    def chain(domains, domain_id):
        indexed = {d['id']: d for d in domains}
        chain, seen = [], set()
        while domain_id:
            if domain_id in seen or domain_id not in indexed:
                raise PermissionError('Cannot establish every GPU policy ancestor')
            seen.add(domain_id)
            domain = indexed[domain_id]
            chain.append(domain)
            if int(domain.get('level', -1)) == 0:
                return list(reversed(chain))
            domain_id = domain.get('parentdomainid')
        raise PermissionError('GPU policy ancestry is incomplete')

    async def human(self, session_hash, platform=True):
        session = self.service.store.one('SELECT identity FROM sessions WHERE token_hash=? AND expires>?',
                                         (session_hash, time.time()))
        if not session:
            raise PermissionError('A current human platform-administrator session is required')
        private = self.service.store.open(session['identity'])
        identity = {k: private.get(k) for k in ('userid', 'account', 'domainid', 'type')}
        identity['_session'] = session_hash
        users = (await self.service.human_call(identity, 'listUsers', {'id': identity['userid']})).get('user', [])
        accounts = (await self.service.human_call(identity, 'listAccounts',
                    {'name': identity['account'], 'domainid': identity['domainid']})).get('account', [])
        role = private.get('type')
        if not (role in ({1} if platform else {1, 2}) and any(u['id'] == identity['userid'] and u.get('state') == 'enabled' for u in users)
                and any(a.get('name') == identity['account'] and a.get('domainid') == identity['domainid']
                        and int(a.get('accounttype', -1)) == role and a.get('state') == 'enabled' for a in accounts)):
            raise PermissionError('Only a currently authenticated human platform administrator can change GPU policy')
        return identity

    async def inventory(self):
        values = (await self.cloud.raw('listGpuDevices', {'hostid': self.host_id})).get('gpudevice', [])
        return {d['busaddress']: d for d in values if d.get('gpudevicetype') == 'MDEV'}

    async def status(self, session_hash):
        await self.human(session_hash)
        return {'domains': await self.domains(), 'profiles': list(self.host.profiles().values()),
                'policies': self.journal.policies(), 'pools': list(self.journal.owners().values()),
                'devices': list((await self.inventory()).values()),
                'operations': self.journal.rows('SELECT id,phase,updated FROM operations ORDER BY updated DESC LIMIT 30')}

    async def set_policy(self, request):
        actor = await self.human(request['session'])
        domains = await self.domains()
        chain = self.chain(domains, request['domain_id'])
        policy = validate_policy(request['policy'], self.host.profiles())
        if len(chain) == 1:
            if policy['max_allocations'] != -1:
                raise ValueError('CloudStack native ROOT has an unlimited quota; cap managed child domains')
        elif not narrows(policy, effective_policy(chain[:-1], self.journal.policies())):
            raise PermissionError('A child GPU policy may only narrow every ancestor permission and quota')
        if len(chain) > 1:
            if policy['max_allocations'] < 0:
                raise PermissionError('Managed domains require an explicit nonnegative native GPU quota')
            await self.cloud.raw('updateResourceLimit', {'domainid': request['domain_id'], 'resourcetype': 16,
                                                        'max': policy['max_allocations']})
            limits = (await self.cloud.raw('listResourceLimits', {'domainid': request['domain_id'],
                       'resourcetype': 16})).get('resourcelimit', [])
            if not any(int(x['max']) == policy['max_allocations'] for x in limits):
                raise RuntimeError('CloudStack GPU quota update could not be verified; policy was not granted')
        self.journal.write('INSERT INTO policies VALUES(?,?) ON CONFLICT(domain_id) DO UPDATE SET document=excluded.document',
                           (request['domain_id'], json.dumps(policy)))
        self.service.store.audit(actor['userid'], 'gpu-policy', request['domain_id'])
        return {'saved': True}

    async def claim(self, request):
        actor = await self.human(request['session'])
        self.chain(await self.domains(), request['domain_id'])
        identifier = str(uuid.UUID(request['uuid']))
        device = (await self.inventory()).get(identifier)
        host = self.host.devices().get(identifier)
        if (not device or not host or device.get('state') != 'Free' or device.get('virtualmachineid')
                or identifier in await self.host.attachments()):
            raise PermissionError('Only an actual free, unattached device can be assigned a pool owner')
        if identifier in self.journal.owners():
            raise PermissionError('Device already has an owner; implicit ownership reassignment is forbidden')
        self.journal.write('INSERT INTO pools VALUES(?,?,?)', (identifier, request['domain_id'], host['profile']))
        self.service.store.audit(actor['userid'], 'gpu-pool-owner', identifier)
        return {'claimed': identifier}

    async def offering(self, request):
        actor = await self.human(request['session'])
        domains = await self.domains()
        effective = effective_policy(self.chain(domains, request['domain_id']), self.journal.policies())
        profile = self.host.profiles().get(request['profile'])
        if not profile or profile['id'] not in effective['profiles']:
            raise PermissionError('Profile is not authorized by every ancestor GPU policy')
        cpus, memory, disk = request['cpus'], request['memory'], request['root_disk']
        if (type(cpus) is not int or not 1 <= cpus <= 64 or type(memory) is not int or not 512 <= memory <= 262144
                or type(disk) is not int or not 8 <= disk <= 4096):
            raise ValueError('Choose valid platform-admin compute resources')
        cards = (await self.cloud.raw('listGpuCards')).get('gpucard', [])
        card = next((c for c in cards if c.get('deviceid') == (self.host.path / 'device').read_text().strip()[2:]), None)
        if not card:
            raise PermissionError('Physical GPU card has not been discovered by CloudStack')
        profiles = (await self.cloud.raw('listVgpuProfiles', {'gpucardid': card['id']})).get('vgpuprofile', [])
        native = next((p for p in profiles if p['name'] == profile['name']), None)
        if not native:
            native = (await self.cloud.raw('createVgpuProfile', {'name': profile['name'], 'gpucardid': card['id'],
                      'videoram': profile['memory'], 'maxvgpuperphysicalgpu': profile['maximum'],
                      'maxheads': profile['heads'], 'description': 'Verified host mdev type ' + profile['id']}))['vgpuprofile']
        name = ('Dirigentenstab-' + profile['name'].replace('GRID ', '').replace(' ', '-')
                + f'-{cpus}CPU-{memory}MiB-{disk}GiB-' + request['domain_id'][:8])
        values = (await self.cloud.raw('listServiceOfferings', {'name': name, 'listall': True})).get('serviceoffering', [])
        offering = next((o for o in values if o['name'] == name and o.get('vgpuprofileid') == native['id']), None)
        if not offering:
            offering = (await self.cloud.raw('createServiceOffering', {'name': name, 'displaytext': profile['name'] + ' authorized mdev',
                        'cpunumber': cpus, 'cpuspeed': 1000, 'memory': memory, 'rootdisksize': disk, 'storagetype': 'local',
                        'domainid': request['domain_id'], 'vgpuprofileid': native['id'], 'gpucount': 1}))['serviceoffering']
        self.service.store.audit(actor['userid'], 'gpu-offering', offering['id'])
        return {'offering_id': offering['id']}

    async def authorize(self, agent, profile):
        domains = await self.domains()
        chain = self.chain(domains, agent['domain_id'])
        policy = effective_policy(chain, self.journal.policies())
        if profile not in policy['profiles'] or policy['max_allocations'] == 0:
            raise PermissionError('GPU profile or allocation is denied by an ancestor domain policy')
        if agent['id'] != APP_ROOT_AGENT and not policy['subgroup_requests']:
            raise PermissionError('Subgroup GPU capacity requests are disabled by an ancestor policy')
        await self.quota_enforced(chain)
        visible = (await (await self.service.cloud_client(agent)).raw('listDomains', {'listall': True})).get('domain', [])
        permitted = {d['id'] for d in visible if any(a['id'] == agent['domain_id'] for a in self.chain(domains, d['id']))}
        if agent['domain_id'] not in permitted:
            raise PermissionError('Agent runtime identity cannot verify its own domain')
        return policy, permitted

    async def quota_enforced(self, chain):
        policies = self.journal.policies()
        for domain in chain:
            if int(domain['level']) == 0:
                continue
            limits = (await self.cloud.raw('listResourceLimits', {'domainid': domain['id'], 'resourcetype': 16})).get('resourcelimit', [])
            maximum = policies[domain['id']]['max_allocations']
            if not any(0 <= int(x['max']) <= maximum for x in limits):
                raise PermissionError('Native CloudStack GPU quota no longer enforces the approved domain policy')

    async def assert_free(self, identifier, permitted):
        owner = self.journal.owners().get(identifier)
        if not owner or owner['domain_id'] not in permitted:
            raise PermissionError('GPU device is foreign or has unknown ownership; no device changes are permitted')
        device = (await self.inventory()).get(identifier)
        if not device or device.get('state') != 'Free' or device.get('virtualmachineid'):
            raise PermissionError('GPU device is allocated, reserved, or not verified free')
        if identifier in await self.host.attachments():
            raise PermissionError('GPU device remains attached or reserved in libvirt')
        return device

    async def prepare(self, identifier, agent, profile, count, policy, permitted):
        await self.cloud.raw('discoverGpuDevices', {'id': self.host_id})
        devices = self.host.devices()
        owners = self.journal.owners()
        inventory = await self.inventory()
        attached = await self.host.attachments()
        if any(item in attached and inventory.get(item, {}).get('state') == 'Free' for item in devices):
            raise PermissionError('CloudStack GPU inventory disagrees with libvirt attachments; reconcile discovery before allocation')
        if any(item not in inventory for item in devices):
            await self.cloud.raw('discoverGpuDevices', {'id': self.host_id})
            inventory = await self.inventory()
        global_devices = (await self.cloud.raw('listGpuDevices')).get('gpudevice', [])
        for device in global_devices:
            if (device.get('gpudevicetype') == 'MDEV'
                    and device.get('vgpuprofilename') == self.host.profiles()[profile]['name']):
                owner = owners.get(device['busaddress'])
                if device['busaddress'] not in devices or not owner or owner['domain_id'] not in permitted:
                    raise PermissionError('CloudStack cannot safely select devices from a profile shared with foreign or unknown pools')
        # Native allocation has no domain-specific device selector: refuse an ambiguous foreign pool.
        for item, host in devices.items():
            if host['profile'] == profile and (item not in owners or owners[item]['domain_id'] not in permitted):
                if inventory.get(item, {}).get('state') == 'Free':
                    raise PermissionError('CloudStack could select another group’s free device; dedicated authorized capacity is required')
        free = [item for item, host in devices.items() if host['profile'] == profile and item in owners
                and owners[item]['domain_id'] in permitted and inventory.get(item, {}).get('state') == 'Free'
                and not inventory[item].get('virtualmachineid') and item not in attached]
        if any(inventory[item].get('managedstate') != 'Managed' for item in free):
            raise PermissionError('Owned capacity is unmanaged/reserved; an administrator must reconcile it before allocation')
        if len(free) >= count:
            return
        different = [item for item, host in devices.items() if host['profile'] != profile]
        if different:
            if not policy['reconfigure_unused']:
                raise PermissionError('Unused GPU pool reconfiguration is not permitted by every ancestor policy')
            for item in different:
                await self.assert_free(item, permitted)
                owner = owners[item]['domain_id']
                if not effective_policy(self.chain(await self.domains(), owner), self.journal.policies())['reconfigure_unused']:
                    raise PermissionError('The device owner’s effective policy forbids pool reconfiguration')
            self.journal.write('UPDATE operations SET changed=1 WHERE id=?', (identifier,))
            for item in different:
                device = await self.assert_free(item, permitted)
                await self.cloud.raw('unmanageGpuDevice', {'ids': device['id']})
            jobs = (await self.cloud.raw('listAsyncJobs', {'listall': True})).get('asyncjobs', [])
            if any(int(j.get('jobstatus', -1)) == 0 for j in jobs):
                raise PermissionError('CloudStack has pending jobs; pool changes require a quiescent allocation boundary')
            for item in different:
                device = await self.assert_free(item, permitted)
                await self.host.remove(item)
                await self.cloud.raw('deleteGpuDevice', {'ids': device['id']})
                self.journal.write('DELETE FROM pools WHERE uuid=?', (item,))
        available = self.host.profiles()[profile]['available']
        needed = count - len(free)
        if needed > available:
            raise PermissionError('The physical GPU does not have enough capacity for the requested profile')
        for number in range(count):
            if not needed:
                break
            item = str(uuid.uuid5(uuid.NAMESPACE_OID, identifier + ':' + str(number)))
            existing = self.journal.owners().get(item)
            if existing and (existing['domain_id'] != agent['domain_id'] or existing['profile'] != profile):
                raise PermissionError('Saved GPU creation identity has conflicting ownership')
            self.journal.write('INSERT INTO pools VALUES(?,?,?) ON CONFLICT(uuid) DO NOTHING',
                               (item, agent['domain_id'], profile))
            if item in self.host.devices():
                continue
            self.journal.write('UPDATE operations SET changed=1 WHERE id=?', (identifier,))
            await self.host.create(item, profile)
            needed -= 1
        await self.cloud.raw('discoverGpuDevices', {'id': self.host_id})
        final = await self.inventory()
        if sum(d.get('vgpuprofilename') == self.host.profiles()[profile]['name'] and d.get('state') == 'Free'
               and d['busaddress'] in self.journal.owners() and
               self.journal.owners()[d['busaddress']]['domain_id'] in permitted for d in final.values()) < count:
            raise RuntimeError('CloudStack rediscovery did not confirm the prepared GPU capacity')

    async def reconcile(self, op):
        request = json.loads(op['request'])
        command, params = request['command'], request['params']
        agent = await self.service.agent(request['agent_id'])
        cloud = await self.service.cloud_client(agent)
        if command == 'deployVirtualMachine':
            row = self.service.store.one('SELECT * FROM vm_deployments WHERE id=? AND agent_id=?', (op['id'], agent['id']))
            if not row or row['phase'] == 'rejected':
                values = (await cloud.raw('listVirtualMachines', {'name': 'ds-vm-'+op['id'][:20], 'listall': True})).get('virtualmachine', [])
                jobs = (await self.cloud.raw('listAsyncJobs', {'listall': True})).get('asyncjobs', [])
                if values or any(int(j.get('jobstatus', -1)) == 0 for j in jobs):
                    raise RuntimeError('GPU deployment outcome is ambiguous; no action was repeated')
                result = {'rejected': True, 'description': 'The durable VM dispatch was not accepted; no VM exists.'}
                self.journal.phase(op['id'], 'failed', result)
                return result
            await self.service.recover_deployments(operation_id=op['id'])
            row = self.service.store.one('SELECT * FROM vm_deployments WHERE id=?', (op['id'],))
            if row['phase'] != 'complete':
                raise RuntimeError('GPU deployment remains unresolved; no deployment was repeated')
            vm_id = row['vm_id']
        else:
            vm_id = params['id']
        values = (await cloud.raw('listVirtualMachines', {'id': vm_id})).get('virtualmachine', [])
        vm = next((v for v in values if v['id'] == vm_id), None)
        done = vm and (command == 'deployVirtualMachine' or
                       command == 'startVirtualMachine' and vm.get('state') == 'Running' or
                       command == 'stopVirtualMachine' and vm.get('state') == 'Stopped' or
                       command == 'changeServiceForVirtualMachine' and vm.get('serviceofferingid') == params['serviceofferingid'])
        if not done:
            raise RuntimeError('GPU action outcome is not proven; administrator reconciliation is required')
        result = self.service.redact({'virtualmachine': vm, 'recovered': True})
        self.journal.phase(op['id'], 'completed', result)
        return result

    async def owned_result(self, request):
        actor = await self.human(request['session'], platform=False)
        run = self.service.store.one('SELECT r.agent_id,c.human_id FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id '
                                     'WHERE r.id=?', (request['run_id'],))
        rows = self.journal.rows('SELECT * FROM operations WHERE id=?', (request['operation_id'],))
        if not run or run['human_id'] != actor['userid'] or not rows:
            raise PermissionError('GPU operation does not belong to this human conversation owner')
        await self.service.authorize(actor, run['agent_id'])
        op = rows[0]
        original = json.loads(op['request'])
        if original['context']['run_id'] != request['run_id'] or original['agent_id'] != run['agent_id']:
            raise PermissionError('GPU operation agent or conversation identity mismatch')
        if op['phase'] not in {'completed', 'failed'}:
            if op['phase'] == 'preparing':
                raise RuntimeError('A platform administrator must resume the saved pre-dispatch GPU plan first')
            await self.reconcile(op)
            op = self.journal.rows('SELECT * FROM operations WHERE id=?', (op['id'],))[0]
        return {'phase': op['phase'], 'result': json.loads(op['result']) if op['result'] else {'rejected': True},
                'command': original['command'], 'params': original['params']}

    async def execute(self, request, preflight=False, *, actor=None):
        command, params = request['command'], request['params']
        if command not in GPU_COMMANDS:
            raise PermissionError('GPU controller operation is not allowed')
        context = request['context']
        if (not isinstance(context, dict) or set(context) != {'run_id', 'call_id'}
                or not isinstance(context['call_id'], str) or len(context['call_id']) > 256):
            raise PermissionError('GPU operation context is invalid')
        run = self.service.store.one('SELECT r.agent_id,r.status,c.human_id FROM chat_runs r '
                                     'JOIN conversations c ON c.id=r.conversation_id WHERE r.id=?', (context['run_id'],))
        if not run or run['agent_id'] != request['agent_id'] or run['status'] not in {'running', 'reconciliation'}:
            raise PermissionError('GPU request does not belong to this durable server-side agent execution')
        if actor is not None and run['human_id'] != actor['userid']:
            raise PermissionError('GPU execution does not belong to this human conversation owner')
        agent = await self.service.agent(request['agent_id'])
        cloud = await self.service.cloud_client(agent)
        metadata = (await cloud.catalogue()).get(command)
        if not metadata:
            raise PermissionError('GPU operation unavailable to the restricted agent identity')
        validate(metadata, params)
        vm = None
        allocation_owner = agent
        if command != 'deployVirtualMachine':
            vm = next((v for v in (await cloud.raw('listVirtualMachines', {'id': params['id']})).get('virtualmachine', [])
                       if v['id'] == params['id']), None)
            access = self.service.store.one('SELECT owner_agent FROM vm_access WHERE vm_id=?', (params['id'],))
            if not vm or not access:
                raise PermissionError('GPU VM has no managed group identity')
            allocation_owner = await self.service.agent(access['owner_agent'])
            if vm.get('domainid') != allocation_owner['domain_id']:
                raise PermissionError('GPU VM domain does not match its managed owner')
            accounts = (await cloud.raw('listAccounts', {'id': allocation_owner['account_id'], 'listall': True})).get('account', [])
            if not any(a['id'] == allocation_owner['account_id'] and a.get('domainid') == allocation_owner['domain_id']
                       and a.get('name') == vm.get('account') for a in accounts):
                raise PermissionError('CloudStack could not verify the exact GPU VM owner account')
        elif params.get('domainid') not in {None, agent['domain_id']} or params.get('account') or params.get('projectid'):
            raise PermissionError('GPU deployment must use the agent’s own account and domain')
        native_id = params.get('serviceofferingid') or (vm or {}).get('serviceofferingid')
        values = (await cloud.raw('listServiceOfferings', {'id': native_id})).get('serviceoffering', [])
        offering = next((o for o in values if o['id'] == native_id), None)
        if not offering:
            raise PermissionError('GPU/CPU compute offering is outside the agent’s native permissions')
        required = gpu_count(offering)
        current = offering
        if vm and vm.get('serviceofferingid') != native_id:
            current = next((o for o in (await cloud.raw('listServiceOfferings', {'id': vm['serviceofferingid']})).get(
                'serviceoffering', []) if o['id'] == vm['serviceofferingid']), None)
        name = (offering if required else current or {}).get('vgpuprofilename')
        profile = next((p['id'] for p in self.host.profiles().values() if p['name'] == name), None)
        if not profile:
            raise PermissionError('The offering does not reference an actual mediated profile on this physical GPU')
        policy, permitted = await self.authorize(agent, profile)
        if vm and vm['domainid'] not in permitted:
            raise PermissionError('GPU VM belongs outside the requesting group and its subgroups')
        if vm and vm['domainid'] != agent['domain_id']:
            target_chain = self.chain(await self.domains(), vm['domainid'])
            policy = effective_policy(target_chain, self.journal.policies())
            await self.quota_enforced(target_chain)
            if profile not in policy['profiles'] or policy['max_allocations'] == 0:
                raise PermissionError('The subgroup’s effective policy denies this GPU operation')
        if vm:
            for item, allocated in (await self.inventory()).items():
                if allocated.get('virtualmachineid') == vm['id']:
                    owner = self.journal.owners().get(item)
                    if not owner or owner['domain_id'] not in permitted:
                        raise PermissionError('The VM references a GPU device owned outside the agent’s group or subgroups')
        if preflight:
            chain = self.chain(await self.domains(), allocation_owner['domain_id'])
            policies = self.journal.policies()
            return {'domain_id': agent['domain_id'], 'profile': profile, 'chain': chain,
                    'policies': {d['id']: policies.get(d['id'], {}) for d in chain}}
        identifier = operation_id(context)
        fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        existing = self.journal.rows('SELECT * FROM operations WHERE id=?', (identifier,))
        if existing:
            op = existing[0]
            if op['fingerprint'] != fingerprint:
                raise PermissionError('GPU operation identifier cannot be reused with different arguments')
            if op['phase'] == 'completed':
                return json.loads(op['result'])
            if op['phase'] in {'dispatching', 'reconciliation'}:
                return await self.reconcile(op)
        else:
            unresolved = self.journal.rows("SELECT id FROM operations WHERE phase IN ('preparing','dispatching','reconciliation')")
            if unresolved:
                raise RuntimeError('Another GPU operation requires reconciliation before further GPU changes')
            self.journal.write('INSERT INTO operations(id,fingerprint,request,phase,result,updated) VALUES(?,?,?,?,NULL,?)',
                               (identifier, fingerprint, json.dumps(request), 'preparing', time.time()))
        previous_local = getattr(self.service, 'gpu_local', False)
        previous_deployment = getattr(self.service, 'gpu_deployment_id', None)
        try:
            from .limits import VM_POLICY_COMMANDS, check_vm_policy
            if command in VM_POLICY_COMMANDS:
                await check_vm_policy(self.service, agent, params, command=command)
            if required and command in {'deployVirtualMachine', 'startVirtualMachine'}:
                await self.prepare(identifier, allocation_owner, profile, required, policy, permitted)
            if command in {'scaleVirtualMachine', 'changeServiceForVirtualMachine'}:
                if (not vm or vm.get('state') != 'Stopped' or required and
                        (offering.get('vgpuprofileid') != (current or {}).get('vgpuprofileid')
                         or required != gpu_count(current or {}))):
                    raise PermissionError('Offering changes require a stopped VM; changing GPU profile requires release to CPU first')
            if command == 'stopVirtualMachine':
                await self.cloud.raw('updateConfiguration', {'name': 'gpu.detach.on.stop',
                                     'domainid': allocation_owner['domain_id'], 'value': str(policy['release_on_stop']).lower()})
            self.journal.phase(identifier, 'dispatching')
            self.service.gpu_deployment_id = identifier if command == 'deployVirtualMachine' else None
            self.service.gpu_local = True
            try:
                result = await self.service.execute(agent['id'], command, params, managed=command == 'deployVirtualMachine')
            except CloudError as exc:
                deployment = (self.service.store.one('SELECT phase FROM vm_deployments WHERE id=? AND agent_id=?',
                                                     (identifier, agent['id']))
                              if command == 'deployVirtualMachine' else None)
                # A polling denial may follow VM submission; only the durable rejection proves no deploy occurred.
                if exc.rejected and (command != 'deployVirtualMachine' or deployment and deployment['phase'] == 'rejected'):
                    self.journal.phase(identifier, 'failed', {'rejected': True,
                                       'description': exc.public_detail or 'CloudStack rejected the operation.'})
                raise
            await self.cloud.raw('discoverGpuDevices', {'id': self.host_id})
            self.journal.phase(identifier, 'completed', result)
            return result
        except BaseException as exc:
            state = self.journal.rows('SELECT phase,changed FROM operations WHERE id=?', (identifier,))[0]
            phase = state['phase']
            if phase == 'dispatching':
                self.journal.phase(identifier, 'reconciliation')
            elif not state['changed'] and isinstance(exc, (PermissionError, ValueError)):
                self.journal.phase(identifier, 'failed')
            raise
        finally:
            self.service.gpu_deployment_id = previous_deployment
            self.service.gpu_local = previous_local

    async def dispatch(self, request, peer_uid):
        if peer_uid not in {0, 10001}:
            raise PermissionError('GPU helper accepts only the authenticated local backend')
        if not isinstance(request, dict) or len(json.dumps(request)) > 65536:
            raise ValueError('Invalid GPU controller request')
        actions = {'status': {'session'}, 'set_policy': {'session', 'domain_id', 'policy'},
                   'claim': {'session', 'domain_id', 'uuid'},
                   'offering': {'session', 'domain_id', 'profile', 'cpus', 'memory', 'root_disk'},
                   'execute': {'session', 'agent_id', 'command', 'params', 'context'}, 'reconcile': {'session', 'operation_id'},
                   'resume': {'session', 'operation_id'}, 'authorize': {'session', 'agent_id', 'command', 'params', 'context'},
                   'result': {'session', 'operation_id', 'run_id'}}
        action = request.get('action')
        if action not in actions or set(request) != actions[action] | {'action'}:
            raise PermissionError('GPU controller request contains unauthorized operations or fields')
        if action == 'status':
            return await self.status(request['session'])
        async with self.lock:
            if action == 'result':
                return await self.owned_result(request)
            if action == 'set_policy':
                return await self.set_policy(request)
            if action == 'claim':
                return await self.claim(request)
            if action == 'offering':
                return await self.offering(request)
            if action in {'reconcile', 'resume'}:
                await self.human(request['session'])
                rows = self.journal.rows('SELECT * FROM operations WHERE id=?', (request['operation_id'],))
                if not rows:
                    raise ValueError('GPU operation missing')
                if action == 'resume':
                    if rows[0]['phase'] != 'preparing':
                        raise PermissionError('Only a saved pre-dispatch GPU plan may be resumed')
                    return await self.execute(json.loads(rows[0]['request']))
                return await self.reconcile(rows[0])
            actor = await self.human(request['session'], platform=False)
            await self.service.authorize(actor, request['agent_id'])
            return await self.execute(request, preflight=action == 'authorize', actor=actor)
