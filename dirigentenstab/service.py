import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import time
import uuid

import httpx

from .cloud import Cloud, CloudError, PROVISION_APIS, RUNTIME_APIS, redact, validate
from .settings import endpoint
from .hierarchy import validate_child
from .limits import VM_POLICY_COMMANDS, check_vm_policy


def first(response, key):
    value = response.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    if not value:
        raise CloudError(f'CloudStack did not return {key}')
    return value


class Service:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        self._clients = {}
        self._provision_lock = asyncio.Lock()
        self._deploy_lock = asyncio.Lock()
        self._secrets = set()
        for row in store.all('SELECT runtime,provisioning FROM agents'):
            for field in ('runtime', 'provisioning'):
                self._remember(store.open(row[field]))
        for row in store.all('SELECT api_key FROM providers'):
            self._remember(store.open(row['api_key']))

    def _remember(self, value):
        if isinstance(value, str):
            self._secrets.add(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in {'apikey', 'secretkey', 'private_key'}:
                    self._remember(item)

    def redact(self, value):
        return redact(value, self._secrets)

    def client(self, credentials):
        self._remember(credentials)
        cache_key = hashlib.sha256(json.dumps(credentials, sort_keys=True).encode()).hexdigest()
        if cache_key not in self._clients:
            self._clients[cache_key] = Cloud(self.settings, credentials)
        return self._clients[cache_key]

    async def agent(self, agent_id):
        row = self.store.one('SELECT * FROM agents WHERE id=? AND enabled=1', (agent_id,))
        if not row:
            raise PermissionError('Agent is unavailable')
        return row

    async def cloud_client(self, agent, purpose='runtime'):
        return self.client(self.store.open(agent[purpose]))

    async def human_call(self, identity, command, params=None):
        session = self.store.one('SELECT identity FROM sessions WHERE token_hash=? AND expires>?',
                                 (identity['_session'], time.time()))
        if not session:
            raise PermissionError('Session expired')
        private = self.store.open(session['identity'])
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            response = await client.post(self.settings.cloudstack_url,
                                         data={'command': command, 'response': 'json',
                                               'sessionkey': private['sessionkey'], **(params or {})},
                                         cookies=private['cookies'])
        try:
            data = response.json()
            value = next(iter(data.values()))
            if response.is_error or 'errorcode' in value:
                raise PermissionError('CloudStack session no longer authorized')
            return value
        except (ValueError, StopIteration, TypeError):
            raise PermissionError('CloudStack session validation failed') from None

    async def hierarchy(self, identity):
        if identity['type'] not in {1, 2}:
            raise PermissionError('A CloudStack administrator account is required')
        domains = (await self.human_call(identity, 'listDomains', {'listall': 'true'})).get('domain', [])
        visible = {domain['id'] for domain in domains}
        agents = self.store.all('SELECT id,name,domain_id,account_id,user_id,provider_id,model,instructions,'
                                'can_provision,enabled FROM agents')
        main = self.store.one('SELECT id FROM provisioning WHERE parent_id IS NULL AND phase=?', ('complete',))
        agents = [a | {'is_main': bool(main and a['id'] == main['id'])}
                  for a in agents if a['domain_id'] in visible and a['enabled']]
        users = (await self.human_call(identity, 'listUsers', {'listall': 'true'})).get('user', [])
        visible_agents = {a['id'] for a in agents}
        pending = [op for op in self.store.all(
            "SELECT id,parent_id,name,phase FROM provisioning WHERE phase<>'complete'")
            if op['parent_id'] in visible_agents]
        return {'domains': domains, 'agents': agents, 'pending_provisioning': pending,
                'users': [{k: user.get(k) for k in ('id', 'username', 'domainid', 'account', 'state', 'accounttype')}
                          for user in users if user.get('domainid') in visible],
                'status': 'CloudStack connected'}

    async def authorize(self, identity, agent_id, *, include_disabled=False):
        agent = (self.store.one('SELECT * FROM agents WHERE id=?', (agent_id,)) if include_disabled
                 else await self.agent(agent_id))
        if not agent:
            raise PermissionError('Agent is unavailable')
        if identity['type'] not in {1, 2}:
            raise PermissionError('A CloudStack administrator account is required')
        result = await self.human_call(identity, 'listDomains', {'id': agent['domain_id'], 'listall': 'true'})
        if not any(d['id'] == agent['domain_id'] for d in result.get('domain', [])):
            raise PermissionError('Agent outside your CloudStack domain')
        return agent

    async def context(self, agent):
        cloud = await self.cloud_client(agent)
        domains = (await cloud.raw('listDomains', {'listall': True})).get('domain', [])
        domain = next((d for d in domains if d['id'] == agent['domain_id']), None)
        if not domain:
            raise PermissionError('Agent domain no longer accessible')
        return {'agent': {'name': agent['name'], 'role': 'DomainAdmin'},
                'cloudstack': {'domain_id': domain['id'], 'domain_name': domain['name'],
                               'domain_path': domain.get('path', domain['name'])},
                'hierarchy': {'parent': domain.get('parentdomainid'),
                              'children': [{'id': d['id'], 'path': d.get('path', d['name'])}
                                           for d in domains if d.get('parentdomainid') == domain['id']]},
                'available_api_names': sorted(set(await cloud.catalogue()) & RUNTIME_APIS),
                'tools': ['search_api', 'describe_api', 'execute_api', 'create_subgroup',
                          'run_vm_command', 'transfer_vm_file', 'delegate'],
                'boundaries': 'Host filesystems, hypervisor configuration and host mounts are platform-admin only.'}

    async def search_api(self, agent_id, query):
        agent = await self.agent(agent_id)
        catalogue = await (await self.cloud_client(agent)).catalogue()
        terms = query.lower().split()[:10]
        matches = [a for name, a in catalogue.items() if name in RUNTIME_APIS
                   and all(term in (name + ' ' + a.get('description', '')).lower() for term in terms)]
        return [{'name': a['name'], 'description': a.get('description', '')[:300]} for a in matches[:30]]

    async def describe_api(self, agent_id, command):
        agent = await self.agent(agent_id)
        if command not in RUNTIME_APIS:
            raise PermissionError('API not available to runtime tools')
        api = (await (await self.cloud_client(agent)).catalogue()).get(command)
        if not api:
            raise PermissionError('API not available to this identity')
        from .cloud import FORBIDDEN_PARAMS
        return {**api, 'params': [p for p in api.get('params', []) if p['name'] not in FORBIDDEN_PARAMS],
                'policy': 'Use scalar values and comma-separated strings for lists, not JSON arrays. '
                          'Host configuration and mounts are unavailable. Managed templates receive SSH keys and '
                          'cloud-init from the backend; use run_vm_command after deployment.'}

    async def execute(self, agent_id, command, params):
        agent = await self.agent(agent_id)
        cloud = await self.cloud_client(agent)
        try:
            if command in VM_POLICY_COMMANDS:
                metadata = (await cloud.catalogue()).get(command)
                if not metadata:
                    raise PermissionError('VM operation unavailable to this CloudStack identity')
                validate(metadata, params)
                await check_vm_policy(self, agent, params, command=command)
            if command == 'deployVirtualMachine' and isinstance(params, dict) and self.store.one(
                    'SELECT id FROM managed_templates WHERE id=?', (params.get('templateid'),)):
                async with self._deploy_lock:
                    result = await self._deploy_managed(agent, cloud, params)
            else:
                result = await cloud.execute(command, params)
            self.store.audit(agent_id, command, status='ok')
            safe = self.redact(result)
            if len(json.dumps(safe)) > self.settings.max_output:
                return {'truncated': True, 'preview': json.dumps(safe)[:self.settings.max_output],
                        'hint': 'Narrow the query with explicit IDs or pagination'}
            return safe
        except BaseException:
            self.store.audit(agent_id, command if isinstance(command, str) and len(command) < 100 else 'invalid-api',
                             status='failed')
            raise

    async def _deploy_managed(self, agent, cloud, params, *, workspace_disk=False):
        from .guest import Guest

        pending = self.store.one("SELECT id FROM vm_deployments WHERE agent_id=? AND phase IN ('prepared','dispatched','failed')",
                                 (agent['id'],))
        if pending:
            raise CloudError(f"Deployment {pending['id']} needs recovery before another managed VM is created", operation_id=pending['id'])
        metadata = (await cloud.catalogue()).get('deployVirtualMachine')
        if not metadata:
            raise PermissionError('VM deployment unavailable to this identity')
        validate(metadata, params)
        await check_vm_policy(self, agent, params, command='deployVirtualMachine')
        if workspace_disk and not params.get('diskofferingid'):
            raise ValueError('Workspace initialization requires a newly provisioned CloudStack data disk')
        if 'userdata' in params or 'userdataid' in params:
            raise ValueError('Managed templates receive trusted SSH cloud-init; custom userdata is unavailable in v0.1')
        if params.get('securitygroupnames'):
            raise ValueError('Use securitygroupids for additional managed VM security groups')
        group_id = await self._ssh_security_group(cloud)
        op_id = uuid.uuid4().hex
        guest = Guest(self)
        cloud_init, access = await guest.prepare_vm_config(agent['id'], workspace_disk=workspace_disk)
        name = 'ds-vm-' + op_id[:20]
        groups = [group_id, *str(params.get('securitygroupids', '')).split(',')]
        request = {**params, 'name': name, 'userdata': base64.b64encode(cloud_init.encode()).decode(),
                   'securitygroupids': ','.join(dict.fromkeys(group for group in groups if group))}
        with self.store.connect() as conn:
            conn.execute('INSERT INTO vm_deployments VALUES(?,?,?,?,NULL,?,?)',
                         (op_id, agent['id'], name, self.store.seal(request), 'prepared', time.time()))
            conn.execute('INSERT INTO vm_access(vm_id,owner_agent,username,private_key,host_key,port) '
                         'VALUES(?,?,?,?,?,?)',
                         ('pending-' + op_id, agent['id'], access['username'], access['private_key'],
                          access['host_key'], access['port']))
        self.store.execute("UPDATE vm_deployments SET phase='dispatched',updated=? WHERE id=?", (time.time(), op_id))
        # Keep a returned job ID durable: never redeploy after an ambiguous timeout or crash.
        try:
            result = await cloud.raw('deployVirtualMachine', request)
        except CloudError as exc:
            if exc.rejected:
                self.store.execute("UPDATE vm_deployments SET phase='rejected',updated=? WHERE id=?",
                                   (time.time(), op_id))
                raise
            raise CloudError(f'Managed deployment {op_id} has an uncertain outcome; recover before retrying', operation_id=op_id) from None
        except (TimeoutError, OSError):
            raise CloudError(f'Managed deployment {op_id} has an uncertain outcome; recover before retrying', operation_id=op_id) from None
        self.store.execute('UPDATE vm_deployments SET params=?,updated=? WHERE id=?',
                           (self.store.seal({'request': request, 'result': result}), time.time(), op_id))
        if result.get('jobid'):
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                status = await cloud.raw('queryAsyncJobResult', {'jobid': result['jobid']})
                if status.get('jobstatus') == 2:
                    # Failed deployment jobs can retain a Stopped VM and its already-injected SSH identity.
                    self.store.execute("UPDATE vm_deployments SET phase='failed',updated=? WHERE id=?",
                                       (time.time(), op_id))
                    raise CloudError(f'Managed deployment {op_id} failed; recover before retrying', operation_id=op_id)
                if status.get('jobstatus') == 1:
                    result = status['jobresult']
                    break
                await asyncio.sleep(2)
            else:
                raise CloudError(f'Managed deployment {op_id} pending; do not retry until recovered', operation_id=op_id)
        vm = first(result, 'virtualmachine')
        self._bind_vm(op_id, vm['id'])
        return result

    async def _ssh_security_group(self, cloud):
        source = ipaddress.ip_network(self.settings.ssh_source_cidr)
        if source.prefixlen != source.max_prefixlen or not source.is_private or source.is_loopback:
            raise ValueError('SSH_SOURCE_CIDR must be one approved private application egress address')
        name = 'dirigentenstab-managed-ssh'
        groups = (await cloud.execute('listSecurityGroups', {'securitygroupname': name})).get('securitygroup', [])
        group = next((g for g in groups if g['name'] == name), None)
        if not group:
            group = first(await cloud.execute('createSecurityGroup', {'name': name,
                          'description': 'SSH only from the private Dirigentenstab application egress'}), 'securitygroup')
        rules = group.get('ingressrule', [])
        if not any(r.get('protocol') == 'tcp' and str(r.get('startport')) == '22'
                   and str(r.get('endport')) == '22' and r.get('cidr') == str(source) for r in rules):
            await cloud.execute('authorizeSecurityGroupIngress', {'securitygroupid': group['id'], 'protocol': 'tcp',
                                'startport': 22, 'endport': 22, 'cidrlist': str(source)})
        return group['id']

    def _bind_vm(self, op_id, vm_id):
        if not isinstance(vm_id, str) or not vm_id:
            raise CloudError('Recovered VM has no valid identity')
        with self.store.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            op = conn.execute('SELECT agent_id,vm_id FROM vm_deployments WHERE id=?', (op_id,)).fetchone()
            if not op or op['vm_id'] not in {None, vm_id}:
                raise CloudError('Deployment is missing or already bound to another VM')
            pending = conn.execute('SELECT owner_agent FROM vm_access WHERE vm_id=?',
                                   ('pending-' + op_id,)).fetchone()
            existing = conn.execute('SELECT owner_agent FROM vm_access WHERE vm_id=?', (vm_id,)).fetchone()
            if pending:
                if pending['owner_agent'] != op['agent_id'] or existing:
                    raise CloudError('Prepared SSH identity ownership conflicts with VM recovery')
                conn.execute('UPDATE vm_access SET vm_id=? WHERE vm_id=?', (vm_id, 'pending-' + op_id))
            elif op['vm_id'] != vm_id or not existing or existing['owner_agent'] != op['agent_id']:
                raise CloudError('Prepared SSH identity is missing; deployment needs administrator review')
            conn.execute("UPDATE vm_deployments SET vm_id=?,phase='complete',updated=? WHERE id=?",
                         (vm_id, time.time(), op_id))

    async def recover_deployments(self):
        for op in self.store.all("SELECT * FROM vm_deployments WHERE phase IN ('prepared','dispatched','failed')"):
            agent = await self.agent(op['agent_id'])
            cloud = await self.cloud_client(agent)
            accounts = (await cloud.raw('listAccounts', {'id': agent['account_id'], 'listall': True})).get('account', [])
            account = next((value for value in accounts if value.get('id') == agent['account_id']
                            and value.get('domainid') == agent['domain_id'] and value.get('name')), None)
            if not account:
                raise CloudError(f"Cannot verify the owning CloudStack account for deployment {op['id']}")
            response = await cloud.raw('listVirtualMachines', {'name': op['name'], 'listall': True})
            matches = [vm for vm in response.get('virtualmachine', []) if vm.get('name') == op['name']
                       and vm.get('account') == account['name'] and vm.get('domainid') == account['domainid']]
            if len(matches) == 1 and matches[0].get('state') in {'Running', 'Stopped'}:
                self._bind_vm(op['id'], matches[0]['id'])
            else:
                self.store.audit(op['agent_id'], 'deployment-recovery-needs-review', op['id'], 'pending')
        # Absence is not proof that dispatch never reached CloudStack. Never create a second VM here.

    async def can_delegate(self, source_id, target_id):
        source, target = await self.agent(source_id), await self.agent(target_id)
        result = await (await self.cloud_client(source)).raw('listDomains',
                                                            {'id': target['domain_id'], 'listall': True})
        return source_id != target_id and any(d['id'] == target['domain_id'] for d in result.get('domain', []))

    async def providers(self, identity):
        if identity['type'] not in {1, 2}:
            raise PermissionError('Administrator required')
        return self.store.all('SELECT id,name,protocol,base_url,default_model FROM providers')

    async def get_provider(self, identity, provider_id):
        if identity['type'] != 1:
            raise PermissionError('Provider secrets require platform administrator')
        row = self.store.one('SELECT * FROM providers WHERE id=?', (provider_id,))
        if not row:
            raise ValueError('Provider missing')
        return row

    async def save_provider(self, identity, name, protocol, base_url, key, default_model='', provider_id=None):
        if identity['type'] != 1:
            raise PermissionError('Provider configuration requires platform administrator')
        if protocol not in {'chat', 'responses'} or not name.strip() or len(name) > 100:
            raise ValueError('Invalid provider name or protocol')
        provider_id = provider_id or str(uuid.uuid4())
        base_url = endpoint(base_url)
        self._remember(key)
        existing = self.store.one('SELECT api_key FROM providers WHERE id=?', (provider_id,))
        encrypted = existing['api_key'] if existing and not key else self.store.seal(key)
        self.store.execute('INSERT INTO providers(id,name,protocol,base_url,api_key,default_model) VALUES(?,?,?,?,?,?) '
                           'ON CONFLICT(id) DO UPDATE SET name=excluded.name,protocol=excluded.protocol,'
                           'base_url=excluded.base_url,api_key=excluded.api_key,default_model=excluded.default_model',
                           (provider_id, name.strip(), protocol, base_url, encrypted, default_model))
        self.store.audit(identity['userid'], 'configure-provider', provider_id)
        return provider_id

    async def update_agent(self, identity, agent_id, provider_id, model, instructions, can_provision=None):
        await self.authorize(identity, agent_id)
        if provider_id and not self.store.one('SELECT id FROM providers WHERE id=?', (provider_id,)):
            raise ValueError('Provider missing')
        if len(model) > 300 or len(instructions) > 32000:
            raise ValueError('Agent configuration too large')
        if can_provision is not None:
            if identity['type'] != 1:
                raise PermissionError('Only a platform administrator can change provisioning permission')
            self.store.execute('UPDATE agents SET can_provision=? WHERE id=?', (bool(can_provision), agent_id))
        self.store.execute('UPDATE agents SET provider_id=?,model=?,instructions=? WHERE id=?',
                           (provider_id or None, model, instructions, agent_id))
        self.store.audit(identity['userid'], 'configure-agent', agent_id)

    async def _key(self, cloud, user_id, name, allowed):
        if not allowed:
            raise PermissionError('Refusing to issue a key without explicit restricted permissions')
        params = {'id': user_id, 'name': name, 'enddate': time.strftime('%Y-%m-%dT%H:%M:%S+0000',
                                                                     time.gmtime(time.time() + 90 * 86400))}
        for index, api in enumerate(sorted(allowed)):
            params[f'rules[{index}].rule'] = api
            params[f'rules[{index}].permission'] = 'allow'
        value = first(await cloud.raw('registerUserKeys', params), 'userkeys')
        return {'id': value['id'], 'apikey': value['apikey'], 'secretkey': value['secretkey']}

    async def _credentials(self, cloud, user_id, operation_id, runtime_allowed=None):
        # On a retry, delete any previously issued keys whose response was lost before persistence.
        keys = (await cloud.raw('listUserKeys', {'userid': user_id})).get('userapikey', [])
        for key in keys:
            if key.get('name', '').startswith('ds-' + operation_id):
                await cloud.raw('deleteUserKeys', {'keypairid': key['id']})
        issuer = set(await cloud.catalogue())
        allowed = RUNTIME_APIS & issuer
        if runtime_allowed is not None:
            allowed &= set(runtime_allowed)
        runtime = await self._key(cloud, user_id, 'ds-' + operation_id + '-runtime', allowed)
        # CloudStack 4.23 requires a signing key to cover every permission it delegates to a child.
        envelope = (PROVISION_APIS | allowed) & issuer
        provisioning = await self._key(cloud, user_id, 'ds-' + operation_id + '-provision', envelope)
        self._remember(runtime)
        self._remember(provisioning)
        return {'runtime': runtime, 'provisioning': provisioning, 'runtime_policy': sorted(allowed)}

    async def create_subgroup(self, agent_id, name, model=None, instructions=None):
        parent = await self.agent(agent_id)
        if not parent['can_provision']:
            raise PermissionError('Subgroup creation disabled for this agent')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _-]{0,63}', name):
            raise ValueError('Use a short subgroup name with letters, numbers, spaces, underscores or dashes')
        if model is not None and len(model) > 300 or instructions is not None and len(instructions) > 32000:
            raise ValueError('Subgroup configuration too large')
        async with self._provision_lock:
            op = self.store.one('SELECT * FROM provisioning WHERE parent_id=? AND name=?', (agent_id, name))
            if not op:
                op_id = uuid.uuid4().hex
                self.store.execute('INSERT INTO provisioning(id,parent_id,name,model,instructions,updated,provider_id) '
                                   'VALUES(?,?,?,?,?,?,?)',
                                   (op_id, agent_id, name, model if model is not None else parent['model'],
                                    instructions if instructions is not None else parent['instructions'],
                                    time.time(), parent['provider_id']))
                op = self.store.one('SELECT * FROM provisioning WHERE id=?', (op_id,))
            runtime_allowed = set(await (await self.cloud_client(parent)).catalogue())
            return await self._provision(op, await self.cloud_client(parent, 'provisioning'),
                                         parent['domain_id'], runtime_allowed)

    async def _provision(self, op, cloud, parent_domain, runtime_allowed=None):
        op_id, resource = op['id'], 'ds-' + op['id'][:20]
        def save(phase, **fields):
            fields = {'phase': phase, 'updated': time.time(), 'error': None, **fields}
            self.store.execute('UPDATE provisioning SET ' + ','.join(key + '=?' for key in fields) + ' WHERE id=?',
                               (*fields.values(), op_id))
            op.update(fields)
        try:
            if op['phase'] == 'complete':
                row = await self.agent(op_id)
                return {k: row[k] for k in ('id', 'name', 'domain_id', 'model')}
            if not op['domain_id']:
                name = op['name'] + '--' + resource
                parents = (await cloud.raw('listDomains', {'id': parent_domain, 'listall': True})).get('domain', [])
                parent = next((d for d in parents if d['id'] == parent_domain), None)
                if not parent:
                    raise PermissionError('Parent domain no longer accessible')
                validate_child(parent, name, getattr(self.settings, 'max_hierarchy_depth', 10))
                save('creating-domain')
                domains = (await cloud.raw('listDomains', {'name': name, 'listall': True})).get('domain', [])
                domain = next((d for d in domains if d['name'] == name
                               and d.get('parentdomainid') == parent_domain), None)
                domain = domain or first(await cloud.raw('createDomain', {'name': name, 'parentdomainid': parent_domain}),
                                         'domain')
                save('domain', domain_id=domain['id'])
            if not op['account_id']:
                save('creating-account')
                accounts = (await cloud.raw('listAccounts', {'name': resource, 'domainid': op['domain_id'],
                                                              'listall': True})).get('account', [])
                account = next((a for a in accounts if a['name'] == resource and a['domainid'] == op['domain_id']), None)
                if not account:
                    password = uuid.uuid4().hex + uuid.uuid4().hex
                    account = first(await cloud.raw('createAccount', {
                        'account': resource, 'username': resource, 'password': password, 'accounttype': 2,
                        'domainid': op['domain_id'], 'firstname': 'Dirigentenstab', 'lastname': op['name'],
                        'email': resource + '@invalid.example'}), 'account')
                user = next((u for u in account.get('user', []) if u['username'] == resource), None)
                if not user:
                    users = (await cloud.raw('listUsers', {'account': resource, 'domainid': op['domain_id'],
                                                          'listall': True})).get('user', [])
                    user = next((u for u in users if u['username'] == resource), None)
                if account.get('accounttype') != 2 or not user:
                    raise PermissionError('Subordinate account must be a domain administrator')
                save('account', account_id=account['id'], user_id=user['id'])
            if not op['credentials']:
                save('issuing-credentials')
                credentials = await self._credentials(cloud, op['user_id'], op_id, runtime_allowed)
                save('credentials', credentials=self.store.seal(credentials))
            credentials = self.store.open(op['credentials'])
            for purpose in ('runtime', 'provisioning'):
                test = await self.client(credentials[purpose]).raw('listDomains', {'id': op['domain_id']})
                if not any(d['id'] == op['domain_id'] for d in test.get('domain', [])):
                    raise PermissionError('New credentials failed domain validation')
            with self.store.connect() as conn:
                conn.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,runtime,provisioning,'
                             'provider_id,model,instructions,can_provision,runtime_policy) VALUES(?,?,?,?,?,?,?,?,?,?,1,?) '
                             'ON CONFLICT(id) DO NOTHING',
                             (op_id, op['name'], op['domain_id'], op['account_id'], op['user_id'],
                              self.store.seal(credentials['runtime']), self.store.seal(credentials['provisioning']),
                              op['provider_id'], op['model'], op['instructions'], json.dumps(credentials['runtime_policy'])))
                conn.execute("UPDATE provisioning SET phase='complete',credentials=NULL,error=NULL,updated=? WHERE id=?",
                             (time.time(), op_id))
            self.store.audit(op['parent_id'] or 'bootstrap', 'create-subgroup', op_id)
            return {'id': op_id, 'name': op['name'], 'domain_id': op['domain_id'], 'model': op['model']}
        except BaseException:
            self.store.execute('UPDATE provisioning SET error=?,updated=? WHERE id=?',
                               ('Provisioning interrupted; retry using the same parent and name', time.time(), op_id))
            self.store.audit(op['parent_id'] or 'bootstrap', 'create-subgroup', op_id, 'incomplete')
            raise

    async def bootstrap(self, credentials):
        cloud = self.client(credentials)
        version = (await cloud.raw('listCapabilities')).get('capability', {}).get('cloudstackversion', '')
        if not re.fullmatch(r'4\.23\.\d+\.\d+', version):
            raise RuntimeError('CloudStack 4.23.x is required for restricted key pairs; no identities were created')
        root = next(d for d in (await cloud.raw('listDomains', {'listall': True})).get('domain', [])
                    if d.get('level') == 0)
        op_id = '00000000000000000000000000000001'
        self.store.execute('INSERT INTO provisioning(id,parent_id,name,model,instructions,updated) '
                           'VALUES(?,NULL,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                           (op_id, 'Agents', '', 'Manage this domain safely. Delegate only to subordinate agents.',
                            time.time()))
        op = self.store.one('SELECT * FROM provisioning WHERE id=?', (op_id,))
        return await self._provision(op, cloud, root['id'])

    async def rotate_credentials(self, identity, agent_id):
        agent = await self.authorize(identity, agent_id)
        async with self._provision_lock:
            service = self
            class HumanIssuer:
                async def raw(self, command, params=None):
                    if command not in PROVISION_APIS:
                        raise PermissionError('API unavailable to credential rotation')
                    return await service.human_call(identity, command, params)

                async def catalogue(self):
                    return {a['name']: a for a in (await self.raw('listApis')).get('api', [])}
            cloud = HumanIssuer()
            rotation = self.store.one('SELECT * FROM credential_rotations WHERE agent_id=?', (agent_id,))
            if not rotation:
                current = {p: self.store.open(agent[p]) for p in ('runtime', 'provisioning')}
                self.store.execute('INSERT INTO credential_rotations VALUES(?,?,?,NULL,?,?)',
                                   (agent_id, uuid.uuid4().hex, self.store.seal(current), 'issuing', time.time()))
                rotation = self.store.one('SELECT * FROM credential_rotations WHERE agent_id=?', (agent_id,))
            current = self.store.open(rotation['previous'])
            if rotation['replacement']:
                keys = self.store.open(rotation['replacement'])
            else:
                try:
                    current_policy = set(await (await self.cloud_client(agent)).catalogue())
                except CloudError:
                    current_policy = set(json.loads(agent['runtime_policy']))
                    if not current_policy:
                        raise PermissionError('Previous runtime policy unknown; restore or review it before rotation') from None
                keys = await self._credentials(cloud, agent['user_id'], rotation['operation_id'], current_policy)
                self.store.execute("UPDATE credential_rotations SET replacement=?,phase='validating',updated=? WHERE agent_id=?",
                                   (self.store.seal(keys), time.time(), agent_id))
            for purpose in ('runtime', 'provisioning'):
                check = await self.client(keys[purpose]).raw('listDomains', {'id': agent['domain_id']})
                if not any(d['id'] == agent['domain_id'] for d in check.get('domain', [])):
                    raise PermissionError('Replacement credentials failed domain validation; old keys retained')
            self.store.execute('UPDATE agents SET runtime=?,provisioning=?,runtime_policy=? WHERE id=?',
                               (self.store.seal(keys['runtime']), self.store.seal(keys['provisioning']),
                                json.dumps(keys['runtime_policy']), agent_id))
            new_cloud = self.client(keys['provisioning'])
            for key in current.values():
                if key.get('id'):
                    available = (await new_cloud.raw('listUserKeys', {'userid': agent['user_id']})).get('userapikey', [])
                    if any(k['id'] == key['id'] for k in available):
                        await new_cloud.raw('deleteUserKeys', {'keypairid': key['id']})
            self.store.execute('DELETE FROM credential_rotations WHERE agent_id=?', (agent_id,))
            self.store.audit(identity['userid'], 'rotate-credentials', agent_id)

    async def revoke_agent(self, identity, agent_id):
        agent = await self.authorize(identity, agent_id, include_disabled=True)
        self.store.execute('UPDATE agents SET enabled=0 WHERE id=?', (agent_id,))
        cloud = await self.cloud_client(agent, 'provisioning')
        call = cloud.raw
        try:
            response = await call('listUserKeys', {'userid': agent['user_id']})
        except CloudError:
            async def call(command, params):
                return await self.human_call(identity, command, params)
            response = await call('listUserKeys', {'userid': agent['user_id']})
        available = response.get('userapikey', [])
        current = self.store.open(agent['provisioning'])
        known = {self.store.open(agent[p]).get('id') for p in ('runtime', 'provisioning')}
        rotation = self.store.one('SELECT previous,replacement FROM credential_rotations WHERE agent_id=?', (agent_id,))
        if rotation:
            for field in ('previous', 'replacement'):
                if rotation[field]:
                    tracked = self.store.open(rotation[field])
                    known.update(tracked[p].get('id') for p in ('runtime', 'provisioning'))
        # Include keys from interrupted provisioning/rotation, and revoke the active signing key last.
        targets = [item for item in available if item.get('name', '').startswith('ds-') or item['id'] in known]
        targets.sort(key=lambda item: item['id'] == current.get('id'))
        for key in targets:
            await call('deleteUserKeys', {'keypairid': key['id']})
        self.store.execute('DELETE FROM credential_rotations WHERE agent_id=?', (agent_id,))
        self.store.audit(identity['userid'], 'revoke-agent', agent_id)
