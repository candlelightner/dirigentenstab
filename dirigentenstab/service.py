import asyncio
import base64
import hashlib
import json
import re
import time
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from urllib.parse import quote

import httpx

from .cloud import Cloud, CloudError, redact, validate
from .settings import endpoint, dashboard_endpoint
from .hierarchy import validate_child
from .limits import APP_ROOT_AGENT, check_vm_policy, gpu_count
from .gpu import GPU_COMMANDS, GPU_CONTEXT, helper_call

_UNSET = object()
_CONFIGURING = ContextVar('configuring_agents', default=frozenset())


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
        self.gpu_local = False
        self.gpu_deployment_id = None
        for row in store.all('SELECT credentials FROM agents UNION ALL SELECT credentials FROM legacy_agent_credentials'):
            self._remember(store.open(row['credentials']))
        for row in store.all('SELECT previous,replacement FROM credential_rotations'):
            for field in ('previous', 'replacement'):
                if row[field]:
                    for pair in self._pairs(store.open(row[field])):
                        self._remember(pair)
        for row in store.all('SELECT api_key FROM providers'):
            self._remember(store.open(row['api_key']))
        for row in store.all('SELECT token FROM mcp_servers'):
            token = store.open(row['token'])
            self._remember(token)
            if token:
                self._remember('Bearer ' + token)

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

    async def cloud_client(self, agent):
        return self.client(self.store.open(agent['credentials']))

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
        if identity.get('_agent_id'):
            actor = await self.agent(identity['_agent_id'])
            result = await (await self.cloud_client(actor)).raw('listDomains', {'id': agent['domain_id'], 'listall': True})
        else:
            if identity['type'] not in {1, 2}:
                raise PermissionError('A CloudStack administrator account is required')
            result = await self.human_call(identity, 'listDomains', {'id': agent['domain_id'], 'listall': 'true'})
        if not any(d['id'] == agent['domain_id'] for d in result.get('domain', [])):
            raise PermissionError('Agent outside your CloudStack domain')
        return agent

    async def context(self, agent):
        cloud = await self.cloud_client(agent)
        try:
            domains = (await cloud.raw('listDomains', {'listall': True})).get('domain', [])
        except CloudError:
            domains = []
        domain = next((d for d in domains if d['id'] == agent['domain_id']), {'id': agent['domain_id']})
        try:
            catalogue = await cloud.catalogue(refresh=True)
        except CloudError:
            catalogue = {}
        return {'agent': {'id': agent['id'], 'name': agent['name'], 'role': 'CloudStack account'},
                'managed_agents': [{key: member[key] for key in ('id', 'name', 'domain_id')}
                                   for member in self.store.all('SELECT id,name,domain_id FROM agents WHERE enabled=1')
                                   if member['domain_id'] in {domain['id'] for domain in domains}],
                'cloudstack': {'domain_id': domain['id'], 'domain_name': domain.get('name'),
                               'domain_path': domain.get('path', domain.get('name'))},
                'hierarchy': {'parent': domain.get('parentdomainid'),
                              'children': [{'id': d['id'], 'path': d.get('path', d['name'])}
                                           for d in domains if d.get('parentdomainid') == domain['id']]},
                'available_api_names': sorted(catalogue),
                'approved_guest_assets': await self.guest_assets(agent['id']),
                'tools': ['search_api', 'describe_api', 'execute_api', 'create_subgroup',
                          'run_vm_command', 'transfer_vm_file', 'configure_agent'],
                'boundaries': 'CloudStack account, domain and role permissions authorize every API request.'}

    async def guest_assets(self, agent_id):
        from .guest import Guest
        return await Guest(self).approved_assets(agent_id)

    def dashboard_url(self, identity):
        if identity.get('type') != 1:
            return ''
        row = self.store.one("SELECT value FROM platform_settings WHERE name='cloudstack_ui_url'")
        value = row['value'] if row else self.settings.cloudstack_ui_url
        return dashboard_endpoint(value) if value else ''

    def save_dashboard_url(self, identity, url):
        if identity.get('type') != 1:
            raise PermissionError('Platform settings require platform administrator')
        value = dashboard_endpoint(url.strip()) if url.strip() else ''
        self.store.execute("INSERT INTO platform_settings VALUES('cloudstack_ui_url',?) "
                           'ON CONFLICT(name) DO UPDATE SET value=excluded.value', (value,))
        self.store.audit(identity['userid'], 'configure-cloudstack-dashboard')

    async def gpu_admin(self, identity, action='status', **payload):
        if identity.get('type') != 1:
            raise PermissionError('GPU policy administration requires a human platform administrator')
        return await helper_call(self.settings, action, session=identity['_session'], **payload)

    async def search_api(self, agent_id, query):
        agent = await self.agent(agent_id)
        catalogue = await (await self.cloud_client(agent)).catalogue(refresh=True)
        terms = query.lower().split()[:10]
        matches = [a for name, a in catalogue.items()
                   if all(term in (name + ' ' + a.get('description', '')).lower() for term in terms)]
        return [{'name': a['name'], 'description': a.get('description', '')[:300]} for a in matches[:30]]

    async def describe_api(self, agent_id, command):
        agent = await self.agent(agent_id)
        api = (await (await self.cloud_client(agent)).catalogue(refresh=True)).get(command)
        if not api:
            raise ValueError('API metadata unavailable; native execution remains available')
        return {**api, 'policy': 'Use scalar values and comma-separated strings for lists, not JSON arrays. '
                'CloudStack account, domain and role permissions determine whether the request is allowed.'}

    async def execute(self, agent_id, command, params, *, managed=False):
        agent = await self.agent(agent_id)
        cloud = await self.cloud_client(agent)
        try:
            gpu_request = None
            if managed and command not in GPU_COMMANDS | {'createTemplate'}:
                raise ValueError('Managed enrollment supports VM deployment, private template creation and GPU lifecycle operations')
            if managed and command in GPU_COMMANDS and not self.gpu_local:
                validate(None, params)
                vm = None
                if command != 'deployVirtualMachine':
                    vm = next((v for v in (await cloud.raw('listVirtualMachines', {'id': params.get('id')})).get(
                        'virtualmachine', []) if v['id'] == params.get('id')), None)
                    if not vm:
                        raise PermissionError('VM is unavailable to this agent')
                offering_ids = {value for value in (params.get('serviceofferingid'), (vm or {}).get('serviceofferingid')) if value}
                gpu = False
                for offering_id in offering_ids:
                    offering = next((o for o in (await cloud.raw('listServiceOfferings', {'id': offering_id})).get(
                        'serviceoffering', []) if o['id'] == offering_id), None)
                    if not offering:
                        raise PermissionError('Compute offering is unavailable to this agent')
                    gpu |= gpu_count(offering) > 0
                if gpu:
                    context = GPU_CONTEXT.get() or {}
                    if not all(isinstance(context.get(field), str) and context[field] for field in ('run_id', 'call_id')):
                        raise PermissionError('Managed GPU operations require an authenticated durable agent execution')
                    gpu_request = {'agent_id': agent_id, 'command': command, 'params': params,
                                   'session': context.get('session'),
                                   'context': {field: context[field] for field in ('run_id', 'call_id')}}
                elif command != 'deployVirtualMachine':
                    raise ValueError('Managed enrollment supports VM deployment, private template creation and GPU lifecycle operations')
            if gpu_request:
                result = await helper_call(self.settings, 'execute', **gpu_request)
            elif managed and command == 'createTemplate':
                result = await self._create_private_template(agent, cloud, params)
            elif managed and command == 'deployVirtualMachine':
                async with self._deploy_lock:
                    result = await self._deploy_managed(agent, cloud, params)
            else:
                # Native APIs never enter the privileged host helper; this account signs its own request.
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
        op_id = self.gpu_deployment_id or uuid.uuid4().hex
        guest = Guest(self)
        cloud_init, access = await guest.prepare_vm_config(agent['id'], workspace_disk=workspace_disk)
        name = 'ds-vm-' + op_id[:20]
        request = {**params, 'name': name, 'userdata': base64.b64encode(cloud_init.encode()).decode()}
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
                    failure = status.get('jobresult')
                    detail = cloud._error_detail(failure.get('errortext', 'Native operation failed')
                                                 if isinstance(failure, dict) else 'Native operation failed', request)
                    raise CloudError(f'Managed deployment {op_id} failed; recover before retrying',
                                     operation_id=op_id, public_detail=detail)
                if status.get('jobstatus') == 1:
                    result = status['jobresult']
                    break
                await asyncio.sleep(2)
            else:
                raise CloudError(f'Managed deployment {op_id} pending; do not retry until recovered', operation_id=op_id)
        vm = first(result, 'virtualmachine')
        self._bind_vm(op_id, vm['id'])
        return result

    async def _create_private_template(self, agent, cloud, params):
        metadata = (await cloud.catalogue()).get('createTemplate')
        if not metadata:
            raise PermissionError('Private template creation is not enabled for this agent')
        validate(metadata, params)
        allowed = {'name', 'displaytext', 'ostypeid', 'volumeid', 'bits', 'isdynamicallyscalable', 'ispublic', 'isfeatured'}
        if set(params) - allowed or params.get('ispublic') or params.get('isfeatured') or not params.get('volumeid'):
            raise PermissionError('Only private templates from an owned managed root volume are permitted')
        volume = next((v for v in (await cloud.raw('listVolumes', {'id': params.get('volumeid')})).get('volume', [])
                       if v['id'] == params.get('volumeid') and v.get('type') == 'ROOT'), None)
        access = self.store.one('SELECT owner_agent FROM vm_access WHERE vm_id=?',
                                ((volume or {}).get('virtualmachineid'),))
        if not volume or not access or access['owner_agent'] != agent['id']:
            raise PermissionError('Template source must be this agent’s managed root volume')
        vm = next((v for v in (await cloud.raw('listVirtualMachines', {'id': volume['virtualmachineid']})).get(
            'virtualmachine', []) if v['id'] == volume['virtualmachineid']), None)
        source = self.store.one('SELECT * FROM managed_templates WHERE id=?', ((vm or {}).get('templateid'),))
        if not vm or vm.get('state') != 'Stopped':
            raise PermissionError('Stop the managed VM and prepare its cloud-init identity before creating a template')
        op_id = hashlib.sha256(json.dumps([agent['id'], params], sort_keys=True).encode()).hexdigest()[:32]
        name = 'ds-template-' + op_id[:20]
        request = {**params, 'name': name, 'displaytext': params.get('displaytext', params['name']),
                   'ispublic': False, 'isfeatured': False}
        op = self.store.one('SELECT * FROM template_creations WHERE id=?', (op_id,))
        if op and op['phase'] == 'complete':
            return {'template': await self._bind_private_template(op)}
        if op:
            raise CloudError('Private template operation needs recovery; do not repeat creation', operation_id=op_id)
        self.store.execute('INSERT INTO template_creations VALUES(?,?,?,?,?,NULL,?,?,?)',
                           (op_id, agent['id'], volume['id'], name, self.store.seal({'request': request}),
                            'dispatched', bool(source and source['guest_admin']), time.time()))
        deadline = time.monotonic() + 600
        try:
            result = await cloud.raw('createTemplate', request)
            self.store.execute('UPDATE template_creations SET params=? WHERE id=?',
                               (self.store.seal({'request': request, 'result': result}), op_id))
            if result.get('jobid'):
                while time.monotonic() < deadline:
                    job = await cloud.raw('queryAsyncJobResult', {'jobid': result['jobid']})
                    if job.get('jobstatus') == 1:
                        break
                    if job.get('jobstatus') == 2:
                        failure = job.get('jobresult')
                        detail = cloud._error_detail(failure.get('errortext', 'Native operation failed')
                                                     if isinstance(failure, dict) else 'Native operation failed', request)
                        raise CloudError('Private template job failed; inspect the saved operation',
                                         operation_id=op_id, public_detail=detail)
                    await asyncio.sleep(2)
                else:
                    raise CloudError('Private template job pending; recover before continuing', operation_id=op_id)
            op = self.store.one('SELECT * FROM template_creations WHERE id=?', (op_id,))
            while time.monotonic() < deadline:
                try:
                    return {'template': await self._bind_private_template(op)}
                except CloudError:
                    await asyncio.sleep(2)
            raise CloudError('Private template is still preparing; recover before continuing', operation_id=op_id)
        except CloudError as exc:
            if exc.rejected:
                self.store.execute("UPDATE template_creations SET phase='rejected' WHERE id=?", (op_id,))
            raise CloudError(str(exc), rejected=exc.rejected, operation_id=op_id,
                             public_detail=exc.public_detail) from None

    async def _bind_private_template(self, op):
        agent = await self.agent(op['agent_id'])
        cloud = await self.cloud_client(agent)
        accounts = (await cloud.raw('listAccounts', {'id': agent['account_id'], 'listall': True})).get('account', [])
        owner = next((a for a in accounts if a['id'] == agent['account_id'] and
                      a.get('domainid') == agent['domain_id']), None)
        if not owner:
            raise CloudError('Private template account ownership could not be verified', operation_id=op['id'])
        values = (await cloud.raw('listTemplates', {'templatefilter': 'self', 'name': op['name'],
                                                  'listall': True})).get('template', [])
        template = next((v for v in values if v.get('name') == op['name'] and v.get('account') == owner['name']
                         and v.get('accountid') in {None, agent['account_id']}
                         and v.get('domainid') == agent['domain_id'] and not v.get('ispublic') and v.get('isready')), None)
        if not template:
            raise CloudError('Private template not ready or ownership not verified; recover before continuing', operation_id=op['id'])
        with self.store.connect() as conn:
            conn.execute('INSERT INTO managed_templates(id,name,guest_admin) VALUES(?,?,?) ON CONFLICT(id) DO NOTHING',
                         (template['id'], template.get('displaytext', template['name']), op['guest_admin']))
            conn.execute("UPDATE template_creations SET template_id=?,phase='complete',updated=? WHERE id=?",
                         (template['id'], time.time(), op['id']))
        return template

    async def recover_templates(self):
        for op in self.store.all("SELECT * FROM template_creations WHERE phase='dispatched'"):
            try:
                await self._bind_private_template(op)
            except CloudError:
                self.store.audit(op['agent_id'], 'template-recovery-needs-review', op['id'], 'pending')

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

    async def recover_deployments(self, operation_id=None):
        query = "SELECT * FROM vm_deployments WHERE phase IN ('prepared','dispatched','failed')"
        for op in self.store.all(query + (' AND id=?' if operation_id else ''), (operation_id,) if operation_id else ()):
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

    async def recover_operation(self, agent_id, operation_id):
        await self.agent(agent_id)
        deployment = self.store.one('SELECT * FROM vm_deployments WHERE id=? AND agent_id=?', (operation_id, agent_id))
        template = self.store.one('SELECT * FROM template_creations WHERE id=? AND agent_id=?', (operation_id, agent_id))
        if deployment:
            await self.recover_deployments(operation_id=operation_id)
            current = self.store.one('SELECT phase,vm_id FROM vm_deployments WHERE id=?', (operation_id,))
            return {'operation_id': operation_id, **current, 'request': self.redact(self.store.open(deployment['params']))}
        if template:
            if template['phase'] == 'dispatched':
                await self._bind_private_template(template)
            current = self.store.one('SELECT phase,template_id FROM template_creations WHERE id=?', (operation_id,))
            return {'operation_id': operation_id, **current, 'request': self.redact(self.store.open(template['params']))}
        raise PermissionError('Managed operation is unavailable to this agent')

    async def execution_identity(self, agent_id, human_id):
        identity = {'_agent_id': agent_id, 'userid': human_id, 'type': 2}
        await self.authorize(identity, agent_id)
        return identity

    async def subgroup_capability(self, agent_id):
        agent = await self.agent(agent_id)
        catalogue = await (await self.cloud_client(agent)).catalogue(refresh=True)
        return all(name in catalogue for name in ('createDomain', 'createAccount', 'registerUserKeys'))

    async def agent_chain(self, agent):
        from .mcp import MCP
        return await MCP(self)._chain(agent)

    def selected_providers(self, agent):
        return set(json.loads(agent['enabled_providers'])) if agent.get('enabled_providers') is not None else {
            row['id'] for row in self.store.all('SELECT id FROM providers')}

    async def effective_providers(self, agent):
        chain = await self.agent_chain(agent)
        allowed = self.selected_providers(chain[0])
        for member in chain[1:]:
            allowed &= self.selected_providers(member)
        return allowed

    async def providers(self, identity):
        if identity['type'] not in {1, 2}:
            raise PermissionError('Administrator required')
        rows = self.store.all('SELECT id,name,protocol,base_url,default_model FROM providers')
        if identity.get('_agent_id'):
            agent = await self.authorize(identity, identity['_agent_id'])
            allowed = await self.effective_providers(agent)
            rows = [row for row in rows if row['id'] in allowed]
        return rows

    async def provider_configuration(self, identity, agent_id):
        agent = await self.authorize(identity, agent_id)
        chain = await self.agent_chain(agent)
        allowed = await self.effective_providers(chain[-2]) if len(chain) > 1 else None
        return {'providers': await self.providers(identity), 'selected': sorted(self.selected_providers(agent)),
                'allowed': sorted(allowed) if allowed is not None else None}

    async def affected_agents(self, agent_id):
        if not getattr(self, 'runtime', None):
            return [agent_id]
        agent = await self.agent(agent_id)
        domains = (await (await self.cloud_client(agent)).raw('listDomains', {'listall': True})).get('domain', [])
        scope = {agent['domain_id']}
        while children := {domain['id'] for domain in domains if domain.get('parentdomainid') in scope} - scope:
            scope |= children
        return [row['id'] for row in self.store.all('SELECT id,domain_id FROM agents') if row['domain_id'] in scope]

    @asynccontextmanager
    async def configuration_change(self, agent_ids):
        runtime = getattr(self, 'runtime', None)
        new_ids = set(agent_ids) - _CONFIGURING.get()
        token = _CONFIGURING.set(_CONFIGURING.get() | new_ids)
        paused = False
        try:
            if runtime and new_ids:
                await runtime.pause_agents(new_ids)
                paused = True
            yield
        finally:
            # Resumed tasks must inherit the cleared transition context.
            _CONFIGURING.reset(token)
            if paused:
                await runtime.resume_agents(new_ids)

    async def owner_ssh_key_access(self, agent):
        chain = await self.agent_chain(agent)
        allowed = all(member['owner_ssh_key_enabled'] for member in chain[:-1])
        selected = bool(agent['owner_ssh_key_enabled'])
        return {'selected': selected, 'allowed': allowed, 'enabled': selected and allowed}

    def owner_ssh_key(self, identity):
        if identity.get('_agent_id') or identity.get('type') != 1:
            raise PermissionError('Owner SSH configuration requires a human platform administrator')
        row = self.store.one("SELECT value FROM platform_settings WHERE name='owner_ssh_public_key'")
        return row['value'] if row else ''

    async def save_owner_ssh_key(self, identity, public_key):
        import asyncssh
        self.owner_ssh_key(identity)
        if not isinstance(public_key, str) or len(public_key) > 16384 or 'PRIVATE KEY' in public_key:
            raise ValueError('Use an SSH public key')
        try:
            value = asyncssh.import_public_key(public_key.strip()).export_public_key().decode().strip() if public_key.strip() else ''
        except (ValueError, asyncssh.KeyImportError):
            raise ValueError('Use an SSH public key') from None
        self.store.execute("INSERT INTO platform_settings VALUES('owner_ssh_public_key',?) "
                           'ON CONFLICT(name) DO UPDATE SET value=excluded.value', (value,))
        self.store.audit(identity['userid'], 'configure-owner-ssh-key')

    async def vm_overview(self, identity, agent_id):
        agent = await self.authorize(identity, agent_id)
        result = await (await self.cloud_client(agent)).raw('listVirtualMachines', {'listall': True})
        base = self.dashboard_url(identity)
        machines = []
        for vm in result.get('virtualmachine', []):
            record = self.store.one('SELECT username,port FROM vm_access WHERE vm_id=?', (vm['id'],))
            nics = vm.get('nic', [])
            nic = next((item for item in nics if item.get('isdefault')), nics[0] if nics else {})
            machines.append({key: vm.get(key) for key in ('id', 'name', 'displayname', 'state')} | {
                'address': nic.get('ipaddress'), 'username': record['username'] if record else None,
                'port': record['port'] if record else 22,
                'cloudstack_url': base + '#/vm/' + quote(vm['id'], safe='') if base else ''})
        return machines

    async def configure_agent(self, actor_id, target_id, settings=None):
        identity = await self.execution_identity(actor_id, actor_id)
        target = await self.authorize(identity, target_id)
        if actor_id != target_id:
            chain = await self.agent_chain(target)
            if actor_id not in {member['id'] for member in chain[:-1]}:
                raise PermissionError('Only an ancestor agent may configure descendants')
        if settings is None:
            from .mcp import MCP
            providers = await self.provider_configuration(identity, target_id)
            mcp = await MCP(self).configuration(identity, target_id)
            key_access = await self.owner_ssh_key_access(target)
            owner_key = (self.store.one("SELECT value FROM platform_settings WHERE name='owner_ssh_public_key'")
                         if key_access['enabled'] else None)
            return {'agent': {key: target[key] for key in ('id', 'name', 'provider_id', 'model', 'instructions',
                    'thinking', 'compaction_provider_id', 'compaction_model', 'auto_compact_percent', 'context_window')},
                    'enabled_providers': providers['selected'], 'allowed_providers': providers['allowed'],
                    'providers': providers['providers'], 'mcp_servers': mcp['servers'],
                    'owner_ssh_key_access': key_access, 'owner_ssh_public_key': owner_key['value'] if owner_key else None}
        if not isinstance(settings, dict) or not settings:
            raise ValueError('Supply agent settings')
        allowed = {'provider_id', 'model', 'instructions', 'thinking', 'compaction_provider_id',
                   'compaction_model', 'auto_compact_percent', 'context_window', 'enabled_providers', 'enabled_mcp_servers', 'mcp_tools', 'owner_ssh_key_enabled'}
        if set(settings) - allowed:
            raise ValueError('Unsupported agent setting')
        if actor_id == target_id and set(settings) != {'instructions'}:
            raise PermissionError('An agent may only edit its own system prompt')
        updates = dict(settings)
        mcp_tools = updates.pop('mcp_tools', None)
        # Validate tool assignments before changing model or prompt.
        if mcp_tools is not None:
            from .mcp import MCP
            if not isinstance(mcp_tools, dict):
                raise ValueError('MCP tools must map server IDs to selected tool names')
            for server_id, tools in mcp_tools.items():
                await MCP(self).validate_assignment(identity, target_id, server_id, tools)
        async with self.configuration_change(await self.affected_agents(target_id)):
            await self.update_agent(identity, target_id, updates.pop('provider_id', target['provider_id']),
                                    updates.pop('model', target['model']), updates.pop('instructions', target['instructions']), **updates)
            if mcp_tools is not None:
                from .mcp import MCP
                for server_id, tools in mcp_tools.items():
                    await MCP(self).assign(identity, target_id, server_id, tools)
        return {'id': target_id, 'configured': True}

    async def get_provider(self, identity, provider_id):
        if identity.get('_agent_id') or identity['type'] != 1:
            raise PermissionError('Provider secrets require platform administrator')
        row = self.store.one('SELECT * FROM providers WHERE id=?', (provider_id,))
        if not row:
            raise ValueError('Provider missing')
        return row

    async def save_provider(self, identity, name, protocol, base_url, key, default_model='', provider_id=None):
        if identity.get('_agent_id') or identity['type'] != 1:
            raise PermissionError('Provider configuration requires platform administrator')
        if protocol not in {'chat', 'responses'} or not name.strip() or len(name) > 100:
            raise ValueError('Invalid provider name or protocol')
        provider_id = provider_id or str(uuid.uuid4())
        base_url = endpoint(base_url)
        self._remember(key)
        existing = self.store.one('SELECT api_key FROM providers WHERE id=?', (provider_id,))
        encrypted = existing['api_key'] if existing and not key else self.store.seal(key)
        async with self.configuration_change([row['id'] for row in self.store.all('SELECT id FROM agents')]):
            self.store.execute('INSERT INTO providers(id,name,protocol,base_url,api_key,default_model) VALUES(?,?,?,?,?,?) '
                               'ON CONFLICT(id) DO UPDATE SET name=excluded.name,protocol=excluded.protocol,'
                               'base_url=excluded.base_url,api_key=excluded.api_key,default_model=excluded.default_model',
                               (provider_id, name.strip(), protocol, base_url, encrypted, default_model))
        self.store.audit(identity['userid'], 'configure-provider', provider_id)
        return provider_id

    async def update_agent(self, identity, agent_id, provider_id, model, instructions, can_provision=None,
                           *, thinking=None, compaction_provider_id=_UNSET, compaction_model=_UNSET,
                           auto_compact_percent=_UNSET, context_window=_UNSET, enabled_providers=_UNSET, enabled_mcp_servers=_UNSET, owner_ssh_key_enabled=_UNSET):
        agent = await self.authorize(identity, agent_id)
        if provider_id and not self.store.one('SELECT id FROM providers WHERE id=?', (provider_id,)):
            raise ValueError('Provider missing')
        if not isinstance(model, str) or not isinstance(instructions, str) or len(model) > 300 or len(instructions) > 32000:
            raise ValueError('Agent configuration too large')
        if thinking is not None and (not isinstance(thinking, str)
                                     or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', thinking)):
            raise ValueError('Invalid thinking level')
        compaction = {key: agent.get(key) if value is _UNSET else value for key, value in {
            'compaction_provider_id': compaction_provider_id, 'compaction_model': compaction_model,
            'auto_compact_percent': auto_compact_percent, 'context_window': context_window}.items()}
        selected_provider = compaction['compaction_provider_id']
        if selected_provider is not None and (not isinstance(selected_provider, str) or len(selected_provider) > 256):
            raise ValueError('Invalid compaction provider')
        compaction['compaction_provider_id'] = selected_provider or None
        if compaction['compaction_model'] is None:
            compaction['compaction_model'] = ''
        if not isinstance(compaction['compaction_model'], str) or len(compaction['compaction_model']) > 256:
            raise ValueError('Invalid compaction model')
        if compaction['compaction_provider_id']:
            selected = self.store.one('SELECT default_model FROM providers WHERE id=?',
                                      (compaction['compaction_provider_id'],))
            if not selected:
                raise ValueError('Compaction provider missing')
            if compaction['auto_compact_percent'] is not None and not (compaction['compaction_model'].strip() or selected['default_model']):
                raise ValueError('Choose a compaction model')
        else:
            compaction['compaction_model'] = ''
        percentage = compaction['auto_compact_percent']
        if percentage is not None and (type(percentage) is not int or not 1 <= percentage <= 99):
            raise ValueError('Automatic compaction must be a whole percentage from 1 to 99, or disabled')
        window = compaction['context_window']
        if window is not None and (type(window) is not int or not 2 <= window <= 2147483647):
            raise ValueError('Context window must be a whole token count from 2 to 2147483647')
        chain = await self.agent_chain(agent)
        actor_id = identity.get('_agent_id')
        if actor_id == agent_id and (provider_id != agent['provider_id'] or model != agent['model'] or
                thinking is not None or enabled_providers is not _UNSET or enabled_mcp_servers is not _UNSET or owner_ssh_key_enabled is not _UNSET or any(
                    value is not _UNSET for value in (compaction_provider_id, compaction_model, auto_compact_percent, context_window))):
            raise PermissionError('An agent may only edit its own system prompt')
        if actor_id and actor_id != agent_id and actor_id not in {member['id'] for member in chain[:-1]}:
            raise PermissionError('Only an ancestor agent may configure descendants')
        if owner_ssh_key_enabled is not _UNSET:
            if type(owner_ssh_key_enabled) is not bool:
                raise ValueError('Owner SSH public key access must be a boolean')
            if owner_ssh_key_enabled and not all(member['owner_ssh_key_enabled'] for member in chain[:-1]):
                raise PermissionError('Owner SSH public key access cannot widen ancestor access')
        selection = self.selected_providers(agent) if enabled_providers is _UNSET else enabled_providers
        if not isinstance(selection, (set, list)) or any(not isinstance(item, str) for item in selection):
            raise ValueError('Enabled providers must be a list of provider IDs')
        selection = set(selection)
        catalog = {row['id'] for row in self.store.all('SELECT id FROM providers')}
        if not selection <= catalog:
            raise ValueError('Provider missing')
        ceiling = await self.effective_providers(chain[-2]) if len(chain) > 1 else catalog
        if actor_id and actor_id != agent_id:
            ceiling &= await self.effective_providers(await self.agent(actor_id))
        if enabled_providers is not _UNSET and not selection - self.selected_providers(agent) <= ceiling:
            raise PermissionError('Provider selections cannot widen ancestor access')
        for chosen, previous, model_changed in ((provider_id, agent['provider_id'], model != agent['model']),
                                 (compaction['compaction_provider_id'], agent.get('compaction_provider_id'),
                                  compaction['compaction_model'] != agent.get('compaction_model', ''))):
            if chosen and (chosen != previous or model_changed) and chosen not in selection & ceiling:
                raise PermissionError('Selected provider is outside inherited access')
        from .mcp import MCP
        policy = MCP(self)
        selected_servers = policy.selected_servers(agent) if enabled_mcp_servers is _UNSET else enabled_mcp_servers
        if not isinstance(selected_servers, (set, list)) or any(not isinstance(item, str) for item in selected_servers):
            raise ValueError('Enabled MCP servers must be a list of server IDs')
        selected_servers = set(selected_servers)
        if not selected_servers <= {row['id'] for row in self.store.all('SELECT id FROM mcp_servers')}:
            raise ValueError('MCP server is unavailable')
        if any(not policy.server_enabled(chain[:-1], server_id)
               for server_id in selected_servers - policy.selected_servers(agent)):
            raise PermissionError('MCP selections cannot widen ancestor access')
        affected = await self.affected_agents(agent_id)
        async with self.configuration_change(affected):
            self.store.execute('UPDATE agents SET provider_id=?,model=?,instructions=?,thinking=COALESCE(?,thinking),'
                               'compaction_provider_id=?,compaction_model=?,auto_compact_percent=?,context_window=?,'
                               'enabled_providers=?,enabled_mcp_servers=?,owner_ssh_key_enabled=? WHERE id=?',
                               (provider_id or None, model, instructions, thinking, compaction['compaction_provider_id'],
                                compaction['compaction_model'], percentage, window,
                                json.dumps(sorted(selection)) if enabled_providers is not _UNSET else agent.get('enabled_providers'),
                                json.dumps(sorted(selected_servers)) if enabled_mcp_servers is not _UNSET else agent.get('enabled_mcp_servers'),
                                agent['owner_ssh_key_enabled'] if owner_ssh_key_enabled is _UNSET else owner_ssh_key_enabled, agent_id))
        self.store.audit(identity['userid'], 'configure-agent', agent_id)

    async def _key(self, call, user_id, name):
        value = first(await call('registerUserKeys', {'id': user_id, 'name': name}), 'userkeys')
        return {'id': value['id'], 'apikey': value['apikey'], 'secretkey': value['secretkey']}

    @staticmethod
    def _pairs(value):
        if isinstance(value, dict):
            if all(isinstance(value.get(key), str) and value[key] for key in ('id', 'apikey', 'secretkey')):
                return [{key: value[key] for key in ('id', 'apikey', 'secretkey')}]
            return [pair for item in value.values() for pair in Service._pairs(item)]
        if isinstance(value, list):
            return [pair for item in value for pair in Service._pairs(item)]
        return []

    async def _owned_keys(self, call, agent, *, enabled=True):
        accounts = (await call('listAccounts', {'id': agent['account_id'], 'listall': True})).get('account', [])
        account = next((a for a in accounts if a.get('id') == agent['account_id']
                        and a.get('domainid') == agent['domain_id']), None)
        if not account or not account.get('name') or enabled and account.get('state') != 'enabled':
            raise PermissionError('Cannot verify the managed CloudStack account; previous credentials retained')
        response = await call('listUsers', {'account': account['name'], 'domainid': agent['domain_id'],
                                          'listall': True, 'page': 1, 'pagesize': 500})
        users = response.get('user', [])
        if (len(users) != 1 or int(response.get('count', len(users))) != 1
                or users[0].get('id') != agent['user_id'] or users[0].get('accountid') != agent['account_id']
                or users[0].get('domainid') != agent['domain_id']
                or enabled and users[0].get('state') != 'enabled'):
            raise PermissionError('Managed account must contain exactly its recorded user; review it in CloudStack before retrying')
        response = await call('listUserKeys', {'userid': agent['user_id'], 'page': 1, 'pagesize': 500})
        keys = response.get('userapikey', [])
        if int(response.get('count', len(keys))) != len(keys):
            raise PermissionError('Native key catalogue is incomplete; previous credentials retained')
        for key in keys:
            if (key.get('userid') != agent['user_id'] or key.get('accountid') != agent['account_id']
                    or key.get('domainid') != agent['domain_id'] or not self._pairs(key)):
                raise PermissionError('Native key ownership cannot be verified; previous credentials retained')
        return keys

    async def _credentials(self, call, agent, operation_id):
        name = 'ds-' + operation_id + '-key'
        available = await self._owned_keys(call, agent)
        matches = [key for key in available if key.get('name') == name]
        if len(matches) > 1:
            raise PermissionError('Multiple keys match this credential operation; inspect CloudStack before retrying')
        if matches:
            pair = self._native_pair(available, agent, key_id=matches[0]['id'])
        else:
            pair = await self._key(call, agent['user_id'], name)
        self._remember(pair)
        return pair

    async def _validate_credentials(self, call, agent, credentials):
        available = await self._owned_keys(call, agent)
        pair = self._native_pair(available, agent, key_id=credentials['id'], credentials=credentials)
        self._remember(pair)
        client = self.client(pair)
        domains = (await client.raw('listDomains', {'id': agent['domain_id']})).get('domain', [])
        if not any(domain.get('id') == agent['domain_id'] for domain in domains):
            raise PermissionError('Replacement credentials failed domain validation; old keys retained')
        users = (await client.raw('listUsers', {'id': agent['user_id']})).get('user', [])
        if not any(user.get('id') == agent['user_id'] and user.get('accountid') == agent['account_id']
                   and user.get('domainid') == agent['domain_id'] and user.get('state') == 'enabled' for user in users):
            raise PermissionError('Replacement credentials failed user validation; old keys retained')
        return pair

    async def _cleanup_credentials(self, call, agent, previous, retained):
        available = await self._owned_keys(call, agent)
        known = {pair['id'] for pair in previous} | {retained['id']}
        if any(key['id'] not in known for key in available):
            raise PermissionError('New keys appeared during credential maintenance; inspect CloudStack before retrying')
        for key in available:
            if key['id'] != retained['id']:
                await call('deleteUserKeys', {'keypairid': key['id']})
        remaining = await self._owned_keys(call, agent)
        if len(remaining) != 1 or remaining[0]['id'] != retained['id']:
            raise PermissionError('Cannot verify a single active key pair; credential cleanup remains pending')

    async def create_subgroup(self, agent_id, name, model=None, instructions=None, *, enabled_providers=None, enabled_mcp_servers=None, mcp_tools=None):
        parent = await self.agent(agent_id)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _-]{0,63}', name):
            raise ValueError('Use a short subgroup name with letters, numbers, spaces, underscores or dashes')
        if (model is not None and (not isinstance(model, str) or len(model) > 300) or
                instructions is not None and (not isinstance(instructions, str) or len(instructions) > 32000)):
            raise ValueError('Subgroup configuration too large')
        if enabled_providers is not None:
            if (not isinstance(enabled_providers, list) or any(not isinstance(item, str) for item in enabled_providers)
                    or not set(enabled_providers) <= await self.effective_providers(parent)):
                raise PermissionError('Provider selections cannot widen parent access')
        if enabled_mcp_servers is not None:
            from .mcp import MCP
            policy = MCP(self)
            chain = await self.agent_chain(parent)
            if (not isinstance(enabled_mcp_servers, list)
                    or any(not isinstance(server_id, str) for server_id in enabled_mcp_servers)
                    or not set(enabled_mcp_servers) <= policy.selected_servers(parent)
                    or any(not policy.server_enabled(chain, server_id) for server_id in enabled_mcp_servers)):
                raise PermissionError('MCP selections cannot widen parent access')
        if mcp_tools is not None:
            from .mcp import MCP, TOOL_NAME
            if not isinstance(mcp_tools, dict):
                raise ValueError('MCP tools must map server IDs to selected tool names')
            policy = MCP(self)
            chain = await self.agent_chain(parent)
            for server_id, tools in mcp_tools.items():
                if not self.store.one('SELECT id FROM mcp_servers WHERE id=?', (server_id,)):
                    raise ValueError('MCP server is unavailable')
                if (not isinstance(tools, list) or len(tools) > 100 or
                        any(not isinstance(tool, str) or not TOOL_NAME.fullmatch(tool) for tool in tools)):
                    raise ValueError('Assign at most 100 exact MCP tool names')
                if not set(tools) <= policy._effective(chain, server_id):
                    raise PermissionError('MCP selections cannot widen parent access')
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
            result = await self._provision(op, await self.cloud_client(parent), parent['domain_id'])
            settings = {}
            if enabled_providers is not None:
                settings['enabled_providers'] = enabled_providers
            if enabled_mcp_servers is not None:
                settings['enabled_mcp_servers'] = enabled_mcp_servers
            if mcp_tools is not None:
                settings['mcp_tools'] = mcp_tools
            if settings:
                await self.configure_agent(agent_id, result['id'], settings)
            return result

    async def _provision(self, op, cloud, parent_domain):
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
                validate_child(parent, name)
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
            target = {'user_id': op['user_id'], 'account_id': op['account_id'], 'domain_id': op['domain_id']}
            credentials = self.store.open(op['credentials']) if op['credentials'] else None
            if not credentials or 'credential' not in credentials:
                previous = self._pairs(credentials) + self._pairs(await self._owned_keys(cloud.raw, target))
                credentials = {'previous': previous, 'credential': None}
                save('issuing-credentials', credentials=self.store.seal(credentials))
            if not credentials['credential']:
                credentials['credential'] = await self._credentials(cloud.raw, target, op_id)
                save('validating-credentials', credentials=self.store.seal(credentials))
            pair = await self._validate_credentials(cloud.raw, target, credentials['credential'])
            inherited = None
            if op['parent_id']:
                parent = await self.agent(op['parent_id'])
                inherited = (parent['thinking'], parent['compaction_provider_id'], parent['compaction_model'],
                             parent['auto_compact_percent'], parent['context_window'],
                             json.dumps(sorted(await self.effective_providers(parent))), parent.get('enabled_mcp_servers'), op_id)
            with self.store.connect() as conn:
                conn.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials,'
                             'provider_id,model,instructions,can_provision) VALUES(?,?,?,?,?,?,?,?,?,1) '
                             'ON CONFLICT(id) DO NOTHING',
                             (op_id, op['name'], op['domain_id'], op['account_id'], op['user_id'],
                              self.store.seal(pair), op['provider_id'], op['model'], op['instructions']))
                if inherited and conn.execute('SELECT changes()').fetchone()[0]:
                    conn.execute('UPDATE agents SET thinking=?,compaction_provider_id=?,compaction_model=?,'
                                 'auto_compact_percent=?,context_window=?,enabled_providers=?,enabled_mcp_servers=? WHERE id=?',
                                 inherited)
                    conn.execute('INSERT INTO mcp_assignments SELECT ?,server_id,tools FROM mcp_assignments WHERE agent_id=?',
                                 (op_id, parent['id']))
                conn.execute("UPDATE provisioning SET phase='cleaning-credentials',updated=? WHERE id=?",
                             (time.time(), op_id))
            await self._cleanup_credentials(cloud.raw, target, credentials['previous'], pair)
            with self.store.connect() as conn:
                conn.execute("UPDATE provisioning SET phase='complete',credentials=NULL,error=NULL,updated=? WHERE id=?",
                             (time.time(), op_id))
                conn.execute('DELETE FROM legacy_agent_credentials WHERE agent_id=?', (op_id,))
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
            raise RuntimeError('CloudStack 4.23.x is required for native key pairs; no identities were created')
        root = next(d for d in (await cloud.raw('listDomains', {'listall': True})).get('domain', [])
                    if d.get('level') == 0)
        op_id = APP_ROOT_AGENT
        self.store.execute('INSERT INTO provisioning(id,parent_id,name,model,instructions,updated) '
                           'VALUES(?,NULL,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                           (op_id, 'Agents', '', 'Manage this domain safely. Only the human owner assigns work.',
                            time.time()))
        op = self.store.one('SELECT * FROM provisioning WHERE id=?', (op_id,))
        return await self._provision(op, cloud, root['id'])

    @staticmethod
    def _native_pair(available, agent, *, key_id=None, credentials=None):
        matches = [key for key in available if
                   (key.get('id') == key_id if key_id else key.get('apikey') == (credentials or {}).get('apikey'))]
        if len(matches) != 1:
            raise PermissionError('The exact native key pair could not be found; previous credentials retained')
        key = matches[0]
        if (key.get('userid') != agent['user_id'] or key.get('accountid') != agent['account_id']
                or key.get('domainid') != agent['domain_id'] or str(key.get('state', '')).lower() != 'enabled'
                or credentials and any(key.get(field) != credentials.get(field) for field in ('apikey', 'secretkey'))
                or not all(isinstance(key.get(name), str) and key[name] for name in ('id', 'apikey', 'secretkey'))):
            raise PermissionError('Native key pair must be enabled and belong to this exact agent user/account/domain')
        return {name: key[name] for name in ('id', 'apikey', 'secretkey')}

    async def rotate_credentials(self, identity, agent_id, *, native_key_id=None):
        agent = await self.authorize(identity, agent_id)
        async with self._provision_lock:
            async def call(command, params):
                return await self.human_call(identity, command, params)

            available = await self._owned_keys(call, agent)
            rotation = self.store.one('SELECT * FROM credential_rotations WHERE agent_id=?', (agent_id,))
            legacy = self.store.one('SELECT credentials FROM legacy_agent_credentials WHERE agent_id=?', (agent_id,))
            # Old paired journals remain encrypted until all their superseded keys have been removed.
            if (not rotation or not isinstance(self.store.open(rotation['previous']), list)
                    or rotation['replacement'] and 'apikey' not in self.store.open(rotation['replacement'])):
                tracked = self._pairs(self.store.open(agent['credentials']))
                if legacy:
                    tracked += self._pairs(self.store.open(legacy['credentials']))
                if rotation:
                    tracked += self._pairs(self.store.open(rotation['previous']))
                    if rotation['replacement']:
                        tracked += self._pairs(self.store.open(rotation['replacement']))
                tracked += self._pairs(available)
                previous = list({pair['id']: pair for pair in tracked}.values())
                operation_id = rotation['operation_id'] if rotation else uuid.uuid4().hex
                self.store.execute('INSERT INTO credential_rotations VALUES(?,?,?,NULL,?,?) '
                                   'ON CONFLICT(agent_id) DO UPDATE SET previous=excluded.previous,replacement=NULL,'
                                   'phase=excluded.phase,updated=excluded.updated',
                                   (agent_id, operation_id, self.store.seal(previous), 'issuing', time.time()))
                rotation = self.store.one('SELECT * FROM credential_rotations WHERE agent_id=?', (agent_id,))
            previous = self._pairs(self.store.open(rotation['previous']))
            if rotation['replacement']:
                pair = self.store.open(rotation['replacement'])
                if native_key_id and pair['id'] != native_key_id:
                    raise PermissionError('A different credential reconciliation is already pending')
            else:
                if native_key_id:
                    pair = self._native_pair(available, agent, key_id=native_key_id)
                else:
                    pair = await self._credentials(call, agent, rotation['operation_id'])
                self.store.execute("UPDATE credential_rotations SET replacement=?,phase='validating',updated=? WHERE agent_id=?",
                                   (self.store.seal(pair), time.time(), agent_id))
            pair = await self._validate_credentials(call, agent, pair)
            with self.store.connect() as conn:
                conn.execute('UPDATE agents SET credentials=? WHERE id=?', (self.store.seal(pair), agent_id))
                conn.execute("UPDATE credential_rotations SET phase='revoking',updated=? WHERE agent_id=?",
                             (time.time(), agent_id))
            await self._cleanup_credentials(call, agent, previous, pair)
            with self.store.connect() as conn:
                conn.execute('DELETE FROM credential_rotations WHERE agent_id=?', (agent_id,))
                conn.execute('DELETE FROM legacy_agent_credentials WHERE agent_id=?', (agent_id,))
            self.store.audit(identity['userid'], 'adopt-native-key' if native_key_id else 'rotate-credentials', agent_id)

    async def revoke_agent(self, identity, agent_id):
        agent = await self.authorize(identity, agent_id, include_disabled=True)
        self.store.execute('UPDATE agents SET enabled=0 WHERE id=?', (agent_id,))

        async def call(command, params):
            return await self.human_call(identity, command, params)

        # Human authority remains available after the agent's last authentication key is deleted.
        for key in await self._owned_keys(call, agent, enabled=False):
            await call('deleteUserKeys', {'keypairid': key['id']})
        if await self._owned_keys(call, agent, enabled=False):
            raise PermissionError('Agent key revocation remains pending; inspect CloudStack before retrying')
        with self.store.connect() as conn:
            conn.execute('DELETE FROM credential_rotations WHERE agent_id=?', (agent_id,))
            conn.execute('DELETE FROM legacy_agent_credentials WHERE agent_id=?', (agent_id,))
        self.store.audit(identity['userid'], 'revoke-agent', agent_id)
