#!/usr/bin/env python3
"""Local platform-administrator recovery entry point; never an agent tool."""
import argparse
import asyncio
import getpass
import json
import os
from pathlib import Path
import subprocess

from dotenv import dotenv_values

from dirigentenstab.auth import Auth
from dirigentenstab.service import Service
from dirigentenstab.settings import Settings
from dirigentenstab.store import Store


def service():
    root = Path(__file__).resolve().parent.parent
    env = dotenv_values(root / '.env')
    volume = json.loads(subprocess.check_output(['docker', 'volume', 'inspect', 'dirigentenstab_data']))[0]
    return Service(Store(volume['Mountpoint'] + '/dirigentenstab.db',
                         str(root / env.get('MASTER_KEY_PATH', 'secrets/master_key'))),
                   Settings(env['CLOUDSTACK_URL'], env['PUBLIC_ORIGIN'], cmk='/usr/local/bin/cmk',
                            cloudstack_ui_url=env.get('CLOUDSTACK_UI_URL', ''),
                            guest_assets=volume['Mountpoint'] + '/guest-assets',
                            max_hierarchy_depth=int(env.get('MAX_HIERARCHY_DEPTH', '10'))))


async def perform(options, app, login=None):
    if options.command == 'status':
        print(json.dumps({'provisioning': app.store.all('SELECT id,parent_id,name,phase,error FROM provisioning'),
                          'deployments': app.store.all('SELECT id,agent_id,name,vm_id,phase FROM vm_deployments'),
                          'templates': app.store.all('SELECT id,agent_id,name,template_id,phase FROM template_creations'),
                          'rotations': app.store.all('SELECT agent_id,operation_id,phase FROM credential_rotations'),
                          'legacy_credentials': app.store.all('SELECT agent_id FROM legacy_agent_credentials'),
                          'legacy_credential_count': app.store.one('SELECT COUNT(*) AS count FROM legacy_agent_credentials')['count']}, indent=2))
        return
    if options.command == 'recover-deployments':
        await app.recover_deployments()
        print('Recovery queried CloudStack and bound discovered VMs; unresolved operations remain pending.')
        return
    if options.command == 'recover-templates':
        await app.recover_templates()
        print('Existing templates inspected; unresolved operations retained without repeating creation.')
        return
    if options.command == 'resolve-rejection':
        if not options.confirmed_rejection:
            raise SystemExit('Requires --confirmed-rejection after verifying a definitive server rejection in private logs.')
        op = app.store.one("SELECT * FROM vm_deployments WHERE id=? AND phase IN ('prepared','dispatched','failed')",
                           (options.identifier,))
        if not op:
            raise SystemExit('No unresolved deployment with that ID.')
        cloud = await app.cloud_client(await app.agent(op['agent_id']))
        vms = (await cloud.raw('listVirtualMachines', {'name': op['name'], 'listall': True})).get('virtualmachine', [])
        if vms:
            raise SystemExit('A VM exists; use recover-deployments instead. No state changed.')
        jobs = (await cloud.raw('listAsyncJobs', {'listall': True})).get('asyncjobs', [])
        if any(job.get('jobstatus') == 0 for job in jobs):
            raise SystemExit('An asynchronous job is pending; no state changed.')
        app.store.execute("UPDATE vm_deployments SET phase='rejected' WHERE id=?", (op['id'],))
        app.store.audit('local-platform-admin', 'resolve-confirmed-deployment-rejection', op['id'])
        print('Confirmed rejected deployment marked rejected. No VM was created or deleted.')
        return
    auth = Auth(app)
    token, _ = await auth.login(login['username'], login['password'], login.get('domain', '/'), 'local-admin')
    try:
        identity = await auth.identity(token)
        if options.command in {'rotate', 'migrate-key'}:
            await app.rotate_credentials(identity, options.identifier)
        elif options.command == 'migrate-keys':
            domains = (await app.human_call(identity, 'listDomains', {'listall': True})).get('domain', [])
            visible = {domain['id'] for domain in domains}
            for agent in app.store.all('SELECT id,domain_id FROM agents WHERE enabled=1 AND '
                                      '(id IN (SELECT agent_id FROM legacy_agent_credentials) OR '
                                      'id IN (SELECT agent_id FROM credential_rotations))'):
                if agent['domain_id'] in visible:
                    await app.rotate_credentials(identity, agent['id'])
                    print('Migrated credentials for ' + agent['id'])
        elif options.command == 'adopt-key':
            await app.rotate_credentials(identity, options.identifier, native_key_id=options.key_id)
        elif options.command == 'approve-template':
            if identity['type'] != 1:
                raise PermissionError('Template approval requires platform administrator')
            values = (await app.human_call(identity, 'listTemplates',
                      {'id': options.identifier, 'templatefilter': 'all', 'listall': 'true'})).get('template', [])
            value = next((v for v in values if v['id'] == options.identifier and v.get('isready') and
                          v.get('hypervisor') == 'KVM'), None)
            if not value:
                raise ValueError('Only a verified ready KVM template may be approved')
            app.store.execute('INSERT INTO managed_templates(id,name,guest_admin) VALUES(?,?,?) '
                              'ON CONFLICT(id) DO UPDATE SET guest_admin=excluded.guest_admin',
                              (value['id'], value['name'], int(options.guest_admin)))
            app.store.audit(identity['userid'], 'approve-template-guest-admin' if options.guest_admin else
                            'approve-template', value['id'])
        elif options.command == 'revoke':
            await app.revoke_agent(identity, options.identifier)
        elif options.command == 'repair-execution':
            from dirigentenstab.runtime import Runtime
            if not options.deployment_id:
                raise SystemExit('Specify --deployment-id from the verified recovery operation.')
            await Runtime.reconcile(app, identity, options.identifier, options.deployment_id)
        elif options.command == 'repair-provisioning':
            op = app.store.one("SELECT * FROM provisioning WHERE id=? AND phase<>'complete'", (options.identifier,))
            if not op or not op['parent_id']:
                raise SystemExit('Use setup.sh --install to resume bootstrap; no subordinate operation found.')
            await app.authorize(identity, op['parent_id'])
            await app.create_subgroup(op['parent_id'], op['name'])
        print('Administrative operation completed.')
    finally:
        await auth.revoke(token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['status', 'recover-deployments', 'resolve-rejection',
                                            'rotate', 'revoke', 'repair-provisioning', 'repair-execution',
                                            'recover-templates', 'approve-template', 'adopt-key',
                                            'migrate-key', 'migrate-keys'])
    parser.add_argument('identifier', nargs='?')
    parser.add_argument('--login-file')
    parser.add_argument('--deployment-id')
    parser.add_argument('--confirmed-rejection', action='store_true')
    parser.add_argument('--key-id', help='Exact CloudStack-native key pair UUID to adopt')
    parser.add_argument('--guest-admin', action='store_true', help='Approve sudo inside newly deployed guests of this template only')
    options = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root; this command reads the private application master key.')
    if options.command in {'rotate', 'migrate-key', 'revoke', 'repair-provisioning', 'repair-execution', 'resolve-rejection', 'approve-template', 'adopt-key'} and not options.identifier:
        parser.error('This command requires an identifier from status output.')
    if options.command == 'adopt-key' and not options.key_id:
        parser.error('adopt-key requires an explicit --key-id from CloudStack')
    login = None
    if options.command not in {'status', 'recover-deployments', 'recover-templates', 'resolve-rejection'}:
        if options.login_file:
            path = Path(options.login_file)
            if path.stat().st_mode & 0o077:
                parser.error('Login file must be mode 600 or stricter.')
            login = json.loads(path.read_text())
        else:
            login = {'username': input('CloudStack administrator username: '),
                     'password': getpass.getpass('CloudStack password: '), 'domain': input('Domain [/]: ') or '/'}
    asyncio.run(perform(options, service(), login))


if __name__ == '__main__':
    main()
