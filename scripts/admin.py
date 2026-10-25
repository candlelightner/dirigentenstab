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
                            max_hierarchy_depth=int(env.get('MAX_HIERARCHY_DEPTH', '10'))))


async def perform(options, app, login=None):
    if options.command == 'status':
        print(json.dumps({'provisioning': app.store.all('SELECT id,parent_id,name,phase,error FROM provisioning'),
                          'deployments': app.store.all('SELECT id,agent_id,name,vm_id,phase FROM vm_deployments'),
                          'rotations': app.store.all('SELECT agent_id,operation_id,phase FROM credential_rotations')}, indent=2))
        return
    if options.command == 'recover-deployments':
        await app.recover_deployments()
        print('Recovery queried CloudStack and bound discovered VMs; unresolved operations remain pending.')
        return
    if options.command == 'resolve-rejection':
        if not options.confirmed_rejection:
            raise SystemExit('Requires --confirmed-rejection after verifying a definitive server rejection in private logs.')
        op = app.store.one("SELECT * FROM vm_deployments WHERE id=? AND phase IN ('prepared','dispatched')",
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
        app.store.execute("UPDATE vm_deployments SET phase='failed' WHERE id=?", (op['id'],))
        app.store.audit('local-platform-admin', 'resolve-confirmed-deployment-rejection', op['id'])
        print('Confirmed rejected deployment marked failed. No VM was created or deleted.')
        return
    auth = Auth(app)
    token, _ = await auth.login(login['username'], login['password'], login.get('domain', '/'), 'local-admin')
    try:
        identity = await auth.identity(token)
        if options.command == 'rotate':
            await app.rotate_credentials(identity, options.identifier)
        elif options.command == 'revoke':
            await app.revoke_agent(identity, options.identifier)
        elif options.command == 'repair-provisioning':
            op = app.store.one("SELECT * FROM provisioning WHERE id=? AND phase<>'complete'", (options.identifier,))
            if not op or not op['parent_id']:
                raise SystemExit('Use setup.sh --install to resume bootstrap; no subordinate operation found.')
            await app.authorize(identity, op['parent_id'])
            app.store.execute('UPDATE provisioning SET credentials=NULL WHERE id=?', (op['id'],))
            await app.create_subgroup(op['parent_id'], op['name'])
        print('Administrative operation completed.')
    finally:
        await auth.revoke(token)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['status', 'recover-deployments', 'resolve-rejection',
                                            'rotate', 'revoke', 'repair-provisioning'])
    parser.add_argument('identifier', nargs='?')
    parser.add_argument('--login-file')
    parser.add_argument('--confirmed-rejection', action='store_true')
    options = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root; this command reads the private application master key.')
    if options.command in {'rotate', 'revoke', 'repair-provisioning', 'resolve-rejection'} and not options.identifier:
        parser.error('This command requires an identifier from status output.')
    login = None
    if options.command not in {'status', 'recover-deployments', 'resolve-rejection'}:
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
