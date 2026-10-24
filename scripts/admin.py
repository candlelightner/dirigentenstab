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
                   Settings(env['CLOUDSTACK_URL'], env['PUBLIC_ORIGIN'], cmk='/usr/local/bin/cmk'))


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
    parser.add_argument('command', choices=['status', 'recover-deployments', 'rotate', 'revoke', 'repair-provisioning'])
    parser.add_argument('identifier', nargs='?')
    parser.add_argument('--login-file')
    options = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root; this command reads the private application master key.')
    if options.command in {'rotate', 'revoke', 'repair-provisioning'} and not options.identifier:
        parser.error('This command requires an identifier from status output.')
    login = None
    if options.command not in {'status', 'recover-deployments'}:
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
