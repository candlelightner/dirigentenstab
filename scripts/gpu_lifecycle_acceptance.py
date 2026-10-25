#!/usr/bin/env python3
"""Explicit real web-UI 3x8Q -> 1x24Q allocation test; no driver installation/workload."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import time
import uuid

from admin import service
from dirigentenstab.limits import APP_ROOT_AGENT
from dirigentenstab.settings import endpoint

STATE = Path('/var/lib/dirigentenstab/setup/gpu-lifecycle-acceptance.json')


def save(state):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(STATE)


def evidence(events, prefix, offering8, offering24):
    three, full = [], []
    for event in events:
        if event.get('type') != 'tool_result' or event.get('target') != 'listVirtualMachines' or event.get('failed'):
            continue
        content = event.get('content', {})
        if not isinstance(content, dict):
            continue
        values = [v for v in content.get('virtualmachine', []) if v.get('displayname', '').startswith(prefix)]
        running = [v for v in values if v.get('state') == 'Running' and v.get('gpucount') == 1]
        eight = [v['id'] for v in running if v.get('serviceofferingid') == offering8]
        twenty_four = [v['id'] for v in running if v.get('serviceofferingid') == offering24]
        if len(set(eight)) == 3:
            three = eight
        if three and len(set(twenty_four)) == 1:
            full = twenty_four
    if len(set(three + full)) != 4:
        raise AssertionError('Missing actual native evidence of three concurrent 8Q VMs followed by one distinct 24Q VM')
    return three + full


async def cleanup(cloud, state, *, domain_id, account):
    identifiers = state['vm_ids']
    if len(set(identifiers)) != 4 or set(identifiers) & set(state['baseline']):
        raise AssertionError('Cleanup requires exactly four verified non-baseline test VMs')
    state['phase'] = 'cleanup'
    save(state)
    for identifier in identifiers:
        values = (await cloud.raw('listVirtualMachines', {'id': identifier, 'listall': True})).get('virtualmachine', [])
        if not values:
            continue
        if any(v['id'] != identifier or v['state'] != 'Stopped' or
               v['serviceofferingid'] != state['config']['cpu_offering'] or v.get('domainid') != domain_id or
               v.get('account') != account or not v.get('displayname', '').startswith(state['prefix']) for v in values):
            raise AssertionError('Cleanup refused a VM that is no longer a stopped CPU-only test VM')
        await cloud.execute('destroyVirtualMachine', {'id': identifier, 'expunge': True})
    remaining = (await cloud.raw('listVirtualMachines', {'listall': True, 'domainid': domain_id,
                                                        'isrecursive': True})).get('virtualmachine', [])
    if sorted(v['id'] for v in remaining) != state['baseline']:
        raise AssertionError('Inventory differs from the original baseline; inspect without further deletion')
    state['phase'] = 'cleaned'
    save(state)


async def platform_cleanup(app, state):
    # Expunge stays an explicit root-operator action; never widen the agent's runtime role for cleanup.
    path = Path('/var/lib/dirigentenstab/setup/cloudstack-admin.json')
    if (await asyncio.to_thread(path.stat)).st_mode & 0o077:
        raise PermissionError('Platform maintenance credentials must be root-private')
    credentials = json.loads(await asyncio.to_thread(path.read_text))
    cloud = app.client({key: credentials[key] for key in ('apikey', 'secretkey')})
    owner = await app.agent(APP_ROOT_AGENT)
    accounts = (await cloud.raw('listAccounts', {'id': owner['account_id'], 'listall': True})).get('account', [])
    account = next((a for a in accounts if a['id'] == owner['account_id'] and a['domainid'] == owner['domain_id']), None)
    if not account:
        raise PermissionError('Cannot verify the test VMs’ exact native owner')
    await cleanup(cloud, state, domain_id=owner['domain_id'], account=account['name'])


async def acceptance(options):
    from playwright.async_api import async_playwright
    app = service()
    if await asyncio.to_thread(STATE.exists):
        state = json.loads(await asyncio.to_thread(STATE.read_text))
        if state.get('phase') == 'cleaned':
            print('Previously completed acceptance and cleanup retained; no task was repeated.')
            return
    else:
        config = json.loads(await asyncio.to_thread(Path(options.config).read_text))
        if set(config) != {'origin', 'zone_id', 'template_id', 'offering8', 'offering24', 'cpu_offering'}:
            raise ValueError('Supply only the documented native resource IDs and HTTPS origin')
        if not endpoint(config['origin']).startswith('https://'):
            raise ValueError('The real browser origin must use HTTPS')
        cloud = await app.cloud_client(await app.agent(APP_ROOT_AGENT))
        baseline = (await cloud.raw('listVirtualMachines', {'listall': True})).get('virtualmachine', [])
        state = {'config': config, 'started': time.time(), 'prefix': 'GPU lifecycle '+uuid.uuid4().hex[:12],
                 'baseline': sorted(v['id'] for v in baseline), 'phase': 'prepared'}
        save(state)
    config = state['config']
    cloud = await app.cloud_client(await app.agent(APP_ROOT_AGENT))
    if state['phase'] in {'passed', 'cleanup'}:
        if options.cleanup:
            await platform_cleanup(app, state)
        print(json.dumps({k: state[k] for k in ('phase', 'operation_id', 'vm_ids')}))
        return
    # A submitted task is found by its unique title, never silently submitted again after interruption.
    runs = app.store.all('SELECT r.* FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id '
                         'WHERE c.agent_id=? AND c.title LIKE ? AND c.created>=? ORDER BY r.created',
                         (APP_ROOT_AGENT, state['prefix']+'%', state['started']))
    if state.get('operation_id'):
        runs = app.store.all('SELECT * FROM chat_runs WHERE id=? AND agent_id=?',
                             (state['operation_id'], APP_ROOT_AGENT))
    if len(runs) > 1:
        raise RuntimeError('Ambiguous acceptance conversation; inspect its durable operations')
    if not runs and state['phase'] != 'prepared':
        raise RuntimeError('Submission outcome requires administrator review; no task was repeated')
    login_file = Path(options.credentials_file)
    if (await asyncio.to_thread(login_file.stat)).st_mode & 0o077:
        raise PermissionError('Human login file must be root-private')
    login = json.loads(await asyncio.to_thread(login_file.read_text))
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={'width': 1440, 'height': 900})
        try:
            await page.goto(config['origin'].rstrip('/')+'/login')
            await page.get_by_label('Username', exact=True).fill(login['username'])
            await page.get_by_label('Password', exact=True).fill(login['password'])
            await page.get_by_role('button', name='Sign in', exact=True).click()
            await page.wait_for_function('window.socket?.connected && window.did_handshake')
            if runs:
                title = app.store.one('SELECT title FROM conversations WHERE id=?', (runs[0]['conversation_id'],))['title']
                await page.get_by_label('Conversation', exact=True).fill(title)
                await page.get_by_role('option', name=title, exact=True).click()
            else:
                prompt = (state['prefix']+'. Allocation test only; no driver installation, GPU workload or template creation. '
                    'Do not modify pre-existing VMs. Create exactly three new disposable VMs with displaynames beginning '
                    f"'{state['prefix']}-8Q-', zoneid={config['zone_id']}, templateid={config['template_id']}, "
                    f"serviceofferingid={config['offering8']}, startvm=true. Verify all THREE Running together with "
                    'listVirtualMachines ids as a comma-separated string. Then stop only those three, change EACH '
                    f"to CPU offering {config['cpu_offering']} using changeServiceForVirtualMachine shrinkok=true, "
                    'and verify GPU resource count released. Then create exactly ONE further VM, displayname '
                    f"'{state['prefix']}-24Q', same zone/template, serviceofferingid={config['offering24']}, startvm=true. "
                    'Verify it Running using listVirtualMachines, then stop it and change it to the CPU offering. '
                    'Finish with those four VMs Stopped on CPU offerings. Reuse IDs and completed results, avoid '
                    'discovery loops, never replace an uncertain dispatch. Backend performs only policy-authorized '
                    'owned-pool transitions. Report references on failure.')
                state['phase'] = 'submitted'
                save(state)
                await page.get_by_label('Message', exact=True).fill(prompt)
                await page.get_by_role('button', name='Send', exact=True).click()
                for _ in range(60):
                    runs = app.store.all('SELECT r.* FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id '
                        'WHERE c.agent_id=? AND c.title LIKE ? AND c.created>=?',
                        (APP_ROOT_AGENT, state['prefix']+'%', state['started']))
                    if runs:
                        break
                    await asyncio.sleep(1)
                if len(runs) != 1:
                    raise RuntimeError('No unique execution reference; inspect before any further submission')
            state['operation_id'] = runs[0]['id']
            save(state)
            async with asyncio.timeout(3600):
                while True:
                    run = app.store.one('SELECT * FROM chat_runs WHERE id=?', (state['operation_id'],))
                    checkpoint = app.store.open(run['checkpoint']) if run['checkpoint'] else {}
                    if run['status'] == 'interrupted' and checkpoint.get('resumable'):
                        await page.get_by_role('button', name='Continue saved task', exact=True).click()
                        await asyncio.sleep(2)
                    elif run['status'] != 'running':
                        break
                    await asyncio.sleep(1)
            state['status'] = run['status']
            save(state)
            await page.locator('.q-message').first.wait_for(timeout=60000)
            if run['status'] == 'completed':
                await page.get_by_text('Completed', exact=True).wait_for(timeout=60000)
            for width, height, name in [(1440, 900, 'desktop'), (390, 844, 'mobile')]:
                await page.set_viewport_size({'width': width, 'height': height})
                if width == 390:
                    await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
                await page.screenshot(path=str(STATE.with_suffix('.'+name+'.png')), full_page=True)
            if run['status'] != 'completed':
                raise RuntimeError('Acceptance incomplete; reopen original conversation, operation '+run['id'])
            identifiers = evidence(app.store.open(run['events']), state['prefix'], config['offering8'], config['offering24'])
            values = (await cloud.raw('listVirtualMachines', {'ids': ','.join(identifiers), 'listall': True})).get('virtualmachine', [])
            if len(values) != 4 or any(v['state'] != 'Stopped' or v['serviceofferingid'] != config['cpu_offering'] for v in values):
                raise AssertionError('The four test VMs were not stopped and released to CPU offerings')
            state.update(phase='passed', vm_ids=identifiers)
            save(state)
        finally:
            await browser.close()
    if options.cleanup and state.get('phase') == 'passed':
        await platform_cleanup(app, state)
    print(json.dumps({k: state[k] for k in ('phase', 'operation_id', 'vm_ids')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--config', default='/var/lib/dirigentenstab/setup/gpu-lifecycle-test.json')
    parser.add_argument('--credentials-file', default='/var/lib/dirigentenstab/setup/initial-admin.json')
    parser.add_argument('--cleanup', action='store_true', help='Expunge only the four verified disposable CPU test VMs')
    options = parser.parse_args()
    if not options.run or os.geteuid() != 0:
        parser.error('Explicit root --run required; policies and offerings must already be approved by a human')
    os.umask(0o077)
    asyncio.run(acceptance(options))
