#!/usr/bin/env python3
"""Opt-in real web/model/CloudStack lifecycle; resumes its receipt, never blindly redeploys."""

import argparse
import asyncio
import json
import os
import time
from pathlib import Path

from playwright.async_api import async_playwright

from admin import service


async def perform(options):
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=True)
    options.output.chmod(0o700)
    receipt_file = options.output / 'receipt.json'
    if receipt_file.exists() and not options.resume:
        raise ValueError('A lifecycle receipt exists. Use --resume; do not start another deployment.')
    app = service()
    main = app.store.one('SELECT a.* FROM agents a JOIN provisioning p ON p.id=a.id WHERE p.parent_id IS NULL')
    cloud = await app.cloud_client(main)
    actual = (await cloud.raw('listVirtualMachines', {'listall': True})).get('virtualmachine', [])
    state = json.loads(receipt_file.read_text()) if receipt_file.exists() else {
        'started': time.time(), 'baseline_vms': sorted(vm['id'] for vm in actual),
        'displayname': 'Dirigentenstab v0.1.4 lifecycle acceptance', 'agent_id': main['id'],
    }

    def save():
        temporary = receipt_file.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, indent=2))
        temporary.replace(receipt_file)

    save()
    login = json.loads(options.login_file.read_text())
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        page = await browser.new_page(viewport={'width': 1440, 'height': 900})
        try:
            await page.goto(options.url + '/login')
            await page.get_by_label('Username', exact=True).fill(login['username'])
            await page.get_by_label('Password', exact=True).fill(login['password'])
            await page.get_by_role('button', name='Sign in', exact=True).click()
            await page.wait_for_function('window.socket?.connected && window.did_handshake')
            await page.get_by_text('Main Agent', exact=True).last.wait_for()
            if not state.get('operation_id'):
                # A prior browser could have disconnected immediately after Send.
                previous = app.store.one(
                    'SELECT r.* FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id '
                    'WHERE r.created>=? AND c.title LIKE ? ORDER BY r.created LIMIT 1',
                    (state['started'], 'Disposable Ubuntu lifecycle acceptance%'))
                if previous:
                    state.update(operation_id=previous['id'], conversation_id=previous['conversation_id'])
                else:
                    assert {vm['id'] for vm in actual} == set(state['baseline_vms']), 'Inventory changed; reconcile before deployment'
                    prompt = ('Disposable Ubuntu lifecycle acceptance. Create exactly one new minimal CPU-only Ubuntu VM '
                              f'with displayname "{state["displayname"]}" in your own domain, using a managed template. '
                              'Use supported API names from your context and reuse discovery results. List-valued '
                              'parameters must be comma-separated strings. Backend-managed SSH and pinned host keys '
                              'are injected automatically; do not create SSH keypairs or user-data. Wait for SSH readiness '
                              'without reprovisioning. Use run_vm_command to write /tmp/dirigentenstab-v014.py containing '
                              'assert 6*7 == 42; print("DIRIGENTENSTAB_LIFECYCLE_OK=42"), run it with python3 and verify '
                              'exit code zero and that exact output. Verify the guest user is non-root. Then stop ONLY '
                              'this new disposable VM and report its ID and evidence. Do not modify any existing VM, '
                              'domain, account or host configuration. If a budget window ends, continue saved progress '
                              'rather than deploying again.')
                    await page.get_by_label('Message', exact=True).fill(prompt)
                    await page.get_by_role('button', name='Send', exact=True).click()
                    for _ in range(60):
                        previous = app.store.one('SELECT * FROM chat_runs WHERE agent_id=? AND created>=? ORDER BY created DESC',
                                                 (main['id'], state['started']))
                        if previous:
                            break
                        await asyncio.sleep(1)
                    assert previous, 'No execution started'
                    state.update(operation_id=previous['id'], conversation_id=previous['conversation_id'])
                save()
            conversation = app.store.one('SELECT title FROM conversations WHERE id=?', (state['conversation_id'],))
            if options.resume:
                await page.get_by_label('Conversation', exact=True).fill(conversation['title'])
                await page.get_by_role('option', name=conversation['title'], exact=True).first.click()
            continuations = 0
            deadline = time.monotonic() + 2000
            while time.monotonic() < deadline:
                run = app.store.one('SELECT * FROM chat_runs WHERE id=?', (state['operation_id'],))
                checkpoint = app.store.open(run['checkpoint']) if run['checkpoint'] else {}
                if run['status'] == 'completed':
                    break
                if run['status'] == 'interrupted' and checkpoint.get('resumable'):
                    assert continuations < 3, 'Acceptance continuation bound reached; inspect saved progress'
                    await page.get_by_role('button', name='Continue saved task', exact=True).click()
                    continuations += 1
                    await asyncio.sleep(2)
                elif run['status'] != 'running':
                    raise AssertionError({k: run[k] for k in ('id', 'status', 'category', 'tool')})
                await asyncio.sleep(1)
            else:
                raise AssertionError('Lifecycle timed out; receipt and durable operations retained')
            events = app.store.open(run['events'])
            assert any(e['type'] == 'tool_call' and e.get('target') == 'deployVirtualMachine' for e in events)
            results = [e['content'] for e in events if e['type'] == 'tool_result' and e['name'] == 'run_vm_command']
            assert any(isinstance(r, dict) and r.get('exit_code') == 0 and
                       'DIRIGENTENSTAB_LIFECYCLE_OK=42' in r.get('stdout', '') for r in results), 'No verified Python/SSH output'
            deployments = app.store.all('SELECT * FROM vm_deployments WHERE agent_id=? AND updated>=?',
                                         (main['id'], state['started']))
            successful = [d for d in deployments if d['phase'] in {'complete', 'destroyed'}]
            assert len(successful) == 1, 'Expected exactly one tracked deployment'
            deployment = successful[0]
            assert deployment['vm_id'] not in state['baseline_vms']
            stored = app.store.open(deployment['params'])
            assert stored['request']['displayname'] == state['displayname']
            vms = (await cloud.raw('listVirtualMachines', {'listall': True})).get('virtualmachine', [])
            vm = next((v for v in vms if v['id'] == deployment['vm_id']), None)
            assert vm and vm['state'] == 'Stopped', 'The agent did not stop its disposable VM'
            assert {v['id'] for v in vms} == set(state['baseline_vms']) | {vm['id']}
            state.update(vm_id=vm['id'], deployment_id=deployment['id'], python_verified=True,
                         stopped=True, budget={
                             k: checkpoint.get(k) for k in ('requests', 'tool_calls', 'windows', 'cache_hits')})
            save()
            await page.screenshot(path=str(options.output / 'lifecycle-desktop.png'), full_page=True)
            await page.reload()
            await page.wait_for_function('window.socket?.connected && window.did_handshake')
            await page.get_by_label('Conversation', exact=True).fill(conversation['title'])
            await page.get_by_role('option', name=conversation['title'], exact=True).first.click()
            await page.get_by_text('Completed · Reference: ' + run['id'], exact=True).wait_for()
            await page.set_viewport_size({'width': 390, 'height': 844})
            await page.wait_for_timeout(400)
            await page.screenshot(path=str(options.output / 'lifecycle-mobile.png'), full_page=True)
            await page.get_by_role('button', name='Sign out', exact=True).click()
        except BaseException:
            await page.screenshot(path=str(options.output / 'failure.png'), full_page=True)
            raise
        finally:
            await browser.close()
    if options.cleanup:
        assert not state.get('cleanup_dispatched'), 'Inspect the previous cleanup outcome before repeating it'
        state['cleanup_dispatched'] = True
        save()
        # Expunge remains an operator-only permission; never widen an agent's runtime key for this test.
        credentials = json.loads(await asyncio.to_thread(
            Path('/var/lib/dirigentenstab/setup/cloudstack-admin.json').read_text))
        operator = app.client({key: credentials[key] for key in ('apikey', 'secretkey')})
        await operator.execute('destroyVirtualMachine', {'id': state['vm_id'], 'expunge': True})
        remaining = (await cloud.raw('listVirtualMachines', {'listall': True})).get('virtualmachine', [])
        assert {vm['id'] for vm in remaining} == set(state['baseline_vms'])
        app.store.execute("UPDATE vm_deployments SET phase='destroyed' WHERE id=? AND vm_id=?",
                           (state['deployment_id'], state['vm_id']))
        state['test_vm_removed'] = True
    state['passed'] = True
    save()
    print(json.dumps({k: v for k, v in state.items() if k != 'baseline_vms'}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--cleanup', action='store_true', help='Expunge only the verified disposable test VM')
    parser.add_argument('--url', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--login-file', type=Path, default=Path('/var/lib/dirigentenstab/setup/initial-admin.json'))
    args = parser.parse_args()
    if not args.run or os.geteuid() != 0 or args.login_file.stat().st_mode & 0o077:
        parser.error('Run as root with --run and a mode-600 human login file')
    asyncio.run(perform(args))


if __name__ == '__main__':
    main()
