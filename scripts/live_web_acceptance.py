#!/usr/bin/env python3
"""Opt-in real web/DeepSeek/CloudStack subgroup acceptance. Never used by CI fixtures."""

import argparse
import asyncio
import json
import os
import re
from pathlib import Path

from playwright.async_api import async_playwright

from admin import service
from dirigentenstab.cloud import CloudError, runtime_api


async def perform(options):
    os.umask(0o077)
    options.output.mkdir(parents=True, exist_ok=True)
    options.output.chmod(0o700)
    login = json.loads(options.login_file.read_text())
    app = service()
    main = app.store.one('SELECT a.* FROM agents a JOIN provisioning p ON p.id=a.id WHERE p.parent_id IS NULL')
    cloud = await app.cloud_client(main)
    domains_before = (await cloud.raw('listDomains', {'listall': True})).get('domain', [])
    vms_before = {v['id'] for v in (await cloud.raw('listVirtualMachines', {'listall': True})).get('virtualmachine', [])}
    operation = app.store.one('SELECT * FROM provisioning WHERE parent_id=? AND name=?', (main['id'], 'Sandbox'))
    existing = [d for d in domains_before if d.get('parentdomainid') == main['domain_id'] and
                (d['name'] == 'Sandbox' or d['name'].startswith('Sandbox--ds-'))]
    if existing and not operation:
        raise RuntimeError('Sandbox exists without a durable provisioning operation; administrator reconciliation required')
    provider = app.store.one('SELECT name,protocol FROM providers WHERE id=?', (main['provider_id'],))
    receipt = {'provider': provider, 'model': main['model'], 'main_agent': main['id'],
               'domains_before': len(domains_before), 'vms_before': len(vms_before)}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        context = await browser.new_context(viewport={'width': 1440, 'height': 900})
        page = await context.new_page()
        page.set_default_timeout(30000)
        await page.goto(options.url + '/login')
        await page.get_by_label('Username', exact=True).fill(login['username'])
        await page.get_by_label('Password', exact=True).fill(login['password'])
        await page.get_by_label('CloudStack domain', exact=True).fill(login.get('domain', '/'))
        await page.get_by_role('button', name='Sign in', exact=True).click()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_text('Main Agent', exact=True).last.wait_for()
        await page.get_by_text('Model: ' + provider['name'] + ' / ' + main['model'], exact=True).wait_for()

        async def send(prompt):
            previous = app.store.one('SELECT id FROM chat_runs ORDER BY created DESC LIMIT 1')
            await page.get_by_label('Message', exact=True).fill(prompt)
            await page.get_by_role('button', name='Send', exact=True).click()
            await page.get_by_role('button', name='Send', exact=True).wait_for(state='visible')
            # Wait for the durable run and UI completion; streamed text is not a completion signal.
            for _ in range(400):
                run = app.store.one('SELECT * FROM chat_runs ORDER BY created DESC LIMIT 1')
                if run and (not previous or run['id'] != previous['id']) and run['status'] != 'running':
                    break
                await asyncio.sleep(1)
            else:
                raise AssertionError('Real application run did not finish within its timeout')
            assert run['status'] == 'completed', {k: run[k] for k in ('id', 'status', 'category', 'tool')}
            await page.get_by_text('Completed', exact=True).wait_for()
            return run, app.store.open(run['events'])

        if options.resume:
            assert operation and operation['phase'] == 'complete', 'No completed Sandbox operation to resume'
            subgroup = next((r for r in app.store.all(
                "SELECT * FROM chat_runs WHERE agent_id=? AND status='completed' ORDER BY created DESC", (main['id'],))
                if any(e['type'] == 'tool_call' and e['name'] == 'create_subgroup' and
                       isinstance(e['content'], dict) and e['content'].get('name') == 'Sandbox'
                       for e in app.store.open(r['events']))), None)
            assert subgroup, 'No completed real web execution for Sandbox'
            inventory = app.store.one(
                "SELECT * FROM chat_runs WHERE conversation_id=? AND created<? AND status='completed' ORDER BY created DESC",
                (subgroup['conversation_id'], subgroup['created']))
            assert inventory, 'No preceding inventory in that conversation'
            events = app.store.open(subgroup['events'])
            title = app.store.one('SELECT title FROM conversations WHERE id=?', (subgroup['conversation_id'],))['title']
            await page.get_by_label('Conversation', exact=True).fill(title)
            await page.get_by_role('option', name=title, exact=True).click()
            await page.get_by_text('Completed · Reference: ' + subgroup['id'], exact=True).wait_for()
            original_events = app.store.open(inventory['events'])
            original_counts = {target: next((int(e['summary'].split()[0]) for e in reversed(original_events)
                               if e['type'] == 'tool_result' and e.get('target') == target and
                               re.fullmatch(r'\d+ results', e.get('summary', ''))), None)
                               for target in ('listDomains', 'listVirtualMachines')}
            receipt.update(inventory_run=inventory['id'], resumed_completed_operation=True,
                           original_inventory_counts=original_counts)
        else:
            inventory, inventory_events = await send('List all CloudStack domains and available VMs. Use actual CloudStack APIs. '
                                                     'This is read-only; do not create or modify any resources.')
            assert any(e['type'] == 'tool_call' and e['name'] == 'execute_api' for e in inventory_events)
            receipt['inventory_run'] = inventory['id']
            subgroup, events = await send(
                'Create a new subgroup named Sandbox under your own domain, provision its administrative agent, '
                'and verify that the new agent can list its own CloudStack domain but cannot access or administer '
                'unrelated domains. Do not create any VMs. Use create_subgroup with the exact name Sandbox, '
                'resuming that same operation if it exists. Then use delegate to ask the new agent to listDomains '
                'with its own credentials. Never attempt any other resource creation or modification.')
        assert subgroup['conversation_id'] == inventory['conversation_id'], 'Second-turn regression was not exercised'
        assert any(e['type'] == 'tool_call' and e['name'] == 'create_subgroup' for e in events)
        operation = app.store.one('SELECT * FROM provisioning WHERE parent_id=? AND name=?', (main['id'], 'Sandbox'))
        assert operation and operation['phase'] == 'complete'
        child = await app.agent(operation['id'])
        assert child['provider_id'] == main['provider_id'] and child['model'] == main['model']
        child_cloud = await app.cloud_client(child)
        own = (await child_cloud.raw('listDomains', {'listall': True})).get('domain', [])
        assert {d['id'] for d in own} == {child['domain_id']}
        unrelated = next(d for d in domains_before if d['id'] != main['domain_id'])
        try:
            denied = (await child_cloud.raw('listDomains', {'id': unrelated['id'], 'listall': True})).get('domain', [])
            assert not any(d['id'] == unrelated['id'] for d in denied)
        except CloudError as exc:
            assert re.search(r'CloudStack (?:HTTP|error) (?:401|403|531):', str(exc)), 'Unexpected CloudStack failure'
        receipt['unrelated_read_denied'] = True
        parent_cloud = await app.cloud_client(main, 'provisioning')
        accounts = (await parent_cloud.raw('listAccounts', {'id': child['account_id'], 'listall': True})).get('account', [])
        assert len(accounts) == 1 and accounts[0]['accounttype'] == 2 and accounts[0]['domainid'] == child['domain_id']
        keys = (await parent_cloud.raw('listUserKeys', {'userid': child['user_id']})).get('userapikey', [])
        assert len([k for k in keys if k['name'].startswith('ds-' + child['id'] + '-')]) == 2
        runtime_key = app.store.open(child['runtime'])
        rules = (await parent_cloud.raw('listUserKeyRules', {'keypairid': runtime_key['id']})).get('keypermission', [])
        allowed = {rule['rule'] for rule in rules if rule['permission'] == 'allow'}
        assert allowed and allowed == set(await child_cloud.catalogue())
        assert all(runtime_api(name) for name in allowed)
        assert all(rule['permission'] == 'allow' for rule in rules)
        assert not {'registerUserKeys', 'listUserKeys', 'deleteUserKeys'} & allowed
        receipt.update(unrelated_admin_denied=True, runtime_key_rules=len(rules),
                       isolation_evidence='CloudStack domain-access rejection plus authoritative restricted key rules')
        await page.get_by_label('Chat directly with an agent', exact=True).fill('Sandbox')
        await page.get_by_role('option', name='Sandbox', exact=True).click()
        await page.get_by_text('Sandbox', exact=True).last.wait_for()
        direct = app.store.one(
            "SELECT * FROM chat_runs WHERE agent_id=? AND status='completed' ORDER BY created DESC LIMIT 1",
            (child['id'],)) if options.resume else None
        if direct:
            direct_events = app.store.open(direct['events'])
            title = app.store.one('SELECT title FROM conversations WHERE id=?', (direct['conversation_id'],))['title']
            await page.get_by_label('Conversation', exact=True).fill(title)
            await page.get_by_role('option', name=title, exact=True).click()
            await page.get_by_text('Completed · Reference: ' + direct['id'], exact=True).wait_for()
        else:
            direct, direct_events = await send('Use execute_api to list your own CloudStack domain. '
                                              'Discover and describe listDomains first if needed. This is read-only; do not create VMs.')
        assert direct['agent_id'] == child['id']
        assert any(e['type'] == 'tool_call' and e['name'] == 'execute_api' for e in direct_events)
        await page.screenshot(path=str(options.output / 'live-desktop.png'), full_page=True)
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_label('Chat directly with an agent', exact=True).fill('Sandbox')
        await page.get_by_role('option', name='Sandbox', exact=True).click()
        await page.get_by_text('Sandbox', exact=True).last.wait_for()
        conversation = app.store.one('SELECT title FROM conversations WHERE id=?', (direct['conversation_id'],))
        await page.get_by_label('Conversation', exact=True).fill(conversation['title'])
        await page.get_by_role('option', name=conversation['title'], exact=True).click()
        await page.get_by_text('Completed · Reference: ' + direct['id'], exact=True).wait_for()
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.wait_for_timeout(500)
        for selected in ('Main Agent', 'Sandbox'):
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
            await page.get_by_label('Search agents and domains', exact=True).fill(selected)
            await page.wait_for_timeout(350)
            await page.locator('.q-tree').get_by_text(selected, exact=True).click()
            await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
        await page.get_by_label('Conversation', exact=True).fill(conversation['title'])
        await page.get_by_role('option', name=conversation['title'], exact=True).click()
        await page.get_by_text('Completed · Reference: ' + direct['id'], exact=True).wait_for()
        composer = await page.get_by_label('Message', exact=True).bounding_box()
        assert composer and composer['x'] < 60 and composer['y'] + composer['height'] <= 844
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await page.screenshot(path=str(options.output / 'live-mobile.png'), full_page=True)
        await page.get_by_role('button', name='Sign out', exact=True).click()
        await browser.close()
    domains_after = (await cloud.raw('listDomains', {'listall': True})).get('domain', [])
    matches = [d for d in domains_after if d.get('parentdomainid') == main['domain_id'] and
               d['name'] == 'Sandbox--ds-' + child['id'][:20]]
    assert len(matches) == 1 and matches[0]['id'] == child['domain_id']
    assert {v['id'] for v in (await cloud.raw('listVirtualMachines', {'listall': True})).get('virtualmachine', [])} == vms_before
    receipt.update(subgroup_run=subgroup['id'], direct_chat_run=direct['id'], subgroup_agent=child['id'],
                   subgroup_domain=child['domain_id'], domains_after=len(domains_after), passed=True)
    (options.output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--resume', action='store_true', help='Reuse a verified completed real Sandbox web execution')
    parser.add_argument('--login-file', type=Path, default=Path('/var/lib/dirigentenstab/setup/initial-admin.json'))
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    if options.login_file.stat().st_mode & 0o077:
        parser.error('Login file must be private (mode 600 or stricter)')
    asyncio.run(perform(options))


if __name__ == '__main__':
    main()
