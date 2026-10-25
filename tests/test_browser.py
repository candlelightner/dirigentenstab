"""Real Chromium + NiceGUI browser tests; infrastructure/model providers are CI fixtures."""

import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

playwright = pytest.importorskip('playwright.async_api', reason='Browser job installs Playwright separately')
pytestmark = pytest.mark.browser


@pytest.fixture
def browser_app(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    project = Path(__file__).resolve().parent.parent
    log = (tmp_path / 'browser-server.log').open('w')
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('PYTEST_', 'NICEGUI_'))}
    process = subprocess.Popen(
        [sys.executable, str(project / 'scripts/browser_fixture.py'), '--state-dir', str(tmp_path), '--port', str(port)],
        cwd=project, env={**environment, 'DIRIGENTENSTAB_BROWSER_FIXTURE': '1',
                          'PYTHONPATH': str(project)}, stdout=log, stderr=subprocess.STDOUT,
    )
    url = f'https://localhost:{port}'
    try:
        for _ in range(120):
            if process.poll() is not None:
                pytest.fail('Browser fixture failed to start:\n' + (tmp_path / 'browser-server.log').read_text())
            try:
                with urllib.request.urlopen(url + '/healthz', context=ssl._create_unverified_context(), timeout=1):
                    break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            pytest.fail('Browser fixture did not become ready')
        yield url, tmp_path
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


async def login(page, url):
    await page.goto(url + '/login')
    await page.get_by_label('Username', exact=True).fill('alice')
    await page.get_by_label('Password', exact=True).fill('browser-fixture-password')
    await page.get_by_role('button', name='Sign in', exact=True).click()
    await page.get_by_text('Main Agent', exact=True).last.wait_for()
    await page.wait_for_function('window.socket?.connected && window.did_handshake')


async def test_browser_secure_login_direct_chat_history_provider_and_logout(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        page = await context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('console', lambda message: errors.append(message.text)
                if message.type == 'error' and 'Error while converting' in message.text else None)
        await login(page, url)
        cookie = next(cookie for cookie in await context.cookies() if cookie['name'] == 'ds_session')
        assert cookie['httpOnly'] and cookie['secure'] and cookie['sameSite'] == 'Strict'
        await page.get_by_label('Chat directly with an agent', exact=True).fill('Research')
        await page.get_by_role('option', name='Research Admin', exact=True).click()
        await page.get_by_text('Research Admin', exact=True).last.wait_for()
        await page.get_by_label('Message', exact=True).fill('Inspect the research VM')
        await page.get_by_role('button', name='Send', exact=True).click()
        output = 'Infrastructure checked. The research VM is running.'
        await page.get_by_text(output, exact=True).wait_for()
        await page.get_by_text('execute_api · Completed', exact=False).first.click()
        assert await page.get_by_text('execute_api', exact=False).count() >= 1
        from scripts.browser_fixture import PRIVATE_VALUES
        content = await page.content()
        assert all(secret not in content for secret in PRIVATE_VALUES)
        await page.get_by_role('button', name='New conversation', exact=True).click()
        await page.get_by_text(output, exact=True).wait_for(state='detached')
        await page.get_by_label('Conversation', exact=True).fill('Inspect the research VM')
        await page.get_by_role('option', name='Inspect the research VM', exact=True).click()
        await page.get_by_text(output, exact=True).wait_for()
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_role('button', name='Model providers', exact=True).click()
        await page.get_by_label('Base URL (including /v1)', exact=True).wait_for()
        await page.get_by_role('button', name='Close', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await page.evaluate('window.scrollTo(0, 0)')
        await page.screenshot(path=str(state / 'desktop.png'), full_page=True)
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.evaluate('window.scrollTo(0, 0)')
        assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        await page.screenshot(path=str(state / 'mobile.png'), full_page=True)
        assert not errors
        await page.get_by_role('button', name='Sign out', exact=True).click()
        await page.get_by_role('button', name='Sign in', exact=True).wait_for()
        assert not any(cookie['name'] == 'ds_session' for cookie in await context.cookies())
        await browser.close()


async def test_browser_disabled_cloudstack_human_loses_existing_socket_access(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await login(page, url)
        (state / 'human-disabled').touch()
        await page.get_by_role('button', name='New conversation', exact=True).click()
        await page.get_by_role('button', name='Sign in', exact=True).wait_for()
        response = await context.request.get(url + '/')
        assert response.url.endswith('/login')
        await browser.close()


@pytest.mark.parametrize('engine', ['chromium', 'firefox'])
async def test_mobile_deep_agent_switch_markdown_keyboard_and_models(browser_app, engine):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await getattr(p, engine).launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': 390, 'height': 844},
                                            is_mobile=engine == 'chromium', has_touch=True)
        page = await context.new_page()
        await login(page, url)
        message = page.get_by_label('Message', exact=True)
        assert await message.is_visible()
        assert await page.get_by_role('button', name='Send', exact=True).is_disabled()
        assert (await message.bounding_box())['x'] < 60
        for name in ('Team 11 Level 3', 'Team 2 Level 3'):
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
            search = page.get_by_label('Search agents and domains', exact=True)
            await search.fill(name)
            await page.wait_for_timeout(350)  # Quasar's branch expansion transition.
            try:
                await page.locator('.q-tree').get_by_text(name, exact=True).click(timeout=10000)
            except Exception:
                await page.screenshot(path=str(state / 'selection-failure.png'), full_page=True)
                raise
            await search.wait_for(state='hidden')
            await page.get_by_text(name, exact=True).last.wait_for()
            assert (await message.bounding_box())['x'] < 60
            assert await page.evaluate('window.scrollY === 0')
        await page.get_by_role('button', name='Configure', exact=True).click()
        model = page.get_by_label('Model ID', exact=True)
        await page.get_by_text('2 models available.', exact=False).wait_for()
        await model.fill('custom-private-model')
        await model.press('Enter')
        provider = page.get_by_label('Model provider', exact=True)
        for name, expected in [('Unsupported', 'custom Model ID'), ('Empty', 'No models discovered'),
                               ('Unauthorized', 'rejected authentication'), ('Local fixture', '2 models available')]:
            await provider.click()
            await page.get_by_role('option', name=name, exact=True).click()
            await page.get_by_text(expected, exact=False).last.wait_for()
            assert await model.input_value() == 'custom-private-model'
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await page.get_by_text('custom-private-model', exact=False).last.wait_for()
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_label('Chat directly with an agent', exact=True).fill('Team 2 Level 3')
        await page.get_by_role('option', name='Team 2 Level 3', exact=True).click()
        await page.get_by_text('Model: Local fixture / custom-private-model', exact=True).wait_for()
        await page.get_by_role('button', name='Configure', exact=True).click()
        await page.get_by_label('Model ID', exact=True).wait_for()
        assert await page.get_by_label('Model ID', exact=True).input_value() == 'custom-private-model'
        await page.get_by_role('button', name='Cancel', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await message.fill('markdown stress')
        try:
            await page.get_by_role('button', name='Send', exact=True).click()
        except Exception:
            await page.screenshot(path=str(state / 'submission-failure.png'), full_page=True)
            print('Textarea at failed submission:', await message.input_value())
            raise
        await page.get_by_role('heading', name='Infrastructure report', exact=True).wait_for()
        await page.get_by_text('Completed', exact=True).wait_for()
        assert await page.locator('.markdown table').count() == 1
        assert await page.locator('.markdown pre code').count() == 1
        assert not await page.evaluate('window.injected === true')
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await page.screenshot(path=str(state / 'mobile-chat.png'), full_page=True)
        await message.focus()
        # Android Chrome can shrink only visualViewport, and can move focus during keyboard animation.
        await page.evaluate('''() => {
            Object.defineProperty(visualViewport,'height',{configurable:true,get:()=>480});
            visualViewport.dispatchEvent(new Event('resize'));
            document.activeElement.blur();
        }''')
        await page.locator('.agent-details').wait_for(state='hidden')
        assert await page.evaluate('innerHeight') == 844
        box = await message.bounding_box()
        assert box and box['y'] + box['height'] <= 480
        await page.screenshot(path=str(state / 'mobile-visual-keyboard.png'), full_page=True)
        await page.evaluate("delete visualViewport.height;visualViewport.dispatchEvent(new Event('resize'))")
        await page.locator('.agent-details').wait_for()
        await page.get_by_role('button', name='Configure', exact=True).click()
        await page.get_by_label('Model ID', exact=True).wait_for()
        await page.evaluate('''() => {
            Object.defineProperty(visualViewport,'height',{configurable:true,get:()=>480});
            visualViewport.dispatchEvent(new Event('resize'));
        }''')
        cancel = page.get_by_role('button', name='Cancel', exact=True)
        await cancel.scroll_into_view_if_needed()
        dialog = await page.locator('.q-dialog__inner > .q-card').bounding_box()
        cancel_box = await cancel.bounding_box()
        await page.screenshot(path=str(state / 'mobile-config-keyboard.png'), full_page=True)
        assert dialog and dialog['y'] >= 0 and dialog['y'] + dialog['height'] <= 480
        assert cancel_box and cancel_box['y'] + cancel_box['height'] <= 480
        await cancel.click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await page.evaluate("delete visualViewport.height;visualViewport.dispatchEvent(new Event('resize'))")
        await message.focus()
        await page.set_viewport_size({'width': 390, 'height': 480})
        await page.locator('.agent-details').wait_for(state='hidden')
        box = await message.bounding_box()
        await page.screenshot(path=str(state / 'mobile-keyboard.png'), full_page=True)
        assert box and box['y'] + box['height'] <= 480, await page.evaluate('''() => ({
            viewport:visualViewport.height, elements:[...document.querySelectorAll('.q-header,.nicegui-content,.workspace,.conversation,.composer')]
            .map(el=>({class:el.className,rect:el.getBoundingClientRect().toJSON(),min:getComputedStyle(el).minHeight}))})''')
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_label('Search agents and domains', exact=True).fill('Team')
        await page.locator('.q-tree').get_by_text('Research Admin', exact=True).wait_for()
        await page.screenshot(path=str(state / 'mobile-drawer.png'), full_page=True)
        await browser.close()


async def test_browser_budget_pause_reload_and_continue(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
        await login(page, url)
        await page.get_by_label('Message', exact=True).fill('bounded lifecycle')
        await page.get_by_role('button', name='Send', exact=True).click()
        continuation = page.get_by_role('button', name='Continue saved task', exact=True)
        await continuation.wait_for()
        await page.get_by_text('Window limits: 2 requests / 2 tools', exact=False).wait_for()
        await page.screenshot(path=str(state / 'budget-paused.png'), full_page=True)
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_label('Conversation', exact=True).fill('bounded lifecycle')
        await page.get_by_role('option', name='bounded lifecycle', exact=True).click()
        await continuation.wait_for()
        for tools in (4, 5):
            await continuation.click()
            await page.get_by_text(f'Tools: {tools}', exact=False).wait_for()
            await page.get_by_text('Paused · Completed activity saved' if tools == 4 else 'Completed',
                                   exact=tools == 5).wait_for()
        await page.get_by_text('Bounded lifecycle complete', exact=True).wait_for()
        assert not await continuation.is_visible()
        await page.get_by_text('Tools: 5', exact=False).wait_for()
        box = await page.get_by_label('Message', exact=True).bounding_box()
        assert box['y'] + box['height'] <= 844
        await page.screenshot(path=str(state / 'budget-completed.png'), full_page=True)
        await page.get_by_label('Message', exact=True).fill('Inspect resources in a second turn')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        await page.get_by_text('Bounded lifecycle complete', exact=True).wait_for()
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_label('Conversation', exact=True).fill('bounded lifecycle')
        await page.get_by_role('option', name='bounded lifecycle', exact=True).click()
        await page.get_by_text('Bounded lifecycle complete', exact=True).wait_for()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        assert await page.get_by_text('Inspect resources in a second turn', exact=True).count() == 1
        await browser.close()


async def test_cloudstack_dashboard_header_mobile_and_platform_configuration(browser_app):
    url, _ = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        link = page.get_by_role('link', name='CloudStack Dashboard', exact=True).filter(visible=True)
        await link.wait_for()
        assert await link.get_attribute('href') == 'https://cloudstack.tailnet.invalid/client/'
        assert await link.get_attribute('target') == '_blank'
        assert 'noopener' in await link.get_attribute('rel')
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.locator('.q-drawer--mobile').wait_for(state='attached')
        await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_label('Search agents and domains', exact=True).wait_for()
        await page.get_by_role('button', name='Close agent hierarchy', exact=True).click()
        await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await link.wait_for()
        await page.get_by_role('button', name='Platform settings', exact=True).click()
        await page.get_by_label('CloudStack Dashboard URL', exact=True).fill('https://another.tailnet.invalid/client')
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        assert await link.get_attribute('href') == 'https://another.tailnet.invalid/client/'
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await link.wait_for()
        assert await link.get_attribute('href') == 'https://another.tailnet.invalid/client/'
        await browser.close()


async def test_gpu_policy_platform_ui_persists_and_loads_on_mobile(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        await page.get_by_role('button', name='GPU policies', exact=True).click()
        await page.get_by_label('GPU policy domain', exact=True).fill('ROOT')
        await page.get_by_role('option', name='ROOT', exact=True).click()
        await page.get_by_label('Allowed vGPU profiles', exact=True).fill('GRID P40-8Q')
        await page.get_by_role('option', name='GRID P40-8Q', exact=True).click()
        await page.keyboard.press('Escape')
        await page.get_by_label('Maximum GPU allocations', exact=True).fill('-1')
        await page.get_by_label('Maximum GPU allocations', exact=True).press('Tab')
        await page.get_by_role('button', name='Save GPU policy', exact=True).click()
        await page.get_by_text('Policy saved; native CloudStack quota verified.', exact=True).wait_for()
        await page.get_by_role('button', name='Close', exact=True).click()
        for _ in range(3):
            await page.set_viewport_size({'width': 1440, 'height': 900})
            await page.reload()
            await page.wait_for_function('window.socket?.connected && window.did_handshake')
            await page.set_viewport_size({'width': 390, 'height': 844})
            await page.locator('.q-drawer--mobile').wait_for(state='attached')
            await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_role('button', name='GPU policies', exact=True).click()
        await page.get_by_label('GPU policy domain', exact=True).fill('ROOT')
        await page.get_by_role('option', name='ROOT', exact=True).click()
        await page.get_by_role('option', name='ROOT', exact=True).wait_for(state='hidden')
        await page.get_by_text('GRID P40-8Q', exact=True).wait_for()
        assert await page.get_by_label('Maximum GPU allocations', exact=True).input_value() == '-1'
        assert await page.get_by_role('checkbox', name='Allow reconfiguration of owned unused GPU pools', exact=True).get_attribute('aria-checked') == 'false'
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await page.screenshot(path=str(state / 'gpu-policy-mobile.png'), full_page=True)
        await browser.close()


async def test_browser_agent_system_prompt_and_mcp_settings_persist(browser_app):
    from dirigentenstab.limits import APP_ROOT_AGENT
    from dirigentenstab.store import Store

    url, state = browser_app
    secret = 'tvly-browser-fixture-mcp-credential'
    prompt = 'Answer infrastructure questions in German and ask before deleting resources.'
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        page = await context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        await login(page, url)
        selector = page.get_by_label('Chat directly with an agent', exact=True)
        await selector.fill('Main Agent')
        await page.get_by_role('option', name='Main Agent', exact=True).click()
        await page.get_by_role('button', name='Configure', exact=True).click()
        await page.get_by_label('System prompt', exact=True).fill(prompt)
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await page.get_by_role('button', name='Configure', exact=True).click()
        assert await page.get_by_label('System prompt', exact=True).input_value() == prompt
        await page.get_by_role('button', name='MCP tools', exact=True).click()
        await page.get_by_label('Server name', exact=True).fill('Tavily web search')
        await page.get_by_label('HTTPS Streamable HTTP endpoint', exact=True).fill('https://mcp.tavily.com/mcp')
        bearer = page.get_by_label('API key / bearer token (blank keeps existing)', exact=True)
        assert await bearer.get_attribute('type') == 'password'
        await bearer.fill(secret)
        await page.get_by_role('button', name='Save server settings', exact=True).click()
        await page.get_by_text('2 tools available.', exact=False).wait_for()
        assert await bearer.input_value() == ''
        search_tool = page.get_by_role('checkbox', name='tavily_search', exact=True)
        extract_tool = page.get_by_role('checkbox', name='tavily_extract', exact=True)
        await search_tool.wait_for()
        assert await search_tool.get_attribute('aria-checked') == 'false'
        assert await extract_tool.get_attribute('aria-checked') == 'false'
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        assert store.all('SELECT * FROM mcp_assignments') == []
        await search_tool.click()
        await page.get_by_role('checkbox', name='tavily_search', exact=True, checked=True).wait_for()
        await page.get_by_role('button', name='Save assigned tools', exact=True).click()
        await page.get_by_text('Assigned tools saved for this agent.', exact=True).wait_for()
        server = store.one('SELECT * FROM mcp_servers')
        assert server['url'] == 'https://mcp.tavily.com/mcp'
        assert store.open(server['token']) == secret and secret.encode() not in server['token']
        assert json.loads(store.one('SELECT tools FROM mcp_assignments WHERE agent_id=?', (APP_ROOT_AGENT,))['tools']) == ['tavily_search']
        assert store.one('SELECT instructions FROM agents WHERE id=?', (APP_ROOT_AGENT,))['instructions'] == prompt
        assert secret not in await page.content()

        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await selector.fill('Main Agent')
        await page.get_by_role('option', name='Main Agent', exact=True).click()
        await page.get_by_role('button', name='Configure', exact=True).click()
        assert await page.get_by_label('System prompt', exact=True).input_value() == prompt
        await page.get_by_role('button', name='MCP tools', exact=True).click()
        await page.get_by_role('checkbox', name='tavily_search', exact=True, checked=True).wait_for()
        assert await extract_tool.get_attribute('aria-checked') == 'false'
        (state / 'mcp-unavailable').touch()
        await page.get_by_role('button', name='Refresh tools', exact=True).click()
        await page.get_by_text('Your selections are preserved.', exact=False).wait_for()
        assert await search_tool.get_attribute('aria-checked') == 'true'
        assert json.loads(store.one('SELECT tools FROM mcp_assignments WHERE agent_id=?', (APP_ROOT_AGENT,))['tools']) == ['tavily_search']
        (state / 'mcp-unavailable').unlink()
        assert await bearer.input_value() == ''
        await page.get_by_role('checkbox', name='Clear saved bearer token', exact=True).click()
        await page.get_by_role('checkbox', name='Clear saved bearer token', exact=True, checked=True).wait_for()
        await page.get_by_role('button', name='Save server settings', exact=True).click()
        await page.get_by_text('2 tools available.', exact=False).wait_for()
        assert store.open(store.one('SELECT token FROM mcp_servers')['token']) == ''
        await page.screenshot(path=str(state / 'mcp-settings.png'), full_page=True)
        assert not errors
        await browser.close()


async def test_browser_entire_agent_details_collapse_on_desktop_and_mobile(browser_app):
    from dirigentenstab.store import Store

    url, state = browser_app
    store = Store(str(state / 'browser.db'), str(state / 'master'))
    store.execute("UPDATE agents SET can_provision=1 WHERE id='research'")
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        selector = page.get_by_label('Chat directly with an agent', exact=True)
        details = page.locator('.agent-details')
        header = details.locator('.q-expansion-item__container > .q-item').first
        configure = details.get_by_role('button', name='Configure', exact=True)
        subgroup = details.get_by_role('button', name='Create subgroup', exact=True)
        for width, height in [(1440, 900), (390, 844)]:
            await page.set_viewport_size({'width': width, 'height': height})
            await selector.fill('Research')
            await page.get_by_role('option', name='Research Admin', exact=True).click()
            await configure.wait_for()
            await subgroup.wait_for()
            await details.get_by_text('Model: Local fixture / fixture-model', exact=True).wait_for()
            assert await header.get_attribute('aria-expanded') == 'true'
            await details.get_by_text('Domain details', exact=True).click()
            account = details.get_by_text('Administrator account: research-account', exact=True)
            await account.wait_for()
            expanded_height = (await details.bounding_box())['height']
            await header.click()
            await configure.wait_for(state='hidden')
            await subgroup.wait_for(state='hidden')
            await account.wait_for(state='hidden')
            await details.get_by_text('Model: Local fixture / fixture-model', exact=True).wait_for(state='hidden')
            await details.get_by_text('Domain details', exact=True).wait_for(state='hidden')
            assert await header.get_attribute('aria-expanded') == 'false'
            assert await header.get_by_text('Research Admin', exact=True).is_visible()
            assert await header.get_by_text('Domain administrator', exact=True).is_visible()
            assert (await details.bounding_box())['height'] < expanded_height
            assert await details.get_by_role('button').count() == 1
            await header.focus()
            await header.press('Enter')
            await configure.wait_for()
            await account.wait_for()
            await configure.click()
            await page.get_by_label('System prompt', exact=True).wait_for()
            await page.get_by_role('button', name='Cancel', exact=True).click()
            await page.get_by_role('dialog').wait_for(state='hidden')
            assert await header.get_attribute('aria-expanded') == 'true'
            await subgroup.click()
            await page.get_by_text('Create subgroup under Research Admin', exact=True).wait_for()
            await page.get_by_role('button', name='Cancel', exact=True).click()
            await page.get_by_role('dialog').wait_for(state='hidden')
            assert await header.get_attribute('aria-expanded') == 'true'
            await header.focus()
            await header.press('Space')
            await configure.wait_for(state='hidden')
            await page.screenshot(path=str(state / f'agent-details-collapsed-{width}.png'), full_page=True)
            await selector.fill('Main Agent')
            await page.get_by_role('option', name='Main Agent', exact=True).click()
            await configure.wait_for()
            assert await header.get_attribute('aria-expanded') == 'true'
            assert await header.get_by_text('Main Agent', exact=True).is_visible()
            assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await browser.close()


async def test_browser_thinking_settings_follow_model_metadata_and_pending_animation(browser_app):
    from dirigentenstab.store import Store

    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
        await login(page, url)
        agent = page.get_by_label('Chat directly with an agent', exact=True)
        await agent.fill('Research')
        await page.get_by_role('option', name='Research Admin', exact=True).click()
        await page.get_by_role('button', name='Configure', exact=True).click()
        await page.get_by_text('Levels advertised by the provider model API.', exact=True).wait_for()
        thinking = page.get_by_label('Thinking level', exact=True)
        await thinking.click()
        await page.get_by_role('option', name='Max', exact=True).click()
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        assert store.one("SELECT thinking FROM agents WHERE id='research'")['thinking'] == 'max'
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await agent.fill('Research')
        await page.get_by_role('option', name='Research Admin', exact=True).click()
        await page.get_by_role('button', name='Configure', exact=True).click()
        await page.get_by_text('Levels advertised by the provider model API.', exact=True).wait_for()
        await thinking.click()
        await playwright.expect(page.get_by_role('option', name='Max', exact=True)).to_have_attribute('aria-selected', 'true')
        await page.keyboard.press('Escape')
        model = page.get_by_label('Model ID', exact=True)
        await model.fill('second-model')
        await model.press('Enter')
        await page.get_by_text('The previous thinking level is unavailable for this model;', exact=False).wait_for()
        await thinking.click()
        assert await page.get_by_role('option', name='Max', exact=True).count() == 0
        assert await page.get_by_role('option', name='On', exact=True).count() == 0
        await page.get_by_role('option', name='High', exact=True).click()
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        assert store.one("SELECT model,thinking FROM agents WHERE id='research'") == {
            'model': 'second-model', 'thinking': 'high'}
        indicator = page.locator('.thinking-indicator')
        assert not await indicator.is_visible()
        await page.get_by_label('Message', exact=True).fill('thinking indicator')
        await page.get_by_role('button', name='Send', exact=True).click()
        await indicator.wait_for()
        assert await indicator.get_attribute('role') == 'status'
        assert await indicator.get_by_text('Thinking…', exact=True).is_visible()
        assert await indicator.locator('.thinking-dot').count() == 3
        assert await indicator.locator('.thinking-dot').first.evaluate('e => getComputedStyle(e).animationName') == 'thinking-pulse'
        await page.emulate_media(reduced_motion='reduce')
        assert await indicator.locator('.thinking-dot').first.evaluate('e => getComputedStyle(e).animationName') == 'none'
        await page.get_by_text('Pending response complete.', exact=True).wait_for()
        await indicator.wait_for(state='hidden')
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        assert not await indicator.is_visible()
        await agent.fill('Research')
        await page.get_by_role('option', name='Research Admin', exact=True).click()
        await page.get_by_label('Conversation', exact=True).fill('thinking indicator')
        await page.get_by_role('option', name='thinking indicator', exact=True).click()
        await page.get_by_text('Pending response complete.', exact=True).wait_for()
        assert not await indicator.is_visible()
        await page.screenshot(path=str(state / 'thinking-selector-mobile.png'), full_page=True)
        await browser.close()
