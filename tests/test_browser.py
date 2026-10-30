"""Real Chromium + NiceGUI browser tests; infrastructure/model providers are CI fixtures."""

import json
import os
import re
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
    started = time.monotonic()
    last_error = None
    try:
        # Imports, migrations and TLS setup can exceed 12 seconds on shared CI storage.
        while time.monotonic() - started < 30:
            if process.poll() is not None:
                pytest.fail('Browser fixture failed to start:\n' + (tmp_path / 'browser-server.log').read_text())
            try:
                with urllib.request.urlopen(url + '/healthz', context=ssl._create_unverified_context(), timeout=1):
                    break
            except (OSError, urllib.error.URLError) as exc:
                last_error = repr(exc)
                time.sleep(0.1)
        else:
            pytest.fail(f'Browser fixture did not become ready after {time.monotonic() - started:.1f}s; '
                        f'last health probe: {last_error}\n' + (tmp_path / 'browser-server.log').read_text())
        yield url, tmp_path
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


@pytest.mark.parametrize('width,height', [(1440, 900), (390, 844)])
async def test_browser_vm_file_browser_lists_downloads_uploads_and_restores(browser_app, width, height):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': width, 'height': height})
        page = await context.new_page()
        await login(page, url)
        await page.goto(url + '/?vm=00000000-0000-0000-0000-000000000004&mode=files')
        pane = page.locator('.terminal-pane')
        files = pane.locator('.files-pane')
        await files.get_by_text('docs', exact=True).wait_for()
        await files.get_by_text(re.compile(r'^long-name-x+\.txt$')).wait_for()
        await playwright.expect(pane.get_by_label('Path', exact=True)).to_have_value('/')
        # Directories first, then files.
        names = await files.locator('.q-item__label:not(.q-item__label--caption)').all_inner_texts()
        assert names[0] == 'docs'
        await files.get_by_text('docs', exact=True).click()
        await playwright.expect(pane.get_by_label('Path', exact=True)).to_have_value('/docs')
        async with page.expect_download() as download:
            await pane.get_by_role('button', name='Download report.txt', exact=True).click()
        saved = await download.value
        await saved.save_as(state / f'download-{width}.txt')
        assert (saved.suggested_filename, (state / f'download-{width}.txt').read_text()) == ('report.txt', 'fixture report\n')
        await files.locator('input[type=file]').set_input_files(
            files=[{'name': 'upload.txt', 'mimeType': 'text/plain', 'buffer': b'uploaded'}])
        await files.locator('.q-list').get_by_text('upload.txt', exact=True).wait_for()
        assert (state / 'vm-files' / 'docs' / 'upload.txt').read_bytes() == b'uploaded'
        await files.locator('input[type=file]').set_input_files(
            files=[{'name': 'upload.txt', 'mimeType': 'text/plain', 'buffer': b'again'}])
        await page.get_by_text('Overwrite upload.txt?', exact=True).wait_for()
        await page.get_by_role('button', name='Cancel', exact=True).click()
        assert (state / 'vm-files' / 'docs' / 'upload.txt').read_bytes() == b'uploaded'
        await pane.get_by_role('button', name='Parent directory', exact=True).click()
        await playwright.expect(pane.get_by_label('Path', exact=True)).to_have_value('/')
        await pane.get_by_label('Path', exact=True).fill('/b.txt')
        await pane.get_by_label('Path', exact=True).press('Enter')
        await pane.locator('[data-marker="terminal_error"], .text-red-600').filter(visible=True).wait_for()
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        assert await files.evaluate('el => el.scrollWidth <= el.clientWidth')
        await page.screenshot(path=str(state / f'files-{width}x{height}.png'), full_page=True)
        await page.wait_for_function('location.search.endsWith("&mode=files")')
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await files.get_by_text('docs', exact=True).wait_for()
        await playwright.expect(pane.get_by_role('button', name='Files', exact=True)).to_have_attribute('aria-pressed', 'true')
        await browser.close()


async def login(page, url):
    await page.goto(url + '/login')
    await page.get_by_label('Username', exact=True).fill('alice')
    await page.get_by_label('Password', exact=True).fill('browser-fixture-password')
    await page.get_by_role('button', name='Sign in', exact=True).click()
    await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Main Agent', exact=True).wait_for()
    await page.wait_for_function('window.socket?.connected && window.did_handshake')


async def open_sidebar(page):
    """Open the agent drawer unless it is open. Wait for Quasar's show-if-above transition first: a drawer that is
    mid-close still counts as visible, so deciding early skipped the click and left it offscreen."""
    search = page.get_by_label('Search agents and domains', exact=True)
    box = None
    for _ in range(50):
        prev, box = box, await page.locator('.q-drawer').bounding_box()
        if prev == box:
            break
        await page.wait_for_timeout(100)
    if not await search.is_visible():
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
    await search.wait_for()


async def select_agent(page, name):
    await open_sidebar(page)
    search = page.get_by_label('Search agents and domains', exact=True)
    await search.fill(name)
    await page.locator('.q-tree').get_by_text(name, exact=True).click()
    await search.wait_for(state='hidden')
    await page.get_by_role('button', name='Agent details', exact=True).get_by_text(name, exact=True).wait_for()


async def ensure_navigation_open(page):
    # After a reload the drawer follows show-if-above: open on desktop, closed on mobile.
    close = page.get_by_role('button', name='Close agent hierarchy', exact=True)
    if not await close.is_visible():
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
    await close.wait_for()


async def open_configuration(page):
    await page.get_by_role('button', name='Agent details', exact=True).click()
    await page.locator('.agent-details').get_by_role('button', name='Configure', exact=True).click()


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
        await select_agent(page, 'Research Admin')
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
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('button', name='Model providers', exact=True).click()
        await page.get_by_label('Base URL (including /v1)', exact=True).wait_for()
        await page.get_by_label('Summary model provider', exact=True).wait_for()
        await page.get_by_role('button', name='Close', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await page.evaluate('window.scrollTo(0, 0)')
        await page.screenshot(path=str(state / 'desktop.png'), full_page=True)
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.locator('.q-drawer--mobile').wait_for(state='attached')
        await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
        await page.locator('.agent-details').get_by_role('button', name='Configure', exact=True).wait_for(state='hidden')
        await page.evaluate('window.scrollTo(0, 0)')
        assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        await page.screenshot(path=str(state / 'mobile.png'), full_page=True)
        assert not errors
        assert await page.locator('.q-header').get_by_role('button', name='Sign out').count() == 0
        assert await page.locator('[data-mark="hub_activity"]').count() == 0
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('button', name='Sign out', exact=True).click()
        await page.get_by_role('button', name='Sign in', exact=True).wait_for()
        assert not any(cookie['name'] == 'ds_session' for cookie in await context.cookies())
        await browser.close()


async def test_browser_remembers_last_open_conversation_per_agent(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await login(page, url)
        await select_agent(page, 'Research Admin')
        message = page.get_by_label('Message', exact=True)
        for title in ('First research conversation', 'Second research conversation'):
            await message.fill(title)
            await page.get_by_role('button', name='Send', exact=True).click()
            await page.get_by_text(title, exact=True).last.wait_for()
            await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
            await page.get_by_role('button', name='New conversation', exact=True).click()
        selector = page.get_by_label('Conversation', exact=True)
        await selector.fill('First research conversation')
        await page.get_by_role('option', name='First research conversation', exact=True).click()
        await page.locator('.q-message').get_by_text('First research conversation', exact=True).wait_for()
        await message.fill('Unsent research draft')
        await select_agent(page, 'Main Agent')
        await message.fill('Main conversation')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        await select_agent(page, 'Research Admin')
        await playwright.expect(message).to_have_value('Unsent research draft')
        await page.locator('.q-message').get_by_text('First research conversation', exact=True).wait_for()
        assert await page.get_by_text('Second research conversation', exact=True).count() == 0
        await page.reload()
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await page.locator('.q-message').get_by_text('First research conversation', exact=True).wait_for()
        await ensure_navigation_open(page)
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('button', name='Sign out', exact=True).click()
        await page.get_by_role('button', name='Sign in', exact=True).wait_for()
        await login(page, url)
        await select_agent(page, 'Research Admin')
        await page.locator('.q-message').get_by_text('First research conversation', exact=True).wait_for()
        from dirigentenstab.store import Store
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        main_conversation = store.one("SELECT value FROM platform_settings WHERE name LIKE 'last_conversation:%' "
                                      "AND name NOT LIKE '%:research'")['value']
        for invalid_id in ('deleted-conversation', main_conversation):
            store.execute("UPDATE platform_settings SET value=? WHERE name LIKE 'last_conversation:%:research'",
                          (invalid_id,))
            await select_agent(page, 'Main Agent')
            await select_agent(page, 'Research Admin')
            await page.locator('.q-message').get_by_text('Second research conversation', exact=True).wait_for()
        await page.get_by_role('button', name='New conversation', exact=True).click()
        await message.fill('New draft')
        await select_agent(page, 'Main Agent')
        await select_agent(page, 'Research Admin')
        await playwright.expect(message).to_have_value('New draft')
        assert await page.locator('.q-message').count() == 0
        await page.reload()
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        assert await page.locator('.q-message').count() == 0
        await browser.close()


async def test_browser_disabled_cloudstack_human_loses_existing_socket_access(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await login(page, url)
        (state / 'human-disabled').touch()
        # The activity timer revalidates the socket session and redirects automatically.
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
            try:
                await select_agent(page, name)
            except Exception:
                await page.screenshot(path=str(state / 'selection-failure.png'), full_page=True)
                raise
            assert (await message.bounding_box())['x'] < 60
            assert await page.evaluate('window.scrollY === 0')
        await open_configuration(page)
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
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Team 2 Level 3', exact=True).wait_for()
        await open_configuration(page)
        await page.get_by_label('Model ID', exact=True).wait_for()
        await playwright.expect(page.get_by_label('Model ID', exact=True)).to_have_value('custom-private-model')
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
        await playwright.expect(page.get_by_role('button', name='Stop conversation', exact=True)).not_to_be_visible()
        await playwright.expect(page.locator('.thinking-indicator')).not_to_be_visible()
        assert await page.locator('.conversation .run-status').count() == 0
        assert await page.locator('.markdown table').count() == 1
        assert await page.locator('.markdown pre code').count() == 1
        assert not await page.evaluate('window.injected === true')
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert await page.locator('.messages .q-scrollarea__container').evaluate('el => el.scrollWidth <= el.clientWidth')
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
        await page.get_by_role('button', name='Agent details', exact=True).wait_for()
        await open_configuration(page)
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
        await page.wait_for_function('() => { const r = document.querySelector(".composer")?.getBoundingClientRect(); return r && r.bottom <= 480; }')
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


async def test_browser_long_task_completes_without_budget_pause_and_restores(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
        await login(page, url)
        await page.get_by_label('Message', exact=True).fill('bounded lifecycle')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Bounded lifecycle complete', exact=True).wait_for()
        assert await page.get_by_role('button', name='Continue saved task', exact=True).count() == 0
        await playwright.expect(page.get_by_role('button', name='Stop conversation', exact=True)).not_to_be_visible()
        await playwright.expect(page.locator('.thinking-indicator')).not_to_be_visible()
        assert await page.locator('.conversation .run-status').count() == 0
        await playwright.expect(page.get_by_text('Tools: 5', exact=False)).not_to_be_visible()
        await page.get_by_role('button', name='Run details', exact=True).click()
        await page.get_by_text('Tools: 5', exact=False).wait_for()
        assert await page.locator('.messages .q-scrollarea__container').evaluate('el => el.scrollWidth <= el.clientWidth')
        box = await page.get_by_label('Message', exact=True).bounding_box()
        assert box['y'] + box['height'] <= 844
        await page.screenshot(path=str(state / 'long-task-completed.png'), full_page=True)
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
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('button', name='Platform settings', exact=True).click()
        limit = page.get_by_label('Open escalation requests per agent', exact=True)
        await playwright.expect(limit).to_have_value('3')
        await limit.fill('2')
        await page.get_by_label('CloudStack Dashboard URL', exact=True).fill('https://another.tailnet.invalid/client')
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        assert await link.get_attribute('href') == 'https://another.tailnet.invalid/client/'
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await link.wait_for()
        assert await link.get_attribute('href') == 'https://another.tailnet.invalid/client/'
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('button', name='Platform settings', exact=True).click()
        await playwright.expect(limit).to_have_value('2')
        await browser.close()


async def test_gpu_policy_platform_ui_persists_and_loads_on_mobile(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        await page.get_by_role('button', name='Settings', exact=True).click()
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
        await page.get_by_role('button', name='Settings', exact=True).click()
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
        await open_configuration(page)
        owner_access = page.get_by_role('checkbox', name='Access owner SSH public key', exact=True)
        await playwright.expect(owner_access).to_be_checked()
        await owner_access.click()
        await page.get_by_label('System prompt', exact=True).fill(prompt)
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await open_configuration(page)
        await playwright.expect(page.get_by_label('System prompt', exact=True)).to_have_value(prompt)
        await playwright.expect(owner_access).not_to_be_checked()
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
        await open_configuration(page)
        await playwright.expect(page.get_by_label('System prompt', exact=True)).to_have_value(prompt)
        await playwright.expect(owner_access).not_to_be_checked()
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
        await page.get_by_role('button', name='Close MCP tools', exact=True).click()
        await page.get_by_role('button', name='Cancel', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await select_agent(page, 'Research Admin')
        await open_configuration(page)
        await playwright.expect(owner_access).to_be_disabled()
        await playwright.expect(owner_access).not_to_be_checked()
        await page.get_by_text('Disabled by an ancestor. The saved selection is retained.', exact=True).wait_for()
        assert store.one("SELECT owner_ssh_key_enabled FROM agents WHERE id='research'")['owner_ssh_key_enabled'] == 1
        await page.screenshot(path=str(state / 'owner-key-inherited-disabled-mobile.png'), full_page=True)
        assert not errors
        await browser.close()


async def test_browser_header_agent_details_and_sidebar_selection_on_desktop_and_mobile(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        details = page.locator('.agent-details')
        opener = page.locator('.q-header').get_by_role('button', name='Agent details', exact=True)
        configure = details.get_by_role('button', name='Configure', exact=True)
        subgroup = details.get_by_role('button', name='Create subgroup', exact=True)
        for width, height in [(1440, 900), (390, 844)]:
            await page.set_viewport_size({'width': width, 'height': height})
            if width <= 900:
                await page.locator('.q-drawer--mobile').wait_for(state='attached')
            toggle = page.locator('.q-header').get_by_role('button', name='Open agent hierarchy', exact=True)
            await playwright.expect(toggle).to_be_visible()
            await playwright.expect(opener).to_be_visible()
            assert await page.get_by_label('Agent', exact=True).count() == 0
            assert await page.get_by_label('Chat directly with an agent', exact=True).count() == 0
            assert await page.locator('.workspace .agent-details').count() == 0
            controls = page.locator('.conversation-controls')
            assert await controls.get_by_label('Conversation', exact=True).is_visible()
            assert await controls.get_by_role('button', name='New conversation', exact=True).is_visible()
            assert await controls.evaluate('el => el.parentElement.firstElementChild === el')
            assert await page.locator('.conversation').evaluate('el => el.previousElementSibling.classList.contains("conversation-controls")')
            run_details_button = controls.get_by_role('button', name='Run details', exact=True)
            await playwright.expect(run_details_button).to_be_visible()
            new_btn_box = await controls.get_by_role('button', name='New conversation', exact=True).bounding_box()
            run_btn_box = await run_details_button.bounding_box()
            assert run_btn_box and new_btn_box and run_btn_box['x'] > new_btn_box['x']
            await run_details_button.click()
            run_details_menu = page.locator('.run-details-menu')
            await run_details_menu.wait_for()
            menu_box = await run_details_menu.bounding_box()
            assert menu_box and 0 <= menu_box['x'] and menu_box['x'] + menu_box['width'] <= width + 2
            assert 0 <= menu_box['y'] and menu_box['y'] + menu_box['height'] <= height + 2
            await page.keyboard.press('Escape')
            await run_details_menu.wait_for(state='hidden')
            assert await page.locator('.conversation .run-details').count() == 0
            assert await page.locator('.conversation .run-status').count() == 0
            send_button = page.get_by_role('button', name='Send', exact=True)
            await playwright.expect(send_button).to_be_visible()
            assert await send_button.locator('.q-icon').count() == 1
            assert await send_button.locator('.q-btn__content > :not(.q-icon)').count() == 0
            assert 'Send' not in (await send_button.inner_text()).split()
            msg_box = await page.locator('.composer .q-field__control').bounding_box()
            snd_box = await send_button.bounding_box()
            assert msg_box and snd_box
            assert abs(msg_box['y'] - snd_box['y']) <= 2
            assert abs(msg_box['height'] - snd_box['height']) <= 2
            assert abs(snd_box['width'] - 44) <= 2 and abs(snd_box['height'] - 44) <= 2
            assert snd_box['x'] + snd_box['width'] <= width
            search = page.get_by_label('Search agents and domains', exact=True)
            if await search.is_visible():
                await page.get_by_role('button', name='Close agent hierarchy', exact=True).click()
            await search.wait_for(state='hidden')
            await toggle.focus()
            await toggle.press('Enter')
            await playwright.expect(search).to_be_visible()
            await select_agent(page, 'Research Admin')
            await details.wait_for(state='hidden')
            await opener.click()
            await configure.wait_for()
            await subgroup.wait_for()
            conf_box = await configure.bounding_box()
            sub_box = await subgroup.bounding_box()
            assert conf_box and sub_box and abs(conf_box['y'] - sub_box['y']) <= 1
            await details.get_by_text('Domain administrator', exact=True).wait_for()
            await details.get_by_text('Model: Local fixture / fixture-model', exact=True).wait_for()
            await details.get_by_text('Domain details', exact=True).click()
            await details.get_by_text('Administrator account: research-account', exact=True).wait_for()
            await details.get_by_text('Virtual machines', exact=True).click()
            await details.get_by_text('research-vm · Running', exact=True).scroll_into_view_if_needed()
            menu_box = await page.locator('.agent-details-menu').bounding_box()
            assert menu_box and 0 <= menu_box['x'] <= width - menu_box['width']
            assert 0 <= menu_box['y'] <= height - menu_box['height']
            await page.screenshot(path=str(state / f'header-agent-details-open-{width}.png'), full_page=True)
            await details.get_by_role('button', name='Close agent details', exact=True).click()
            await details.wait_for(state='hidden')
            await open_configuration(page)
            await page.get_by_label('System prompt', exact=True).wait_for()
            await details.wait_for(state='hidden')
            await page.get_by_role('button', name='Cancel', exact=True).click()
            await page.get_by_role('dialog').wait_for(state='hidden')
            await opener.click()
            await subgroup.click()
            await page.get_by_text('Create subgroup under Research Admin', exact=True).wait_for()
            await details.wait_for(state='hidden')
            await page.get_by_role('button', name='Cancel', exact=True).click()
            await page.get_by_role('dialog').wait_for(state='hidden')
            await opener.click()
            await details.wait_for()
            await page.keyboard.press('Escape')
            await details.wait_for(state='hidden')
            await page.screenshot(path=str(state / f'header-agent-details-closed-{width}.png'), full_page=True)
            await select_agent(page, 'Main Agent')
            await opener.click()
            await configure.wait_for()
            await details.get_by_role('button', name='Close agent details', exact=True).click()
            await details.wait_for(state='hidden')
            assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert await page.locator('.messages .q-scrollarea__container').evaluate('el => el.scrollWidth <= el.clientWidth')
        await browser.close()


async def test_browser_global_admin_separate_entry_and_configuration(browser_app):
    url, _ = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        for width, height in [(1440, 900), (390, 844)]:
            await page.set_viewport_size({'width': width, 'height': height})
            if width <= 900:
                await page.locator('.q-drawer--mobile').wait_for(state='attached')
            search = page.get_by_label('Search agents and domains', exact=True)
            if not await search.is_visible():
                await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
            await search.fill('')
            global_node = page.locator('.q-tree').get_by_text('Global Admin', exact=True)
            main_node = page.locator('.q-tree').get_by_text('Main Agent', exact=True)
            await playwright.expect(global_node).to_be_visible()
            global_box, main_box = await global_node.bounding_box(), await main_node.bounding_box()
            assert global_box and main_box and global_box['y'] < main_box['y']
            await global_node.click()
            await search.wait_for(state='hidden')
            await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Global Admin', exact=True).wait_for()
            await page.get_by_role('button', name='Agent details', exact=True).click()
            await page.locator('.agent-details').get_by_text('Root administrator', exact=True).wait_for()
            await page.locator('.agent-details').get_by_role('button', name='Configure', exact=True).click()
            await page.get_by_label('System prompt', exact=True).wait_for()
            await page.get_by_role('button', name='Cancel', exact=True).click()
            await page.get_by_role('dialog').wait_for(state='hidden')
            await select_agent(page, 'Main Agent')
            assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await browser.close()


async def test_browser_thinking_settings_follow_model_metadata_and_pending_animation(browser_app):
    from dirigentenstab.store import Store

    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
        await login(page, url)
        await select_agent(page, 'Research Admin')
        await open_configuration(page)
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
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await open_configuration(page)
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
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await page.get_by_label('Conversation', exact=True).fill('thinking indicator')
        await page.get_by_role('option', name='thinking indicator', exact=True).click()
        await page.get_by_text('Pending response complete.', exact=True).wait_for()
        assert not await indicator.is_visible()
        await page.screenshot(path=str(state / 'thinking-selector-mobile.png'), full_page=True)
        await browser.close()


async def test_browser_stop_agent_current_and_restored_running_conversation(browser_app):
    from dirigentenstab.store import Store

    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
        await login(page, url)
        await select_agent(page, 'Research Admin')
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        for restored in (False, True):
            title = 'stop fixture restored' if restored else 'stop fixture current'
            await page.get_by_label('Message', exact=True).fill(title)
            await page.get_by_role('button', name='Send', exact=True).click()
            await page.get_by_text('Partial reply retained', exact=True).wait_for()
            await page.get_by_role('button', name='Stop conversation', exact=True).wait_for()
            if restored:
                await page.reload()
                await page.wait_for_function('window.socket?.connected && window.did_handshake')
                await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
                await page.get_by_label('Conversation', exact=True).fill(title)
                await page.get_by_role('option', name=title, exact=True).click()
                await page.get_by_role('button', name='Stop conversation', exact=True).wait_for()
            await page.get_by_role('button', name='Stop conversation', exact=True).click()
            await page.get_by_role('button', name='Stop conversation', exact=True).wait_for(state='hidden')
            await page.locator('.thinking-indicator').wait_for(state='hidden')
            await page.get_by_text('Partial reply retained', exact=True).wait_for()
            assert await page.locator('.conversation .run-status').count() == 0
            await page.get_by_role('button', name='Run details', exact=True).click()
            await page.locator('.run-details').get_by_text('Stopped', exact=True).wait_for()
            await page.keyboard.press('Escape')
            assert await page.get_by_label('Message', exact=True).is_enabled()
            run = store.one('SELECT r.* FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id WHERE c.title=?', (title,))
            assert run['status'] == 'interrupted'
            assert store.open(run['checkpoint'])['reason'] == 'stopped'
            assert await page.get_by_role('button', name='Continue saved task', exact=True).count() == 0
            await page.get_by_role('button', name='New conversation', exact=True).click()
            await page.get_by_text('Partial reply retained', exact=True).wait_for(state='hidden')
        await page.screenshot(path=str(state / 'stopped-agent-mobile.png'), full_page=True)
        await browser.close()


async def test_browser_compaction_configuration_and_context_meter_persist(browser_app):
    from dirigentenstab.store import Store

    url, state = browser_app
    title = 'context meter tool roundtrip'
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 390, 'height': 844})
        await login(page, url)
        await select_agent(page, 'Research Admin')
        await open_configuration(page)
        await page.get_by_text('Context compaction', exact=True).click()
        await page.get_by_text('Provider model API (context_window).', exact=False).wait_for()
        automatic = page.get_by_role('checkbox', name='Automatically compact context', exact=True)
        assert await automatic.get_attribute('aria-checked') == 'false'
        assert await page.get_by_label('Compact at % of usable context', exact=True).is_disabled()
        provider = page.get_by_label('Compaction provider', exact=True)
        await provider.click()
        await page.get_by_role('option', name='Local fixture', exact=True).click()
        model = page.get_by_label('Compaction model', exact=True)
        await model.fill('second-model')
        await model.press('Enter')
        await automatic.click()
        await playwright.expect(automatic).to_have_attribute('aria-checked', 'true')
        override = page.get_by_label('Context window override (tokens, optional)', exact=True)
        await override.fill('65536')
        await override.press('Tab')
        await page.get_by_text('Manual context-window override.', exact=False).wait_for()
        await page.get_by_role('button', name='Save', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        settings = store.one("SELECT compaction_provider_id,compaction_model,auto_compact_percent,context_window FROM agents WHERE id='research'")
        assert settings == {'compaction_provider_id': 'fixture', 'compaction_model': 'second-model',
                            'auto_compact_percent': 75, 'context_window': 65536}
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await open_configuration(page)
        await page.get_by_text('Manual context-window override.', exact=False).wait_for()
        assert await model.input_value() == 'second-model'
        assert await override.input_value() == '65536'
        assert await automatic.get_attribute('aria-checked') == 'true'
        await provider.click()
        await page.get_by_role('option', name='Same as conversation', exact=True).click()
        await model.wait_for(state='hidden')
        await page.get_by_role('button', name='Cancel', exact=True).click()
        await page.get_by_role('dialog').wait_for(state='hidden')
        await page.get_by_label('Message', exact=True).fill(title)
        await page.get_by_role('button', name='Send', exact=True).click()
        meter = page.locator('.run-details').get_by_text('Context: ~', exact=False)
        await playwright.expect(meter).not_to_be_visible()
        await page.get_by_role('button', name='Run details', exact=True).click()
        await meter.wait_for()
        assert '57,344 usable tokens' in await meter.inner_text()
        assert 'Auto-compact at 75%' in await meter.inner_text()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        run = store.one('SELECT id,status,events,checkpoint FROM chat_runs ORDER BY created DESC LIMIT 1')
        assert run['status'] == 'completed'
        assert store.open(run['checkpoint'])['context']['usable_tokens'] == 57344
        events = store.open(run['events'])
        tool_budget = next(event['budget']['context'] for event in events if event['type'] == 'tool_result')
        assert type(tool_budget['estimated_tokens']) is int and tool_budget['estimated_tokens'] > 0
        assert tool_budget['usable_tokens'] == 57344
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await page.get_by_label('Conversation', exact=True).fill(title)
        await page.get_by_role('option', name=title, exact=True).click()
        await playwright.expect(meter).not_to_be_visible()
        await playwright.expect(page.get_by_role('button', name='Stop conversation', exact=True)).not_to_be_visible()
        await page.locator('.thinking-indicator').wait_for(state='hidden')
        assert await page.locator('.conversation .run-status').count() == 0
        await page.get_by_role('button', name='Run details', exact=True).click()
        await meter.wait_for()
        assert '57,344 usable tokens' in await meter.inner_text()
        await page.screenshot(path=str(state / 'compaction-context-mobile.png'), full_page=True)
        checkpoint = store.open(run['checkpoint'])
        checkpoint['context'].update(estimated_tokens='[redacted]', usable_tokens='[redacted]')
        store.execute('UPDATE chat_runs SET checkpoint=? WHERE id=?', (store.seal(checkpoint), run['id']))
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await page.get_by_label('Conversation', exact=True).fill(title)
        await page.get_by_role('option', name=title, exact=True).click()
        await page.get_by_role('button', name='Run details', exact=True).click()
        await page.get_by_text('Context usage unavailable for this activity.', exact=True).wait_for()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        assert 'in show_context' not in (state / 'browser-server.log').read_text()
        await browser.close()


async def test_browser_independent_conversations_interrupt_and_logout(browser_app):
    import asyncio
    from dirigentenstab.store import Store

    url, state = browser_app
    store = Store(str(state / 'browser.db'), str(state / 'master'))
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        async def send(text):
            await page.get_by_label('Message', exact=True).fill(text)
            await page.get_by_role('button', name='Send', exact=True).click()
        async def choose(title):
            await page.get_by_label('Conversation', exact=True).fill(title)
            await page.get_by_role('option', name=title, exact=True).click()
            await page.locator(f'.conversation[data-operation-id="{run(title)["id"]}"]').wait_for()
        async def conversation_options():
            await page.get_by_label('Conversation', exact=True).fill('')
            await playwright.expect(page.get_by_role('option')).to_have_count(2)
            await page.get_by_role('option', name='stop fixture first independent conversation', exact=True).wait_for()
            await page.get_by_role('option', name='stop fixture second independent conversation', exact=True).wait_for()
            labels = await page.get_by_role('option').locator('.q-item__label').all_text_contents()
            await page.keyboard.press('Escape')
            return labels
        def run(title):
            return store.one('SELECT r.* FROM chat_runs r JOIN conversations c ON c.id=r.conversation_id '
                             'WHERE c.title=? ORDER BY r.created DESC LIMIT 1', (title,))

        await send('stop fixture first independent conversation')
        await page.get_by_text('Partial reply retained', exact=True).wait_for()
        await page.get_by_label('Message', exact=True).fill('Keep this first conversation draft')
        await page.get_by_role('button', name='New conversation', exact=True).click()
        await page.get_by_text('Partial reply retained', exact=True).wait_for(state='hidden')
        await send('stop fixture second independent conversation')
        await page.get_by_text('Partial reply retained', exact=True).wait_for()
        assert run('stop fixture first independent conversation')['status'] == 'running'
        assert run('stop fixture second independent conversation')['status'] == 'running'
        await choose('stop fixture first independent conversation')
        await playwright.expect(page.get_by_label('Message', exact=True)).to_have_value('Keep this first conversation draft')
        await playwright.expect(page.get_by_role('button', name='Send', exact=True)).to_be_visible()
        await playwright.expect(page.get_by_role('button', name='Stop conversation', exact=True)).not_to_be_visible()
        options_before_stop = await conversation_options()
        await page.get_by_label('Message', exact=True).fill('')
        await playwright.expect(page.get_by_role('button', name='Stop conversation', exact=True)).to_be_visible()
        await playwright.expect(page.get_by_role('button', name='Send', exact=True)).not_to_be_visible()
        await page.get_by_role('button', name='Stop conversation', exact=True).click()
        await playwright.expect(page.get_by_role('button', name='Stop conversation', exact=True)).not_to_be_visible()
        await page.locator('.thinking-indicator').wait_for(state='hidden')
        assert run('stop fixture second independent conversation')['status'] == 'running'
        assert await conversation_options() == options_before_stop
        await choose('stop fixture second independent conversation')
        await send('Inspect resources after interrupting this conversation')
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        assert run('stop fixture first independent conversation')['status'] == 'interrupted'
        assert run('stop fixture second independent conversation')['status'] == 'completed'

        await page.get_by_role('button', name='New conversation', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for(state='hidden')
        await send('background fixture survives logout')
        await page.get_by_text('Background work accepted.', exact=True).wait_for()
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('button', name='Sign out', exact=True).click()
        await page.get_by_role('button', name='Sign in', exact=True).wait_for()
        for _ in range(100):
            if run('background fixture survives logout')['status'] == 'completed':
                break
            await asyncio.sleep(.1)
        assert run('background fixture survives logout')['status'] == 'completed'
        await login(page, url)
        await choose('background fixture survives logout')
        await page.get_by_text('Background work accepted. Background work completed.', exact=True).wait_for()
        await page.screenshot(path=str(state / 'independent-conversations-desktop.png'), full_page=True)
        await page.set_viewport_size({'width': 390, 'height': 844})
        await page.locator('.q-drawer--mobile').wait_for(state='attached')
        await page.get_by_label('Search agents and domains', exact=True).wait_for(state='hidden')
        await page.locator('.agent-details').get_by_role('button', name='Configure', exact=True).wait_for(state='hidden')
        assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        await page.screenshot(path=str(state / 'independent-conversations-mobile.png'), full_page=True)
        await browser.close()


async def test_browser_large_running_history_keeps_socket_and_transcript_nodes(browser_app):
    import asyncio
    from dirigentenstab.limits import APP_ROOT_AGENT
    from dirigentenstab.store import Store
    from scripts.browser_fixture import HUMAN_ID

    url, state = browser_app
    store = Store(str(state / 'browser.db'), str(state / 'master'))
    history = []
    for index in range(150):
        history.extend([
            {'kind': 'request', 'parts': [{'part_kind': 'user-prompt', 'content': f'Previous request {index}'}]},
            {'kind': 'response', 'parts': [{'part_kind': 'text', 'content': f'Previous answer {index}'}],
             'provider_details': {'fixture_padding': 'x' * 120_000}},
        ])
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('large-history', APP_ROOT_AGENT, HUMAN_ID, 'Large history fixture', time.time(), store.seal(history)))
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True)
        await login(page, url)
        await page.get_by_label('Conversation', exact=True).fill('Large history fixture')
        await page.get_by_role('option', name='Large history fixture', exact=True).click()
        await page.get_by_text('Previous answer 149', exact=True).wait_for()
        await page.evaluate("window.socketFailures = []; window.socket.on('disconnect', reason => socketFailures.push(reason))")
        await asyncio.sleep(6)
        assert await page.evaluate('window.socket.connected && socketFailures.length === 0')
        await page.get_by_label('Message', exact=True).fill('heartbeat fixture')
        await page.get_by_role('button', name='Send', exact=True).click()
        # The 18 MB encrypted history is decrypted, validated and resealed several times before the first token (~10 s idle, far more with 4 workers).
        await page.get_by_text('Heartbeat 0.', exact=False).wait_for(timeout=90000)
        await page.evaluate("window.retainedMessage = document.querySelector('.q-message')")
        await asyncio.sleep(3)
        assert await page.evaluate('window.retainedMessage.isConnected')
        # Reopening an active conversation must use the same incremental refresh path.
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_label('Conversation', exact=True).fill('Large history fixture')
        await page.get_by_role('option', name='Large history fixture', exact=True).click()
        await page.get_by_text('Heartbeat 0.', exact=False).wait_for()
        await page.evaluate("window.retainedMessage = document.querySelector('.q-message'); window.socketFailures = []; window.socket.on('disconnect', reason => socketFailures.push(reason))")
        await asyncio.sleep(3)
        assert await page.evaluate('window.socket.connected && socketFailures.length === 0 && retainedMessage.isConnected')
        await page.get_by_text('Streaming complete.', exact=False).wait_for(timeout=60000)
        assert await page.evaluate('window.socket.connected && socketFailures.length === 0 && retainedMessage.isConnected')
        assert await page.get_by_text('Previous answer 149', exact=True).count() == 1
        await browser.close()


@pytest.mark.parametrize('width', [390, 1440])
async def test_escalation_requests_review_approve_dismiss_and_inheritance(browser_app, width):
    from dirigentenstab.limits import APP_ROOT_AGENT
    from dirigentenstab.store import Store

    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': width, 'height': 844})
        page = await context.new_page()
        await login(page, url)
        await select_agent(page, 'Research Admin')
        requests = page.get_by_role('button', name='Escalation requests: 0 pending', exact=True)
        await requests.wait_for()
        assert await requests.evaluate("el => getComputedStyle(el).animationName") == 'none'
        assert await requests.evaluate("el => getComputedStyle(el).color") == 'rgb(120, 113, 108)'
        await page.get_by_label('Message', exact=True).fill('escalation fixture')
        await page.get_by_role('button', name='Send', exact=True).click()
        pending = page.get_by_role('button', name='Escalation requests: 1 pending', exact=True)
        await pending.wait_for()
        assert not (state / 'escalation-executed.json').exists()
        assert await pending.evaluate("el => getComputedStyle(el).animationName") == 'escalation-pulse'
        await page.emulate_media(reduced_motion='reduce')
        assert await pending.evaluate("el => getComputedStyle(el).animationName") == 'none'
        await pending.click()
        request_list = page.get_by_role('dialog')
        summary = request_list.locator('.escalation-summary').first
        await summary.wait_for()
        assert await request_list.get_by_role('button', name='Approve', exact=True).count() == 0
        assert await request_list.get_by_role('button', name='Dismiss', exact=True).count() == 0
        assert await request_list.get_by_text('updateVirtualMachine', exact=True).count() == 0
        summary = request_list.locator('.escalation-summary').first
        lines = summary.locator('.truncate')
        assert await lines.count() == 2
        assert await lines.evaluate_all("els => els.every(el => getComputedStyle(el).whiteSpace === 'nowrap' && getComputedStyle(el).textOverflow === 'ellipsis' && el.scrollWidth > el.clientWidth)")
        assert await lines.first.evaluate("el => Number(getComputedStyle(el).fontWeight) >= 700")
        assert await lines.evaluate_all("els => parseFloat(getComputedStyle(els[0]).fontSize) > parseFloat(getComputedStyle(els[1]).fontSize)")
        await summary.focus()
        await summary.press('Enter')
        dialog = page.get_by_role('dialog').last
        await dialog.get_by_text('Goal: Rename the research VM so the owner can identify the production analysis workspace', exact=True).wait_for()
        await dialog.get_by_text('Permission needed: My current CloudStack account cannot update this VM because its native role does not allow updateVirtualMachine', exact=True).wait_for()
        await dialog.get_by_text('updateVirtualMachine', exact=True).wait_for()
        assert await dialog.get_by_text('Goal: Rename the research VM so the owner can identify the production analysis workspace', exact=True).evaluate(
            "el => getComputedStyle(el).whiteSpace === 'pre-wrap'")
        assert json.loads(await dialog.locator('.font-mono.text-xs').text_content()) == {
            'id': '00000000-0000-0000-0000-000000000004', 'name': 'Research revised'}
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        await page.screenshot(path=str(state / 'escalation-pending-mobile.png'), full_page=True, animations='disabled')
        await page.get_by_role('button', name='Approve', exact=True).click()
        await page.get_by_text('Approved', exact=True).wait_for()
        executed = json.loads((state / 'escalation-executed.json').read_text())
        assert executed == {'command': 'updateVirtualMachine', 'params': {
            'id': '00000000-0000-0000-0000-000000000004', 'name': 'Research revised'}}
        await dialog.get_by_role('button', name='Back to requests', exact=True).click()
        await page.get_by_role('button', name='Close', exact=True).click()
        await page.get_by_text('Escalation result available.', exact=True).wait_for()
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await page.get_by_text('Escalation result available.', exact=True).wait_for()
        await page.get_by_role('button', name='New conversation', exact=True).click()
        await page.get_by_label('Message', exact=True).fill('escalation fixture')
        await page.get_by_role('button', name='Send', exact=True).click()
        await pending.wait_for()
        await pending.click()
        summary = page.get_by_role('dialog').locator('.escalation-summary').first
        await summary.focus()
        await summary.press('Space')
        dialog = page.get_by_role('dialog').last
        await dialog.get_by_role('button', name='Dismiss', exact=True).click()
        await dialog.get_by_text('Dismissed', exact=True).wait_for()
        await dialog.get_by_role('button', name='Back to requests', exact=True).click()
        await page.get_by_role('button', name='Close', exact=True).click()
        await page.get_by_text('Escalation declined', exact=True).wait_for()
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        declined = store.one("SELECT * FROM escalation_requests WHERE status='deferred'")
        assert not declined['delivery_run_id']
        store.execute('UPDATE agents SET escalation_requests_enabled=0 WHERE id=?', (APP_ROOT_AGENT,))
        await open_configuration(page)
        toggle = page.get_by_role('checkbox', name='Request permission escalation', exact=True)
        await playwright.expect(toggle).to_be_disabled()
        await playwright.expect(toggle).not_to_be_checked()
        assert store.one("SELECT escalation_requests_enabled FROM agents WHERE id='research'")['escalation_requests_enabled'] == 1
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        await page.screenshot(path=str(state / 'escalation-mobile.png'), full_page=True, animations='disabled')
        await browser.close()


@pytest.mark.parametrize('width,height', [(1440, 900), (390, 844)])
async def test_sidebar_hierarchy_selector_and_vm_terminal_pane(browser_app, width, height):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': width, 'height': height})
        page = await context.new_page()
        await login(page, url)

        # Open drawer if search/hierarchy is hidden
        await open_sidebar(page)
        search = page.get_by_label('Search agents and domains', exact=True)

        # Check sidebar selector exists
        sidebar_select = page.locator('.q-drawer .sidebar-view-select')
        await sidebar_select.wait_for()
        await playwright.expect(sidebar_select).not_to_have_class(re.compile(r'.*q-field--disabled.*'))

        # Check alias switch is initially hidden
        alias_switch = page.locator('.q-drawer .sidebar-show-aliases')
        assert not await alias_switch.is_visible()

        # Open sidebar selector menu to select "VMs" (both Agents and VMs selected)
        await sidebar_select.click()
        await page.get_by_role('option', name='VMs', exact=True).click()
        await page.wait_for_timeout(300)
        await page.keyboard.press('Escape')

        # Alias toggle is now visible
        await alias_switch.wait_for()

        # Under Research Admin, research-vm should be visible
        vm_node = page.locator('.q-drawer').get_by_text('research-vm', exact=True)
        await vm_node.wait_for()

        # Toggle Show aliases on: VM label changes to displayname
        await alias_switch.click()
        alias_node = page.locator('.q-drawer').get_by_text('Research Worker', exact=True)
        await alias_node.wait_for()
        assert not await vm_node.is_visible()

        # Toggle Show aliases off: reverts to name
        await alias_switch.click()
        await vm_node.wait_for()
        assert not await alias_node.is_visible()

        # Switch to "VMs" only mode by deselecting Agents
        await sidebar_select.click()
        agents_opt = page.get_by_role('option', name='Agents', exact=True)
        await agents_opt.wait_for()
        await agents_opt.click()
        await page.wait_for_timeout(300)
        await page.keyboard.press('Escape')

        # In VMs mode, research-vm is still visible and alias switch remains visible
        await vm_node.wait_for()
        assert await alias_switch.is_visible()

        # Enforce at least one selected: try deselecting VMs (the last selected item)
        await sidebar_select.click()
        vms_opt = page.get_by_role('option', name='VMs', exact=True)
        await vms_opt.wait_for()
        await vms_opt.click()
        await page.wait_for_timeout(300)
        await page.keyboard.press('Escape')

        # VMs remains selected, research-vm still visible
        await vm_node.wait_for()

        # The selected view and aliases survive a full page reload.
        await alias_switch.click()
        await alias_node.wait_for()
        await page.reload()
        await playwright.expect(sidebar_select).not_to_have_class(re.compile(r'.*q-field--disabled.*'))
        await page.get_by_role('button', name='Agent details', exact=True).wait_for()
        if not await search.is_visible():
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await alias_node.wait_for()
        await playwright.expect(alias_switch).to_have_attribute('aria-checked', 'true')
        await playwright.expect(sidebar_select).to_contain_text('VMs')
        await playwright.expect(sidebar_select).not_to_contain_text('Agents')
        await alias_switch.click()
        await vm_node.wait_for()

        await page.reload()
        await playwright.expect(sidebar_select).not_to_have_class(re.compile(r'.*q-field--disabled.*'))
        await page.get_by_role('button', name='Agent details', exact=True).wait_for()
        if not await search.is_visible():
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await vm_node.wait_for()
        await playwright.expect(alias_switch).to_have_attribute('aria-checked', 'false')
        # Persist Agents alone, then both views, while retaining aliases off.
        for option, expected in [('Agents', ('Agents', 'VMs')), ('VMs', ('Agents',)),
                                 ('VMs', ('Agents', 'VMs'))]:
            await sidebar_select.click()
            await page.get_by_role('option', name=option, exact=True).click()
            await page.keyboard.press('Escape')
            await page.wait_for_function(
                'expected => JSON.stringify(JSON.parse(localStorage.getItem("dirigentenstab.sidebar.'
                '00000000-0000-0000-0000-000000000003")).view.sort()) === JSON.stringify(expected.sort())',
                arg=list(expected))
            await page.reload()
            await playwright.expect(sidebar_select).not_to_have_class(re.compile(r'.*q-field--disabled.*'))
            await page.get_by_role('button', name='Agent details', exact=True).wait_for()
            if not await search.is_visible():
                await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
            for label in expected:
                await playwright.expect(sidebar_select).to_contain_text(label)
            if expected == ('Agents',):
                await playwright.expect(alias_switch).not_to_be_visible()
            else:
                await playwright.expect(alias_switch).to_have_attribute('aria-checked', 'false')
        await vm_node.wait_for()

        # Click the VM node to open terminal pane
        await vm_node.click()

        # Terminal pane should be visible
        terminal_pane = page.locator('.terminal-pane')
        await terminal_pane.wait_for()

        # Terminal status should indicate connection attempt / status
        status = page.locator('.terminal-pane [role="status"]').filter(visible=True)
        await status.wait_for()

        # Terminal controls visible
        await page.locator('.terminal-pane').get_by_role('button', name='Reconnect', exact=True).wait_for()
        await page.locator('.terminal-pane').get_by_role('button', name='Disconnect', exact=True).wait_for()

        # With the keyboard open (smaller visualViewport) the xterm container fits above it and refits.
        rows = 'document.querySelectorAll(".terminal-container .xterm-rows > div").length'
        await page.wait_for_function(f'{rows} > 0')
        full_rows = await page.evaluate(rows)
        await page.evaluate('''() => {
            Object.defineProperty(visualViewport,'height',{configurable:true,get:()=>480});
            visualViewport.dispatchEvent(new Event('resize'));
        }''')
        await page.wait_for_function(f'{rows} < {full_rows}')
        small_rows = await page.evaluate(rows)
        box = await page.locator('.terminal-container').bounding_box()
        assert box and box['y'] >= 0 and box['y'] + box['height'] <= 480
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        await page.evaluate("delete visualViewport.height;visualViewport.dispatchEvent(new Event('resize'))")
        await page.wait_for_function(f'{rows} > {small_rows}')

        frame = page.locator('iframe[title="VM console"]')
        (state / 'console-error').touch()
        await terminal_pane.get_by_role('button', name='Console', exact=True).click()
        await terminal_pane.get_by_text('Console unavailable', exact=True).wait_for()
        await terminal_pane.get_by_text('Console unavailable: Console fixture denied', exact=True).wait_for()
        (state / 'console-error').unlink()
        await terminal_pane.get_by_role('button', name='Reconnect', exact=True).click()
        await playwright.expect(frame).to_have_attribute('src', re.compile(r'^/vm-console/[^/]+/vnc.html\?'))
        embedded_url = await frame.get_attribute('src')
        response = await context.request.get(url + embedded_url)
        assert response.status == 200
        assert response.headers['x-frame-options'] == 'SAMEORIGIN'
        assert 'ticket-2' not in embedded_url
        await frame.content_frame.get_by_text('Connected through console proxy', exact=True).wait_for()
        box = await frame.bounding_box()
        assert box and box['height'] > 300 and box['width'] <= width
        await page.screenshot(path=str(state / f'console-{width}x{height}.png'), full_page=True)
        async with page.expect_popup() as popup_info:
            await terminal_pane.get_by_role('button', name='Open console in new tab', exact=True).click()
        popup = await popup_info.value
        await popup.wait_for_load_state()
        assert popup.url.startswith(url + '/vm-console/') and popup.url != url + embedded_url
        await popup.get_by_text('Connected through console proxy', exact=True).wait_for()
        await popup.close()
        await playwright.expect(frame).to_have_attribute('src', 'about:blank')

        # Disconnect invalidates a pending endpoint, including a request for the same VM.
        (state / 'console-delay').touch()
        await terminal_pane.get_by_role('button', name='Reconnect', exact=True).click()
        await terminal_pane.get_by_text('Opening console: research-vm…', exact=True).wait_for()
        await terminal_pane.get_by_role('button', name='Disconnect', exact=True).click()
        await terminal_pane.get_by_text('Console closed', exact=True).wait_for()
        await playwright.expect(frame).to_have_attribute('src', 'about:blank')
        (state / 'console-delay').unlink()
        await terminal_pane.get_by_role('button', name='Reconnect', exact=True).click()
        await frame.content_frame.get_by_text('Connected through console proxy', exact=True).wait_for()
        reconnected_url = await frame.get_attribute('src')
        assert reconnected_url != embedded_url
        await page.wait_for_timeout(1100)
        await playwright.expect(frame).to_have_attribute('src', reconnected_url)
        # A dropped console shows Reconnect, and reconnecting uses a fresh single-use ticket.
        await (await (await frame.element_handle()).content_frame()).evaluate("ws.send('close-now')")
        await terminal_pane.get_by_text('Console disconnected', exact=True).wait_for()
        await playwright.expect(frame).to_have_attribute('src', 'about:blank')
        await terminal_pane.get_by_role('button', name='Reconnect', exact=True).click()
        await frame.content_frame.get_by_text('Connected through console proxy', exact=True).wait_for()
        assert await frame.get_attribute('src') not in (embedded_url, reconnected_url)
        assert 'reconnect=false' in await frame.get_attribute('src')
        await terminal_pane.get_by_role('button', name='SSH', exact=True).click()
        await playwright.expect(frame).to_have_attribute('src', 'about:blank')
        await playwright.expect(frame).not_to_be_visible()
        await terminal_pane.get_by_role('button', name='Console', exact=True).click()
        await frame.content_frame.get_by_text('Connected through console proxy', exact=True).wait_for()
        # Selecting an agent tears down the iframe, even without using Close.
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await search.fill('Research Admin')
        await page.locator('.q-tree').get_by_text('Research Admin', exact=True).click()
        await search.wait_for(state='hidden')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await playwright.expect(page.locator('.q-tree')).not_to_have_attribute('aria-disabled', 'true')
        await page.get_by_label('Message', exact=True).wait_for()
        await playwright.expect(frame).to_have_attribute('src', 'about:blank')
        await playwright.expect(terminal_pane).not_to_be_visible()
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await search.fill('research-vm')
        await vm_node.click()
        await terminal_pane.wait_for()

        # Verify zero horizontal overflow on both desktop and mobile
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')

        # Reopening a VM retains SSH as the default; closing an active console tears it down.
        await page.locator('.terminal-container').wait_for()
        await playwright.expect(frame).not_to_be_visible()
        await terminal_pane.get_by_role('button', name='Console', exact=True).click()
        await frame.content_frame.get_by_text('Connected through console proxy', exact=True).wait_for()
        # Close terminal pane to return to chat
        await page.locator('.terminal-pane').get_by_role('button', name='Close terminal', exact=True).click()
        await page.get_by_label('Message', exact=True).wait_for()
        await playwright.expect(terminal_pane).not_to_be_visible()
        await playwright.expect(frame).to_have_attribute('src', 'about:blank')

        # Verify zero horizontal overflow again
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        await browser.close()


@pytest.mark.parametrize('width', [390, 1440])
async def test_sidebar_skills_editor_sharing_and_revision_approval(browser_app, width):
    url, state = browser_app
    from dirigentenstab.store import Store

    store = Store(str(state / 'browser.db'), str(state / 'master'))
    existing_text = 'Existing agent-created skill instructions, loaded only when opened.'
    store.execute('INSERT INTO skills(id,creator_agent_id,name,description,text,created,updated) VALUES(?,?,?,?,?,?,?)',
                  ('existing-skill', 'research', 'Existing research skill', 'Existing skill summary',
                   store.seal(existing_text), 1, 1))
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': width, 'height': 844})
        page = await context.new_page()
        await login(page, url)
        search = page.get_by_label('Search agents and domains', exact=True)
        if not await search.is_visible():
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        sidebar = page.locator('.q-drawer .sidebar-view-select')
        await playwright.expect(sidebar).not_to_have_class(re.compile(r'.*q-field--disabled.*'))
        async def select_views(expected):
            if not await search.is_visible():
                await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
            current = await page.evaluate(
                'JSON.parse(localStorage.getItem("dirigentenstab.sidebar.00000000-0000-0000-0000-000000000003"))?.view || ["Agents"]')
            await sidebar.click()
            for option in ('Agents', 'VMs', 'Skills'):
                if (option in current) != (option in expected):
                    await page.get_by_role('option', name=option, exact=True).click()
                    current = [item for item in current if item != option] if option in current else current + [option]
                    await page.wait_for_function(
                        'expected => JSON.stringify(JSON.parse(localStorage.getItem("dirigentenstab.sidebar.00000000-0000-0000-0000-000000000003"))?.view.sort()) === JSON.stringify(expected.sort())',
                        arg=current)
            await page.keyboard.press('Escape')

        assert existing_text not in await page.content()
        views_to_check = [['Agents', 'Skills'], ['Skills']] if width == 1440 else [
            ['Agents', 'Skills'], ['VMs', 'Skills'], ['Skills'], ['Agents', 'VMs', 'Skills']]
        for index, views in enumerate(views_to_check):
            await select_views(views)
            existing = page.locator('.q-tree').get_by_text('Existing research skill', exact=True)
            await existing.wait_for()
            assert 'Research Admin' in await existing.evaluate(
                "el => el.closest('.q-tree__node').parentElement.closest('.q-tree__node').querySelector('.q-tree__node-header').innerText")
            await existing.click()
            await playwright.expect(page.get_by_label('Full text', exact=True)).to_have_value(existing_text)
            await page.get_by_role('dialog').get_by_role('button', name='Close', exact=True).click()
            await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
            await existing.click()
            existing_text += f' Edit {index}.'
            await page.get_by_label('Full text', exact=True).fill(existing_text)
            await page.get_by_role('button', name='Save skill', exact=True).click()
            await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
            assert store.open(store.one("SELECT text FROM skills WHERE id='existing-skill'")['text']) == existing_text
        await select_views(['Skills'])
        await page.screenshot(path=str(state / 'skills-hierarchy.png'), full_page=True, animations='disabled')
        await page.get_by_role('button', name='New skill', exact=True).click()
        await page.get_by_label('Skill name', exact=True).fill('GPU checklist')
        await page.get_by_label('Short description', exact=True).fill('Prepare a GPU VM')
        full_text = 'Detailed private checklist: inspect available profiles before deployment.'
        await page.get_by_label('Full text', exact=True).fill(full_text)
        await page.get_by_role('button', name='Save skill', exact=True).click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        await page.reload()
        await playwright.expect(sidebar).not_to_have_class(re.compile(r'.*q-field--disabled.*'))
        assert full_text not in await page.content()
        if not await search.is_visible():
            await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await playwright.expect(sidebar).to_contain_text('Skills')
        await playwright.expect(sidebar).not_to_contain_text('Agents')
        await page.locator('.q-tree').get_by_text('GPU checklist', exact=True).click()
        await playwright.expect(page.get_by_label('Full text', exact=True)).to_have_value(full_text)
        sharing = page.get_by_label('Share with children', exact=True)
        await sharing.click()
        await page.get_by_role('option', name='Research Admin', exact=True).click()
        await page.keyboard.press('Escape')
        await page.get_by_role('button', name='Save skill', exact=True).click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.locator('.q-tree').get_by_text('GPU checklist', exact=True).click()
        await playwright.expect(sharing).to_have_value('Research Admin')
        await page.get_by_role('button', name='Approve global sharing', exact=True).click()
        review = page.get_by_role('dialog').filter(has=page.get_by_role('button', name='Approve', exact=True))
        await playwright.expect(review.get_by_text(full_text, exact=True)).to_be_visible()
        await review.get_by_role('button', name='Approve', exact=True).click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.locator('.q-tree').get_by_text('GPU checklist', exact=True).click()
        await page.get_by_text('This revision is shared globally. Editing requires approval again.', exact=True).wait_for()
        await page.get_by_label('Full text', exact=True).fill(full_text + ' Updated.')
        await page.get_by_role('button', name='Save skill', exact=True).click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.locator('.q-tree').get_by_text('GPU checklist', exact=True).click()
        await page.get_by_role('button', name='Approve global sharing', exact=True).wait_for()
        assert await page.get_by_text('This revision is shared globally. Editing requires approval again.', exact=True).count() == 0
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        await page.screenshot(path=str(state / 'skills-editor.png'), full_page=True, animations='disabled')
        editor = page.get_by_role('dialog')
        await editor.get_by_role('button', name='Delete', exact=True).click()
        await page.get_by_role('button', name='Cancel', exact=True).click()
        await playwright.expect(editor).to_have_count(1)
        assert store.one("SELECT 1 FROM skills WHERE name='GPU checklist'")
        await editor.get_by_role('button', name='Delete', exact=True).click()
        confirm = page.get_by_role('dialog').filter(has=page.get_by_role('button', name='Cancel', exact=True))
        await confirm.get_by_role('button', name='Delete', exact=True).click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        assert not store.one("SELECT 1 FROM skills WHERE name='GPU checklist'")
        await browser.close()


async def test_browser_chat_autoscroll_setting_persists_and_controls_tool_updates(browser_app):
    url, _ = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        await select_agent(page, 'Research Admin')
        message = page.get_by_label('Message', exact=True)
        await message.fill('markdown stress')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.locator('.messages table').wait_for()
        await playwright.expect(page.get_by_role('button', name='Send', exact=True)).to_be_visible()
        scroll = page.locator('.messages .q-scrollarea__container')
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_role('button', name='Settings', exact=True).click()
        toggle = page.get_by_role('switch', name='Chat autoscroll', exact=True)
        await playwright.expect(toggle).to_be_checked()
        await toggle.click()
        await playwright.expect(toggle).not_to_be_checked()
        await page.keyboard.press('Escape')
        await page.reload()
        await page.wait_for_function('window.socket?.connected && window.did_handshake')
        await page.get_by_role('button', name='Agent details', exact=True).get_by_text('Research Admin', exact=True).wait_for()
        await page.locator('.messages table').wait_for()
        await ensure_navigation_open(page)
        await page.get_by_role('button', name='Settings', exact=True).click()
        await playwright.expect(toggle).not_to_be_checked()
        await page.keyboard.press('Escape')
        await page.get_by_role('button', name='Close agent hierarchy', exact=True).click()
        await scroll.evaluate('el => el.scrollTop = 100')
        await message.fill('Inspect resources')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        assert await page.get_by_text('execute_api · Completed', exact=False).count() >= 1
        assert abs(await scroll.evaluate('el => el.scrollTop') - 100) < 5
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_role('button', name='Settings', exact=True).click()
        await toggle.click()
        await playwright.expect(toggle).to_be_checked()
        await page.keyboard.press('Escape')
        await page.get_by_role('button', name='Close agent hierarchy', exact=True).click()
        await message.fill('Inspect resources again')
        await page.get_by_role('button', name='Send', exact=True).click()
        await playwright.expect(page.get_by_role('button', name='Send', exact=True)).to_be_visible()
        await page.wait_for_function("""() => { const el = document.querySelector('.messages .q-scrollarea__container');
            return el.scrollTop > 100 && el.scrollHeight - el.clientHeight - el.scrollTop < 5; }""")
        await browser.close()


async def test_browser_autoscroll_off_keeps_position_when_declined_notice_shifts_history(browser_app):
    url, state = browser_app
    from dirigentenstab.store import Store

    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        await select_agent(page, 'Research Admin')
        message = page.get_by_label('Message', exact=True)
        await message.fill('markdown stress')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.locator('.messages table').wait_for()
        await playwright.expect(page.get_by_role('button', name='Send', exact=True)).to_be_visible()
        await page.get_by_role('button', name='Open agent hierarchy', exact=True).click()
        await page.get_by_role('button', name='Settings', exact=True).click()
        await page.get_by_role('switch', name='Chat autoscroll', exact=True).click()
        await page.keyboard.press('Escape')
        await page.get_by_role('button', name='Close agent hierarchy', exact=True).click()
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        conversation = store.one('SELECT * FROM conversations ORDER BY created DESC')
        run = store.one('SELECT * FROM chat_runs WHERE conversation_id=?', (conversation['id'],))
        now = int(time.time())
        store.execute('INSERT INTO escalation_requests (id,agent_id,conversation_id,run_id,call_id,human_id,command,description,'
                      "reason,params,status,created,updated) VALUES('declined-scroll','research',?,?,'none',?,'x','x','x',?,'deferred',?,?)",
                      (conversation['id'], run['id'], conversation['human_id'], store.seal({}), now, now))
        scroll = page.locator('.messages .q-scrollarea__container')
        await scroll.evaluate('el => el.scrollTop = 100')
        await page.get_by_text('Escalation declined', exact=True).wait_for()
        assert abs(await scroll.evaluate('el => el.scrollTop') - 100) < 5
        await message.fill('Inspect resources')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        await page.wait_for_timeout(500)
        assert abs(await scroll.evaluate('el => el.scrollTop') - 100) < 5
        await browser.close()


async def test_browser_escalation_notice_sits_at_request_and_waiting_is_not_thinking(browser_app):
    url, state = browser_app
    from dirigentenstab.store import Store

    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(ignore_https_errors=True, viewport={'width': 1440, 'height': 900})
        await login(page, url)
        await select_agent(page, 'Research Admin')
        message = page.get_by_label('Message', exact=True)
        await message.fill('Inspect resources')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        store = Store(str(state / 'browser.db'), str(state / 'master'))
        conversation = store.one('SELECT * FROM conversations ORDER BY created DESC')
        run = store.one('SELECT * FROM chat_runs WHERE conversation_id=?', (conversation['id'],))
        call_id = next(e['call_id'] for e in store.open(run['events']) if e['type'] == 'tool_call')
        now = int(time.time())
        for request_id, status, call in (('approved-inline', 'approved', call_id), ('pending-inline', 'pending', 'other')):
            store.execute('INSERT INTO escalation_requests (id,agent_id,conversation_id,run_id,call_id,human_id,command,description,'
                          'reason,params,status,created,updated) VALUES(?,\'research\',?,?,?,?,\'x\',\'x\',\'x\',?,?,?,?)',
                          (request_id, conversation['id'], run['id'], call, conversation['human_id'], store.seal({}),
                           status, now, now))
        notice = page.get_by_text('Escalation approved', exact=True)
        await notice.wait_for()
        order = await page.evaluate("""() => [...document.querySelectorAll('.messages .q-expansion-item, .messages [role=status], .messages .q-message')]
            .map(el => el.textContent.trim())""")
        assert order.index('Escalation approved') == len(order) - 2 and order[-1].endswith('The research VM is running.'), order
        store.execute("UPDATE chat_runs SET status='running' WHERE id=?", (run['id'],))
        await page.get_by_text('Waiting for your decision on an escalation request', exact=True).wait_for()
        assert await page.get_by_text('Thinking…', exact=True).count() == 0
        store.execute("UPDATE escalation_requests SET status='deferred',updated=? WHERE id='pending-inline'", (now + 1,))
        await page.get_by_text('Thinking…', exact=True).wait_for()
        await browser.close()


@pytest.mark.parametrize('width,height', [(1440, 900), (390, 844)])
async def test_browser_reload_restores_open_agent_vm_mode_and_skill(browser_app, width, height):
    url, state = browser_app
    from dirigentenstab.store import Store

    store = Store(str(state / 'browser.db'), str(state / 'master'))
    store.execute('INSERT INTO skills(id,creator_agent_id,name,description,text,created,updated) VALUES(?,?,?,?,?,?,?)',
                  ('restore-skill', 'research', 'Restorable skill', 'Summary', store.seal('Restorable skill text'), 1, 1))
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': width, 'height': height})
        page = await context.new_page()
        await login(page, url)
        heading = page.get_by_role('button', name='Agent details', exact=True)
        pane = page.locator('.terminal-pane')
        frame = page.locator('iframe[title="VM console"]')

        async def reloaded():
            await page.reload()
            await page.wait_for_function('window.socket?.connected && window.did_handshake')

        async def open_node(label):
            search = page.get_by_label('Search agents and domains', exact=True)
            await ensure_navigation_open(page)
            await playwright.expect(page.locator('.q-drawer .sidebar-view-select')).not_to_have_class(
                re.compile(r'.*q-field--disabled.*'))
            await search.fill(label)
            await page.locator('.q-tree').get_by_text(label, exact=True).click()

        # A non-default agent and its open conversation come back after a reload.
        await select_agent(page, 'Research Admin')
        await page.get_by_label('Message', exact=True).fill('Restored conversation')
        await page.get_by_role('button', name='Send', exact=True).click()
        await page.get_by_text('Infrastructure checked. The research VM is running.', exact=True).wait_for()
        await page.wait_for_function('location.search === "?agent=research"')
        await reloaded()
        await heading.get_by_text('Research Admin', exact=True).wait_for()
        await page.locator('.q-message').get_by_text('Restored conversation', exact=True).wait_for()

        # A bogus id falls back to the default agent without an error toast.
        await page.goto(url + '/?agent=nope')
        await heading.get_by_text('Main Agent', exact=True).wait_for()
        assert await page.locator('.q-notification').count() == 0

        # Show every sidebar view, then open the VM in SSH and Console mode.
        await page.evaluate(
            'localStorage.setItem("dirigentenstab.sidebar.00000000-0000-0000-0000-000000000003", '
            'JSON.stringify({view: ["Agents", "VMs", "Skills"], aliases: false}))')
        await reloaded()
        await open_node('research-vm')
        await pane.wait_for()
        await page.wait_for_function('/^\\?vm=[^&]+&mode=ssh$/.test(location.search)')
        vm_query = await page.evaluate('location.search')
        await reloaded()
        await pane.wait_for()
        await playwright.expect(frame).not_to_be_visible()
        await page.locator('.terminal-container').wait_for()
        await pane.get_by_role('button', name='Console', exact=True).click()
        await page.wait_for_function('location.search.endsWith("&mode=console")')
        await reloaded()
        await pane.wait_for()
        await playwright.expect(frame).to_have_attribute('src', re.compile(r'^/vm-console/'))
        assert await page.evaluate('location.search') == vm_query.replace('mode=ssh', 'mode=console')
        assert 'ticket' not in await page.evaluate('location.href')

        # An open skill editor comes back too; closing it returns the URL to the main pane target.
        await open_node('Restorable skill')
        await playwright.expect(page.get_by_label('Full text', exact=True)).to_have_value('Restorable skill text')
        await page.wait_for_function('location.search === "?skill=restore-skill"')
        await reloaded()
        await playwright.expect(page.get_by_label('Full text', exact=True)).to_have_value('Restorable skill text')
        await page.get_by_role('dialog').get_by_role('button', name='Close', exact=True).click()
        await playwright.expect(page.get_by_role('dialog')).to_have_count(0)
        await page.wait_for_function('/^\\?agent=[^&]+$/.test(location.search)')
        assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
        await browser.close()


async def test_browser_platform_banner_shows_issues_when_fresh_and_unhealthy(browser_app):
    url, state = browser_app
    now = time.time()
    (state / 'platform-status.json').write_text(json.dumps({
        'version': 1, 'updated': now, 'healthy': False, 'hosts': [], 'issues': ['host kvm1 Disconnected']}))
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        page = await (await browser.new_context(ignore_https_errors=True)).new_page()
        await login(page, url)
        banner = page.locator('.whitespace-pre-line.shadow')
        await playwright.expect(banner).to_have_text('host kvm1 Disconnected')
        (state / 'platform-status.json').write_text(json.dumps({'version': 1, 'updated': now - 900, 'healthy': False}))
        await playwright.expect(banner).to_have_text('Platform status unavailable', timeout=15000)
        await browser.close()


async def test_browser_sidebar_tree_geometry_selection_and_overflow(browser_app):
    url, _ = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        for width, height in [(1440, 900), (390, 844)]:
            page = await browser.new_page(ignore_https_errors=True, viewport={'width': width, 'height': height})
            await login(page, url)
            await ensure_navigation_open(page)
            tree = page.locator('.q-tree')
            for _ in range(100):
                arrow = tree.locator('.q-tree__arrow:not(.q-tree__arrow--rotate)')
                if not await arrow.count():
                    break
                await arrow.first.click()
            # Icon x of every header, grouped by sibling list, with its parent's icon x.
            groups = await tree.evaluate('''el => {
                const x = node => node.querySelector(':scope > .q-tree__node-header .q-icon:not(.q-tree__arrow)').getBoundingClientRect().x;
                const siblings = list => [...list.children].filter(n => n.classList.contains('q-tree__node'));
                const out = [{parent: null, xs: siblings(el).map(x)}];
                el.querySelectorAll('.q-tree__children').forEach(c =>
                    out.push({parent: x(c.closest('.q-tree__node')), xs: siblings(c).map(x)}));
                return out;
            }''')
            assert len(groups) > 3
            for group in groups:
                assert max(group['xs']) - min(group['xs']) <= 2, group
                if group['parent'] is not None:
                    assert min(group['xs']) > group['parent'], group
            selected = tree.locator('.q-tree__node-header.q-tree__node--selected')
            await playwright.expect(selected).to_have_count(1)
            await playwright.expect(selected).to_contain_text('Main Agent')
            assert await tree.locator('.q-tree__node-header-content').first.evaluate('el => getComputedStyle(el).opacity') == '1'
            scroll = page.locator('.q-drawer .q-scrollarea__container')
            assert await scroll.evaluate('el => el.scrollWidth <= el.clientWidth')
            assert await page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
            await page.close()
        await browser.close()
