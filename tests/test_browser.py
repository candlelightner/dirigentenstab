"""Real Chromium + NiceGUI browser tests; infrastructure/model providers are CI fixtures."""

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
    await page.get_by_text('Select an agent to begin', exact=True).wait_for()
    await page.wait_for_function('window.socket?.connected && window.did_handshake')


async def test_browser_secure_login_direct_chat_history_provider_and_logout(browser_app):
    url, state = browser_app
    async with playwright.async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 900})
        page = await context.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        await login(page, url)
        cookie = next(cookie for cookie in await context.cookies() if cookie['name'] == 'ds_session')
        assert cookie['httpOnly'] and cookie['secure'] and cookie['sameSite'] == 'Strict'
        await page.get_by_label('Chat directly with an agent', exact=True).fill('Research')
        await page.get_by_role('option', name='Research Admin', exact=True).click()
        await page.get_by_text('Administrator account: research-account', exact=True).wait_for()
        await page.get_by_label('Message', exact=True).fill('Inspect the research VM')
        await page.get_by_role('button', name='Send', exact=True).click()
        output = 'Infrastructure checked. The research VM is running.'
        await page.get_by_text(output, exact=True).wait_for()
        await page.get_by_text('Tool activity', exact=True).first.click()
        assert await page.get_by_text('execute_api', exact=False).count() >= 1
        from scripts.browser_fixture import PRIVATE_VALUES
        content = await page.content()
        assert all(secret not in content for secret in PRIVATE_VALUES)
        await page.get_by_role('button', name='New conversation', exact=True).click()
        await page.get_by_label('Conversation', exact=True).fill('Inspect the research VM')
        await page.get_by_role('option', name='Inspect the research VM', exact=True).click()
        await page.get_by_text(output, exact=True).wait_for()
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
