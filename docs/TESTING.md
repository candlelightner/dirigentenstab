# Testing

The CI jobs run Python unit/integration checks and real Chromium browser checks separately. Neither job deploys to a production host.

Install the locked application dependencies and test tools:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock -e '.[test]'
python -m pytest -q -m 'not browser and not live'
ruff check .
```

The Python tests cover credential encryption, API validation, permissions, provisioning recovery, SSH host-key checks, bounded transfers, conversations, delegation and UI callbacks. Tests use local fakes where external infrastructure is unnecessary. These checks do not establish that a CloudStack zone can boot a VM.

## Real browser checks

```sh
python -m pip install -e '.[browser]'
python -m playwright install --with-deps --only-shell --no-remove chromium
python -m pytest -q -m browser tests/test_browser.py --basetemp=browser-results
```

The tests start a temporary HTTPS NiceGUI server on a loopback port and drive it with Chromium. They exercise the application's real CloudStack login code, encrypted server-side sessions, Secure/HttpOnly cookies, session-bound WebSockets, direct agent chat, Pydantic AI streaming and tools, conversation restoration, provider settings, responsive layout and logout. They also disable a CloudStack human after the socket is established and verify that the next action returns to login.

Only the CloudStack transport and model are fixtures in this test mode. `scripts/browser_fixture.py` refuses to start unless `DIRIGENTENSTAB_BROWSER_FIXTURE=1` is explicitly set. It creates a temporary database, synthetic credentials and a temporary TLS certificate. It does not access an existing CloudStack installation, hypervisor or model provider. Browser tests assert that synthetic infrastructure/provider keys and VM passwords are absent from browser content.

`.github/workflows/browser.yaml` installs Chromium explicitly and uploads desktop/mobile screenshots and the fixture's server log. A development environment without the optional Playwright package reports browser tests as skipped; the dedicated browser CI job must run them.

## Native acceptance

After installation, run:

```sh
sudo ./setup.sh --verify
```

Native service verification, the CI browser fixture and actual infrastructure acceptance are distinct checks. Real acceptance requires a live CloudStack KVM host and VMs: create/start a VM using an agent identity, run Python through its pinned SSH identity, inspect a deliberately failing command, upload/download a file, and reject access from an unrelated domain. Record the actual outputs and resource identities privately; publish only a sanitized result. Never report the browser fixture or unit mocks as real KVM acceptance.
