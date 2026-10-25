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

The Python tests cover credential encryption, API validation, permissions, provisioning recovery, SSH host-key checks, bounded transfers, conversations, delegation and UI callbacks. MCP checks cover explicit inherited tool assignments, administration scope, revocation, credential protection and endpoint validation, with real SDK protocol exchanges through a local HTTP mock transport; GUI checks save per-agent system prompts. Tests use local fakes where external infrastructure is unnecessary. These checks do not establish that a CloudStack zone can boot a VM.

Migration tests cover source-path and symlink boundaries, credential quarantine, archive checksums, resumable history import and isolation of imported transcripts from new model requests. Real migration additionally verifies every restored workspace file and stream-decrypts the original history archives to compare byte counts and hashes; private migration artifacts are never CI fixtures.

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
sudo .venv/bin/python scripts/live_acceptance.py --run
sudo .venv/bin/python scripts/gpu_acceptance.py --run
```

Native service verification, the CI browser fixture and actual infrastructure acceptance are distinct checks. Real acceptance requires a live CloudStack KVM host and VMs: create/start a VM using an agent identity, run Python through its pinned SSH identity, inspect a deliberately failing command, upload/download a file, and reject access from an unrelated domain. Record the actual outputs and resource identities privately; publish only a sanitized result. Never report the browser fixture or unit mocks as real KVM acceptance.

The acceptance script creates two durably tracked private VMs under the Research and Development agents and retains them for inspection. It verifies non-root guest execution without default sudo or host sockets, file round trips, unrelated-domain denial and rejection of host-only API/configuration. It never submits a second deployment after an ambiguous result; use `scripts/admin.py status` and `recover-deployments` first. The private resume/report file is `/var/lib/dirigentenstab/setup/live-acceptance.json`.

`.github/workflows/live.yaml` supports an explicit manual run on a trusted, dedicated self-hosted test runner labeled `dirigentenstab-acceptance`. Configure the `private-cloud-acceptance` environment and its `DIRIGENTENSTAB_INSTALL` variable to point at an already deployed test installation. The workflow runs only from main after the confirmation input is selected. It does not deploy code, run pull-request code, configure a runner automatically, or open the private API to GitHub-hosted runners. Ordinary CI integration tests use real local SSH/SFTP endpoints and synthetic infrastructure fixtures; this manual job uses actual CloudStack/KVM.

### Live portal smoke test, 2026-10-25

Chromium also tested the actual portal at its private local HTTPS endpoint on the Ubuntu 24.04 host, with native CloudStack 4.23.0.0 and the separately configured local Qwen inference provider. The live check passed CloudStack-backed login, Secure/HttpOnly/SameSite cookies, the real domain tree, direct agent selection, model configuration display and authenticated WebSocket handshakes.

The same live check passed through Tailscale Serve with normal browser certificate validation. Existing Serve routes were preserved; the added route is tailnet-only. No CloudStack API or guest SSH port was published.

A separate live Chromium check restored a nonempty imported legacy transcript, verified its read-only notice, sent a benign new prompt, and confirmed a new conversation with empty prior model history. The imported ciphertext remained unchanged, logout succeeded, and the browser reported no page errors. The check recorded counts and assertions without screenshots or private transcript text.

A new read-only conversation called `search_api` against the live catalogue and displayed streamed text plus tool activity. Reloading the portal restored that conversation, including its tool history. A database check confirmed the persisted messages were encrypted. The browser content and WebSocket frames were checked against the installation, agent and provider credentials without recording those credentials. Logout revoked the browser session. The browser reported no page errors. This portal check did not mutate infrastructure and is separate from the real VM/SSH acceptance described above.
