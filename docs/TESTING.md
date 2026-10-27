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

The Python tests cover credential encryption, API validation, permissions, provisioning recovery, SSH host-key checks, bounded transfers, independent conversations, detached execution and UI callbacks. MCP checks cover explicit inherited tool assignments, administration scope, revocation, credential protection and endpoint validation, with real SDK protocol exchanges through a local HTTP mock transport; GUI checks save per-agent system prompts, discover MCP tools without assigning them automatically, and retain selected tools after reload or discovery failure. Tests use local fakes where external infrastructure is unnecessary. These checks do not establish that a CloudStack zone can boot a VM.

Runtime tests exercise real Pydantic AI tool exchanges with local model fixtures: accepted work survives browser cancellation without retaining the human session; same-agent conversations run independently; new messages and Stop stay scoped; restart resumes active work but preserves owner stops and agent pauses; saved uncertain calls are not replayed; inspection and an explicit model retry can continue recovery. A 65-tool chain verifies that former task caps no longer pause work. Configuration tests cover both externally initiated changes and an agent changing its own prompt through a real tool call. Compaction tests retain the complete encrypted archive across turns while using the selected summary model.

Migration tests cover source-path and symlink boundaries, credential quarantine, archive checksums, resumable history import and isolation of imported transcripts from new model requests. Real migration additionally verifies every restored workspace file and stream-decrypts the original history archives to compare byte counts and hashes; private migration artifacts are never CI fixtures.

Guest forwarding tests verify native security-group references, source-IP checks before DHCP exceptions, unknown-port denial, atomic updates without flushing shared tables, idempotence and stale-VM removal. The live firewall repair on 2026-10-25 verified pinned non-root SSH, DNS and HTTP/HTTPS Ubuntu repository metadata from both existing builders; a TCP/25 attempt on the builder with restricted egress still hit its native-policy drop. No VM, application or native service restart was needed for this repair.

## Real browser checks

```sh
python -m pip install -e '.[browser]'
python -m playwright install --with-deps --only-shell --no-remove chromium
python -m pytest -q -m browser tests/test_browser.py -n 2 --timeout=120 --basetemp=browser-results
```

The tests start a temporary HTTPS NiceGUI server on a loopback port and drive it with Chromium. They exercise the application's real CloudStack login code, encrypted server-side sessions, Secure/HttpOnly cookies, session-bound WebSockets, direct agent chat, Pydantic AI streaming and tools, conversation restoration, provider settings, responsive layout and logout. They also disable a CloudStack human after the socket is established and verify that the next action returns to login.

The CloudStack transport, model and remote MCP tool discovery are fixtures in this test mode. `scripts/browser_fixture.py` refuses to start unless `DIRIGENTENSTAB_BROWSER_FIXTURE=1` is explicitly set. It creates a temporary database, synthetic credentials and a temporary TLS certificate. It does not access an existing CloudStack installation, hypervisor or model provider. Browser tests assert that synthetic infrastructure/provider keys and VM passwords are absent from browser content.

`.github/workflows/browser.yaml` runs inside the prebuilt test runner container with Chromium and Firefox pre-installed as a single job using `pytest-xdist` (`-n 4`, matching the 4 vCPUs of the GitHub runner) and a per-test `pytest-timeout` (`--timeout=120`, default signal method; a hung test fails with a traceback instead of stalling the job). Each test starts its own server on a random port in its own temporary directory, so tests are isolation-safe. On a memory-constrained machine run `-n 2` (never more) and, if needed, split the suite with `BROWSER_SHARD=1/2` (and `2/2`) — `tests/conftest.py` assigns browser tests to shards by collection index, and an unset variable runs everything. The job uploads desktop/mobile screenshots and the fixture's server log. Pull requests that only change Markdown files, `docs/**` or `LICENSE` skip the browser tests but the job still succeeds so required checks pass. A new push to a pull request cancels that PR's older `ci.yaml` and `browser.yaml` runs; runs on `main` are never cancelled. A development environment without the optional Playwright package reports browser tests as skipped; the dedicated browser CI job must run them.

## Prebuilt CI test runner

CI workflows (`.github/workflows/ci.yaml` and `.github/workflows/browser.yaml`) execute inside a pinned, immutable container image on GitHub Container Registry:

```yaml
container:
  image: ghcr.io/candlelightner/dirigentenstab:test-runner-py3.12-pw1.64.1-8e89f79303a87df7@sha256:17f9208d340e3628961fecbf5a5c406626c475cf2731c19eed33ac85cb8aab84
```

- **Image composition**: `Dockerfile.test-runner` bakes Python 3.12, CloudMonkey 6.6.0, locked dependencies, and Playwright Chromium and Firefox browser binaries (`/ms-playwright`) into `/opt/venv`.
- **Manifest & invalidation**: `scripts/test_runner.py` computes a sha256 manifest of `Dockerfile.test-runner`, `requirements.lock`, and `pyproject.toml` dependencies/requires-python (excluding application `[project].version` bumps). Any modification triggers `.github/workflows/test-runner.yaml` to build, verify offline, and publish a new immutable tag to GHCR.
- **Workflow preparation**: Each CI job runs `python scripts/test_runner.py prepare`. This verifies that installed packages and workflow image pins match the computed manifest, then executes an offline editable installation (`pip install --no-deps --no-build-isolation --no-index -e .`) and `pip check` without network access.
- **Security rebuilds**: `.github/workflows/test-runner.yaml` provides a manual `workflow_dispatch` trigger with `security_rebuild=true` to refresh base OS packages without dependency changes.

### CI performance comparison

Prebaking packages and browser binaries removes network download flakiness, package repository outages, and apt lock contention.

| Run / Workflow | Setup time | Test execution | Total duration |
|---|---|---|---|
| **Baseline CI `test` (run 40387629637)** | 15s (`pip install -r requirements.lock`) | 42s | 67s |
| **Prebuilt CI `test` (run 40396100649)** | 3s in-container (31s cold runner image pull) | 43s | 82s |
| **Baseline Browser `chromium` (run 40385222474)** | 311s (`playwright install` timeout / apt lock) | 0s (aborted) | 318s (failed) |
| **Baseline Browser `chromium` (run 40387629632)** | 42s (`pip` + `playwright install`) | 163s | 210s |
| **Prebuilt Browser `chromium` (run 40396100615)** | 4s in-container (30s cold runner image pull) | 227s | 268s |

## Native acceptance

After installation, run:

```sh
sudo ./setup.sh --verify
sudo .venv/bin/python scripts/live_acceptance.py --run
sudo .venv/bin/python scripts/gpu_acceptance.py --run
```

Native service verification, the CI browser fixture and actual infrastructure acceptance are distinct checks. Real acceptance requires a live CloudStack KVM host and VMs: explicitly opt into `managed=true` to create/start a VM with managed SSH using an agent identity, run Python through its pinned SSH identity, inspect a deliberately failing command, upload/download a file, and reject access from an unrelated domain. Record the actual outputs and resource identities privately; publish only a sanitized result. Never report the browser fixture or unit mocks as real KVM acceptance.

The acceptance script creates two durably tracked private VMs under the Research and Development agents and retains them for inspection. It verifies non-root guest execution and the absence of host sockets, file round trips, unrelated-domain denial and the agent account's native API catalogue. It never submits a second deployment after an ambiguous result; use `scripts/admin.py status` and `recover-deployments` first. The private resume/report file is `/var/lib/dirigentenstab/setup/live-acceptance.json`.

`.github/workflows/live.yaml` supports an explicit manual run on a trusted, dedicated self-hosted test runner labeled `dirigentenstab-acceptance`. Configure the `private-cloud-acceptance` environment and its `DIRIGENTENSTAB_INSTALL` variable to point at an already deployed test installation. The workflow runs only from main after the confirmation input is selected. It does not deploy code, run pull-request code, configure a runner automatically, or open the private API to GitHub-hosted runners. Ordinary CI integration tests use real local SSH/SFTP endpoints and synthetic infrastructure fixtures; this manual job uses actual CloudStack/KVM.

### Live portal smoke test, 2026-10-25

Chromium also tested the actual portal at its private local HTTPS endpoint on the Ubuntu 24.04 host, with native CloudStack 4.23.0.0 and the separately configured local Qwen inference provider. The live check passed CloudStack-backed login, Secure/HttpOnly/SameSite cookies, the real domain tree, direct agent selection, model configuration display and authenticated WebSocket handshakes.

The same live check passed through Tailscale Serve with normal browser certificate validation. Existing Serve routes were preserved; the added route is tailnet-only. No CloudStack API or guest SSH port was published.

A separate live Chromium check restored a nonempty imported legacy transcript, verified its read-only notice, sent a benign new prompt, and confirmed a new conversation with empty prior model history. The imported ciphertext remained unchanged, logout succeeded, and the browser reported no page errors. The check recorded counts and assertions without screenshots or private transcript text.

A new read-only conversation called `search_api` against the live catalogue and displayed streamed text plus tool activity. Reloading the portal restored that conversation, including its tool history. A database check confirmed the persisted messages were encrypted. The browser content and WebSocket frames were checked against the installation, agent and provider credentials without recording those credentials. Logout revoked the browser session. The browser reported no page errors. This portal check did not mutate infrastructure and is separate from the real VM/SSH acceptance described above.
