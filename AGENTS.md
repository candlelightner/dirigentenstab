# Project Rules · Dirigentenstab

Guidelines and conventions for AI assistants working in this repository.

## 1. Delegation & Subagents (Antigravity / `agy`)

- The main/parent agent coordinates, reviews, and handles user communication and GitHub MCP calls. It must **never** directly edit code/files, run test suites, execute git mutations, or run Docker build/deploy commands itself.
- Delegate all code edits, test executions, git commits/pushes, and local container rebuilds/restarts exclusively to **Gemini 3.8 Flash** subagents (`invoke_subagent` with `Model="flash"`).

## 2. GitHub MCP & Delivery Pipeline

- Use the **GitHub MCP** (`ServerName="github"`) for all GitHub operations (PR creation, check-run tracking, PR merging, issue/PR inspection).
- Standard end-to-end workflow (treat implied steps—branching, committing, pushing, PRs, restarting hung CI jobs, merging, and deploying—as pre-approved scope; only stop on genuine blockers):
  1. Branch off `main` (`implementation/<topic>` or `fix/<topic>`).
  2. Verify locally: `.venv/bin/ruff check .`, `.venv/bin/pytest -q -m "not browser and not live"`, and `.venv/bin/pytest -q -m browser tests/test_browser.py` for UI changes.
  3. Commit locally and push branch changes via GitHub MCP (`create_branch` + `push_files`) when shell git credentials are absent.
  4. Open PR against `main` via GitHub MCP and watch CI (`ci.yaml` and `browser.yaml`, 5-minute browser timeout) until green.
  5. Merge PR into `main` via GitHub MCP.
  6. Pull `origin/main` in `/home/emil/dirigentenstab`, rebuild and restart the `dirigentenstab` Docker Compose service preserving active env/secrets/`dirigentenstab_data`, and verify `/healthz` + live UI.

## 3. Implementation & UI Principles (`ponytail` + `spec.md`)

- Read and respect `spec.md` as the V1 product source of truth (single human owner via CloudStack login, native CloudStack domains/accounts/quotas as sole infrastructure permission authority, independent background conversations surviving logout/restart, interrupt-by-sending + per-conversation Stop, informational VM list without lifecycle buttons, strict ancestor inheritance for owner SSH public key and provider/MCP allowances).
- Apply **Ponytail (`full`)** ("lazy senior dev"): smallest complete diff, reuse existing NiceGUI/Quasar components (`ui.menu`, `ui.dialog`, standard props/classes), zero unrequested wrappers/options/abstractions, update every caller and test touched, don't overthink obvious implied steps, and ask brief clarifying questions up front only when genuinely ambiguous.
- UI layout priorities (desktop `1440x900` and mobile `390x844` + virtual keyboard `visualViewport`):
  - Maximize vertical and horizontal chat space.
  - Sidebar-only agent switching.
  - Agent settings in top header menu.
  - Top-row conversation controls: selector + `+` (new conversation) + `(i)` circular icon button for Run details menu (`ui.menu` with `budget_label`, `context_label`, `compaction_status`, and fallback).
  - Single-slot icon-only `Send`/`Stop` swap button flush to the right of `Message` (keeping `aria-label` and `.mark()`), aligned in height (`44x44` icon button aligned with 1-row `Message` field).
  - No redundant status line (`Ready`, `Running`, `Completed`) above the composer.
  - Zero horizontal overflow (`scrollWidth <= clientWidth` in `.messages` and across the page).

## 4. Safety Boundaries

- Never modify host SSH configurations or host services outside project boundaries.
- Preserve encrypted database state (`dirigentenstab_data`), credentials, conversation history, and active runtime settings (e.g. `SESSION_SECONDS`).
