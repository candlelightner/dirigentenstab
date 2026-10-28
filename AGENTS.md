# Project Rules · Dirigentenstab

Guidelines and conventions for AI assistants working in this repository.

## 1. Delegation & Subagents

- The main/parent agent coordinates, reviews, and handles user communication, GitHub MCP calls (PR creation and merging), and escalations from subagents. It must **never** directly edit code/files, run test suites, execute git mutations, or run Docker build/deploy commands itself.
- Delegate all code edits, test executions, git commits/pushes, CI/CD monitoring, and local container rebuilds/restarts to competent smaller-model subagents available to the coordinating provider. Choose by task competence and availability, not a fixed provider: an OpenAI flagship can delegate to GPT-6.1 Sol, Terra, or Luna, a Google flagship to Gemini Flash, and a Claude flagship to Sonnet or Haiku. Keep implementation and verification with subagents; the parent retains coordination and review.

## 2. GitHub MCP & Delivery Pipeline

- Use the **GitHub MCP** (`ServerName="github"`) for all GitHub operations (PR creation, check-run tracking, PR merging, issue/PR inspection).
- Standard end-to-end workflow (treat implied steps—branching, committing, pushing, PRs, restarting hung CI jobs, merging, and deploying—as pre-approved scope; only stop on genuine blockers):
  1. Branch off `main` (`implementation/<topic>` or `fix/<topic>`) in a dedicated git worktree. The main checkout `/home/emil/dirigentenstab` is deploy-only: never edit, commit, or leave uncommitted changes there; only pull `origin/main` and deploy from it.
  2. Verify locally: `.venv/bin/ruff check .`, `.venv/bin/pytest -q -m "not browser and not live"`, and `.venv/bin/pytest -q -m browser tests/test_browser.py -n 2 --timeout=120` for UI changes (never more than 2 workers locally; `BROWSER_SHARD=1/2` splits the suite on constrained machines).
  3. Commit locally and push branch changes via GitHub MCP (`create_branch` + `push_files`) when shell git credentials are absent.
  4. Open PR against `main` via GitHub MCP. A subagent watches CI (`ci.yaml` and `browser.yaml`, one job with 4 xdist workers) until green, restarting hung jobs itself; the parent steps in only when the subagent escalates a genuine failure or blocker.
  5. Merge PR into `main` via GitHub MCP. Merging does not deploy.
  6. Deploy only a published release, never a bare merge:
     a. Merge a version-bump PR. `release.yaml` then publishes `ghcr.io/candlelightner/dirigentenstab:<version>` and the tag `v<version>`; wait for that workflow to succeed.
     b. Pull `origin/main` in `/home/emil/dirigentenstab`.
     c. Back up `.env` under `.work/env-backup-<UTC timestamp>`.
     d. Pull the release image and set only `IMAGE` in `.env` to `ghcr.io/candlelightner/dirigentenstab:<version>`. Never deploy locally built or SHA-tagged images.
     e. Restart the `dirigentenstab` Docker Compose service preserving active env/secrets/`dirigentenstab_data`.
     f. Verify `/healthz` via `PUBLIC_ORIGIN`. `127.0.0.1:<port>/healthz` can return an empty reply on this host because the port is shared with tailscale serve.
     g. If health fails, roll back to the previous `IMAGE`.
  7. Afterwards remove merged worktrees and their branches.

## 3. Implementation & UI Principles (`ponytail` + `spec.md`)

- Read and respect `spec.md` as the V1 product source of truth (single human owner via CloudStack login, native CloudStack domains/accounts/quotas as sole infrastructure permission authority, independent background conversations surviving logout/restart, interrupt-by-sending + per-conversation Stop, informational VM list without lifecycle buttons, strict ancestor inheritance for owner SSH public key and provider/MCP allowances).
- When a change adds, removes, or alters behavior that `spec.md` describes or excludes, update `spec.md` (and affected docs) in the same PR. Spec and code must not drift.
- Apply **Ponytail (`full`)** ("lazy senior dev"): smallest complete diff, reuse existing NiceGUI/Quasar components (`ui.menu`, `ui.dialog`, standard props/classes), zero unrequested wrappers/options/abstractions, update every caller and test touched, don't overthink obvious implied steps, and ask brief clarifying questions up front only when genuinely ambiguous.
- Before architectural work, infer the actual intent from the conversation and inspect the real failure, existing tools, and execution paths. Reuse or extend the existing owner of a capability: implement it at most once, preferably zero times when it is already covered. Do not add redundant permission layers, workflows, or wrappers. Verify the motivating scenario, not only behavior invented for the implementation. Carry out explicit concrete edits (for example, moving button X to position Y) directly without turning them into architectural discussions.
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

## 5. Instruction Files

- `AGENTS.md` is the single source of project rules for every agent and provider. Always add general agentic instructions here, never to provider-specific files (`CLAUDE.md`, `GEMINI.md`, etc.).
- Provider-specific files only point to `AGENTS.md` and may hold instructions that apply solely to that provider.
