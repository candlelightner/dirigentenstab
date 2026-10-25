# Dirigentenstab 0.1.3

## Execution failure

The failure after a successful inventory was caused by conversation serialization, before the next model request or CloudStack provisioning. The generic secret-field matcher replaced numeric Pydantic AI usage counters (`input_tokens`, `output_tokens`, cache and reasoning counts) with the string `[redacted]`. Reloading this saved history raised a Pydantic validation error. History validation ran outside the execution exception handler, explaining the missing failure audit and generic UI notification.

The deployed inventory conversation reproduced the invalid numeric fields locally. Its structure contained completed API calls; no Sandbox provisioning operation or CloudStack domain existed. The repaired loader successfully validates that same conversation without forwarding its contents elsewhere. Numeric telemetry counters now retain their types; credentials and string token values remain redacted. Legacy damaged usage metadata is discarded during loading, preserving prompts, responses and tool activity.

## Reliability and diagnostics

Encrypted `chat_runs` records link executions to conversations and agents, preserve bounded correlated tool events, and record running/completed/failed/interrupted/reconciliation status. Partial responses and completed tool results are checkpointed. Restart marks unfinished runs interrupted; missing tool returns are explicitly closed with an unknown-outcome warning rather than replayed automatically. Provisioning retains its existing durable idempotent stages and administrative recovery CLI.

User errors distinguish provider authentication, missing endpoint/model, rate limits, server unavailability, invalid responses, execution limits, timeouts, CloudStack rejection and provisioning reconciliation. Unexpected errors log reference IDs, agent/tool identifiers, exception type and traceback frames. Exception bodies, source lines, locals, credentials and private conversation content are excluded from diagnostic logs.

## Navigation and configuration

NiceGUI's responsive drawer contains an independently scrollable, searchable hierarchy. Chat, current agent and selector remain primary. Selecting an agent closes the drawer. Desktop retains a collapsible sidebar. Conversation scrolling and the bounded composer are independent of hierarchy size. The visual viewport adjusts for mobile keyboards; secondary details compact while typing in short mobile viewports.

Managed-agent labels use authoritative application metadata joined to CloudStack domain IDs; native ROOT is a container and the bootstrap agent is Main Agent. No CloudStack names, parent relationships, permissions or identifiers are changed for presentation. Unmanaged and legacy names are preserved literally. Human administrators and technical identifiers appear in domain details.

Agent configuration discovers provider models server-side with a short cache and an editable searchable selector. Changing providers retains the selected model. Unsupported discovery, empty catalogues and errors permit manual entry. Markdown uses NiceGUI's DOMPurify sanitization; code and tables scroll within message bounds.

## Validation and deployment

Run `ruff check .`, `pytest -q -m 'not browser'`, and the Playwright suite after installing Chromium and Firefox. Browser fixtures use synthetic credentials and 50 agents across nested branches. Tests cover second-turn provisioning after legacy history, retained tools and partial text, sanitized diagnostics, provider discovery, custom model persistence, Markdown injection, deep mobile selection and a reduced keyboard viewport. Browser artifacts remain private local test output or synthetic CI screenshots.

The opt-in `scripts/live_web_acceptance.py` uses a protected human login file and the actual deployed web interface, provider and CloudStack. It checks for existing Sandbox state before requesting that exact subgroup, validates the administrative account and restricted keys, exercises direct child chat and reload, rejects unrelated access, and asserts that the VM inventory is unchanged. It writes private screenshots and a credential-free receipt. It is never run by fixture CI.

Migration 007 adds a table and index without modifying existing rows. Take a consistent SQLite backup and preserve the matching encryption master key, `.env` and TLS files before deployment. Roll back with the previous image and its matching database/configuration snapshot. If acceptance has provisioned Sandbox, retain its durable state when reverting; do not restore a snapshot that forgets newly created resources without reconciling them first.
