# Dirigentenstab

A small, self-hosted hierarchical AI agent manager backed by **Apache CloudStack 4.23.0.0**. MIT licensed. One Python/NiceGUI application, Pydantic AI, SQLite, encrypted credentials, CloudMonkey, and AsyncSSH.

CloudStack owns domains, permissions, quotas, KVM, storage, templates, consoles, snapshots and backups. Dirigentenstab owns chat, model configuration and controlled agent delegation. It does not replace CloudStack's infrastructure management.

## Install

Ubuntu Server 24.04 LTS with hardware KVM, at least 8 GiB available memory and 50 GiB free disk is required for native installation. Review the preflight output before installation on an existing server.

```sh
git clone https://github.com/candlelightner/dirigentenstab.git
cd dirigentenstab
cp .env.example .env
nano .env
sudo ./setup.sh --preflight
sudo ./setup.sh --install
sudo docker compose up -d
sudo ./setup.sh --verify
```

The default application address is **https://localhost:3000**, bound to **127.0.0.1:3000**. Choose a free port in `.env` when another service uses 3000. Setup creates a local TLS certificate, a separate encryption master key, a persistent Docker volume, and a dedicated CloudStack domain administrator agent. Use the CloudStack human administrator identity to sign in. There is no public registration.

For an existing CloudStack installation, use `sudo ./setup.sh --install --existing`; provide the private endpoint and a root-private administrator API credential file as described in [installation](docs/INSTALLATION.md). This path does not install or reconfigure the hypervisor.

Configure a provider in the web UI, run **Test tool calling**, and assign its model to an agent. OpenAI-compatible Chat Completions and Responses are supported. Local inference is a separate service; see the [tested llama.cpp example](docs/LOCAL_INFERENCE.md). No commercial API is required.

## Agent prompts and external tools

Select an agent and open **Configure** to edit its **System prompt**. The saved prompt applies to that agent's subsequent model calls, including delegated work; it does not change CloudStack permissions.

Use **Thinking level** in the same dialog to select the model's reasoning effort. The choices use advertised model capabilities when available; the hint identifies documented fallbacks or unavailable capability information. **Model default** preserves the provider's default behavior. Changes apply on the next invocation, including delegated work. The chat shows an animated **Thinking…** status while a reply is in progress; this indicates activity rather than exposing the model's private reasoning.

Use **Stop agent** to cancel an active reply, including after reopening its conversation. Completed work remains saved. Stopping prevents further model/tool calls; a remote action already submitted may still complete and is marked for reconciliation when its outcome is uncertain.

Open **Configure → Context compaction** to choose a separate compaction provider/model and an automatic compaction percentage (disabled by default). The percentage measures estimated input usage against the model's context window after reserving response space: up to 8,192 tokens, or one quarter of a smaller window. Context limits use provider metadata when available; enter a manual token limit when unavailable. The chat meter appears when automatic compaction or a manual context limit is configured. Usage is an estimate from message, instruction and tool metadata size, not an exact provider token count.

Compaction summarizes completed older exchanges only in the context sent to the model; the full encrypted transcript and saved operation state remain intact. The latest user request, system instructions and recent tool exchanges stay available. Summaries use the selected model with no tools. Choose a compaction model large enough for the prefix being summarized: an oversized input, failed request or unusable summary stops the invocation with the original history retained. Settings apply to subsequent invocations without restarting the application.

Each compaction has its own bounded model request (60 seconds and up to 4,096 output tokens); it is separate from the main agent's request counter. When the conversation model also summarizes, its smaller response reserve applies to the summary too.

Open **Configure → MCP tools** to connect an optional remote HTTPS / Streamable HTTP MCP server, such as a web-search service. Saving or selecting a server automatically detects its tools; check the tools you want to assign and select **Save assigned tools**. Use **Refresh tools** to reload the catalogue. Human administrators authorized for the main agent's CloudStack domain can register endpoints and encrypted bearer credentials. A blank credential field retains the stored value; use the clear option to remove it. Child administrators can narrow assignments within their own scope. A tool must be explicitly assigned to the agent and every ancestor agent; new agents start without MCP tools. Disabling a server or removing an ancestor's assignment prevents subsequent calls. Local stdio servers and process execution are unavailable.

For **Tavily**, select the main agent, then **Configure → MCP tools → New server**. Enter name `Tavily`, endpoint `https://mcp.tavily.com/mcp/`, and your `tvly-...` key in **API key / bearer token**. Keep the key out of the URL; the backend sends it using [Tavily’s supported bearer authentication](https://github.com/tavily-ai/tavily-mcp#remote-mcp-server). Save the server, then check `tavily_search` in the detected tools and save its assignments on the main agent and every ancestor/target agent that should use it. Optionally select the extract, crawl, map or research tools; see the [current tool catalogue](https://docs.tavily.com/documentation/mcp). Registering a server grants no agent access until tools are assigned. Tavily uses the same generic MCP integration.

External tool results are untrusted data. Generic MCP calls use the existing durable execution tracking; an uncertain outcome requires administrator review before another mutation. Only assign tools and send queries to services you intend to trust with that data. See [security](docs/SECURITY.md) for the boundaries.

CloudStack `execute_api` calls use native behavior by default, preserving caller-supplied names, user-data and publication settings. For application-managed SSH enrollment, explicitly set `managed=true` when deploying from an approved template. The same option on `createTemplate` selects the durable private-template workflow; it does not restrict ordinary native template creation.

## Security boundaries

- Human passwords remain with CloudStack. Application sessions are server-side, expiring and revocable; cookies use HttpOnly, Secure and SameSite Strict.
- Each managed agent account uses one encrypted CloudStack API key pair. Its native account, domain and role determine every available API; Dirigentenstab adds no API allow/deny list.
- API search, description and execution use the same agent credentials, including native-authorized service-offering operations. Denials are returned without retrying as a parent or platform administrator. Local shell access and CloudMonkey `@file` expansion remain unavailable.
- Guest SSH uses a dedicated non-root user, a unique per-VM client key and a verified host-key pin. Transfers are confined to the agent's application workspace. No Docker socket or arbitrary host directories are mounted in the application.
- Infrastructure operations can change or delete resources within the agent's CloudStack permissions. Only configure agents and providers you intend to authorize.

Read [architecture](docs/ARCHITECTURE.md), [security](docs/SECURITY.md), [recovery](docs/RECOVERY.md), and [testing](docs/TESTING.md) before operating a cloud containing valuable data.

Moving from Agentor: the operator-only [workspace migration](docs/MIGRATION.md) and [conversation import](docs/HISTORY_MIGRATION.md) retain the original VMs and volumes for rollback. Imported conversations are read-only references; continuing starts a fresh model conversation.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps -e .
.venv/bin/ruff check .
.venv/bin/pytest -q -m 'not browser and not live'
```

CI runs unit and integration checks and builds the image. Chromium browser tests run in their own job. Merging a version change in `pyproject.toml` publishes `ghcr.io/candlelightner/dirigentenstab:<version>` and creates its release tag; an explicit version tag is also supported. Pushing or publishing an image never deploys it to your host.

CloudStack 4.23 is a regular release supported until the next regular or LTS release. Its native API roles and domain permissions are used directly; schedule upgrades using the upstream release notes rather than enabling unattended CloudStack upgrades. Third-party components retain their own licenses; see [third-party notices](docs/THIRD_PARTY.md).
