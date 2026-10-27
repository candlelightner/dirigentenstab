# Dirigentenstab

A small, self-hosted hierarchical AI agent manager backed by **Apache CloudStack 4.23.0.0**. MIT licensed. One Python/NiceGUI application, Pydantic AI, SQLite, encrypted credentials, CloudMonkey, and AsyncSSH.

CloudStack owns domains, permissions, quotas, KVM, storage, templates, consoles, snapshots and backups. Dirigentenstab owns independent conversations, autonomous background work and model configuration. Only the owner assigns tasks; the hierarchy defines administrative scope. It does not replace CloudStack's infrastructure management.

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

The default application address is **https://localhost:3000**, bound to **127.0.0.1:3000**. Choose a free port in `.env` when another service uses 3000. Setup creates a local TLS certificate, a separate encryption master key, a persistent Docker volume, a dedicated CloudStack domain administrator Main Agent, and a separate Global Admin with its own native root administrator account. Use the CloudStack human administrator identity to sign in. There is no public registration.

For an existing CloudStack installation, use `sudo ./setup.sh --install --existing`; provide the private endpoint and a root-private administrator API credential file as described in [installation](docs/INSTALLATION.md). This path does not install or reconfigure the hypervisor.

Existing installations can add Global Admin without rotating Main Agent keys or changing its history:
`sudo .venv/bin/python scripts/admin.py provision-global-admin` (authenticate as the human CloudStack root administrator).
Global Admin appears above the existing tree and initially copies Main Agent's model/thinking/compaction settings while enabling all central provider, MCP server/tool and owner SSH access. Save individual settings to narrow these defaults; running provisioning again preserves them. Native APIs, including `createServiceOffering` and `updateServiceOffering` with `domainid=public`, run with the selected agent's own identity. Host GPU policies remain enforced.

Configure a provider in the web UI, run **Test tool calling**, and assign its model to an agent. OpenAI-compatible Chat Completions and Responses are supported. Local inference is a separate service; see the [tested llama.cpp example](docs/LOCAL_INFERENCE.md). No commercial API is required.

## Agent prompts and external tools

Select an agent and open **Configure** to edit its **System prompt**. The owner can configure any visible agent; a parent agent can configure descendants within its own provider/MCP allowance. An agent can edit its own prompt, but cannot change its own model or enabled tools. Configuration changes pause affected active conversations, apply the settings, and resume saved work. System prompts do not change CloudStack permissions.

Use **Thinking level** in the same dialog to select the model's reasoning effort. The choices use advertised model capabilities when available; the hint identifies documented fallbacks or unavailable capability information. **Model default** preserves the provider's default behavior. Changes resume active work with the new configuration. The chat shows an animated **Thinking…** status while a reply is in progress; this indicates activity rather than exposing the model's private reasoning.

Conversations run independently, including multiple conversations with the same agent. Work continues when you select another conversation, close the browser, sign out, or your login expires. Accepted work uses the agent’s own CloudStack credentials and resumes after an application restart. Stopped or agent-paused work stays paused. There are no overall task runtime, request-count or tool-call budgets; provider/native limits, bounded outputs, network timeouts and finite execution capacity still apply.

A new message interrupts only its current conversation and continues from saved progress. **Stop conversation** also stops only the current conversation. A submitted remote operation may still finish; the agent receives saved action details and inspects actual infrastructure state before deciding whether to retry, continue or ask for help. The hub shows saved progress, completion and blocked/paused status.

Open **Configure → Context compaction** to choose a separate compaction provider/model and an automatic compaction percentage (disabled by default). The percentage measures estimated input usage against the model's context window after reserving response space: up to 8,192 tokens, or one quarter of a smaller window. Context limits use provider metadata when available; enter a manual token limit when unavailable. The chat meter appears when automatic compaction or a manual context limit is configured. Usage is an estimate from message, instruction and tool metadata size, not an exact provider token count.

Compaction summarizes completed older exchanges only in the context sent to the model; the full encrypted transcript and saved operation state remain intact. The latest user request, system instructions and recent tool exchanges stay available. Summaries use the selected model with no tools. Choose a compaction model large enough for the prefix being summarized: an oversized input, failed request or unusable summary stops the invocation with the original history retained. Changing these settings resumes affected active work under the new configuration without restarting the application.

Each compaction has its own bounded model request (60 seconds and up to 4,096 output tokens); it does not impose an overall task budget. When the conversation model also summarizes, its smaller response reserve applies to the summary too.

Open **Configure → MCP tools** to connect an optional remote HTTPS / Streamable HTTP MCP server, such as a web-search service. Saving or selecting a server automatically detects its tools; check the tools you want to assign and select **Save assigned tools**. Use **Refresh tools** to reload the catalogue. The human owner centrally manages endpoints and encrypted bearer credentials. A blank credential field retains the stored value; use the clear option to remove it. New subgroups inherit their parent’s selected providers and MCP tools; the parent can narrow these selections. A provider or MCP tool must remain enabled at every ancestor. Disabling ancestor access prevents subsequent calls while preserving descendant selections for re-enabling later. Local stdio servers and process execution are unavailable.

For **Tavily**, select the main agent, then **Configure → MCP tools → New server**. Enter name `Tavily`, endpoint `https://mcp.tavily.com/mcp/`, and your `tvly-...` key in **API key / bearer token**. Keep the key out of the URL; the backend sends it using [Tavily’s supported bearer authentication](https://github.com/tavily-ai/tavily-mcp#remote-mcp-server). Save the server, then check `tavily_search` in the detected tools and save its assignments on the main agent and every ancestor/target agent that should use it. Optionally select the extract, crawl, map or research tools; see the [current tool catalogue](https://docs.tavily.com/documentation/mcp). Registering a server grants no agent access until tools are assigned. Tavily uses the same generic MCP integration.

External tool results are untrusted data. Generic MCP calls use the existing durable execution tracking; uncertain outcomes are returned to the agent for investigation rather than silently replayed. Only assign tools and send queries to services you intend to trust with that data. See [security](docs/SECURITY.md) for the boundaries.

CloudStack `execute_api` calls use native behavior by default, preserving caller-supplied names, user-data and publication settings. For application-managed SSH enrollment, explicitly set `managed=true` when deploying from a cloud-init-compatible template. Compatible managed deployments receive agent guest-admin access and the centrally configured owner SSH public key; enrollment does not remove privileges or secrets already baked into an image. The selected offering's root disk must fit the template; fixed disk offerings may ignore `rootdisksize`. The same option on `createTemplate` selects the durable private-template workflow; it does not restrict ordinary native template creation.

Set the owner’s public key once in **Platform settings → Owner SSH public key**. Managed enrollment needs no owner private key and does not modify existing VMs. The hub stores no owner private key: the in-browser SSH terminal connects as the VM’s managed `dirigent` user with that VM’s managed key after CloudStack authorizes the signed-in owner for the owning agent, so it is available for managed VMs. The VM overview shows status, available SSH details and CloudStack links; lifecycle actions remain in chat and CloudStack. In the sidebar, select VMs to open a VM with SSH (default) or its CloudStack console, embedded or in a new tab. Sidebar Agents/VMs selections and Show aliases are saved per user in this browser across refreshes. Console access uses the signed-in owner’s native CloudStack permissions and a fresh endpoint ticket per connection. The **Files** mode browses the VM over SFTP on the same managed connection, with per-file download and upload (100 MiB per file) into the current directory.

With the optional GPU controller installed, `managed=true` also selects its GPU lifecycle workflow. An authorized agent can prepare permitted profiles from its unused owned pool and deploy using its own CloudStack identity. Existing ancestor policies, native quotas, device ownership and attachment checks apply; policy changes and pool ownership grants remain human platform-administrator actions. Use `managed=true` for GPU start/stop and offering changes to retain controller recovery and release-on-stop behavior.

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
