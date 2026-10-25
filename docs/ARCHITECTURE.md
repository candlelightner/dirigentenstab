# Architecture

The application is one process in one Docker container. SQLite is stored in the `dirigentenstab_data` volume; its master key and TLS key are separate Docker secrets. Native CloudStack management, MySQL, libvirt/KVM and storage run on the host, outside Compose.

## Identity and hierarchy

CloudStack authenticates human logins. Only root and domain administrators can operate administrative agents. Each browser session stores an encrypted CloudStack session cookie and session key server-side. Protected HTTP requests, socket connections and UI operations revalidate the account. NiceGUI client IDs are additionally bound to the authenticated session and socket to prevent one browser from dispatching events to another browser's UI.

`agents` stores metadata and CloudStack UUID references. There is no mutable local domain tree or parent column. Domain relationships and visible human administrators come from current CloudStack API calls. CloudStack enforces domain ancestry; the backend independently checks which agents a human may operate and which subordinate agents a caller may delegate to.

Every agent gets a distinct DomainAdmin account in its own domain and two expiring native API key pairs. CloudStack's account role, domain boundary and key rules are the sole infrastructure permission authority. Search, description and execution use the runtime key's native `listApis` catalogue; there is no Python infrastructure allowlist or persisted permission copy. The provisioning key is available only to trusted managed-agent orchestration. Its native envelope must cover permissions delegated to a child, whose runtime grant is derived from the parent's live native catalogue. Separate technical checks prevent host-control bypasses, credential retrieval, local file expansion and command injection; they do not define VM/network/storage grants.

## Execution

Pydantic AI builds the selected Chat Completions or Responses model using a reusable encrypted provider configuration. A bounded event stream records text, tool calls and results. Model messages are encrypted in SQLite and owned by both human and agent. Delegation runs the child's model and tool closures, with its own credentials. A shared usage budget and depth limit bound recursive execution.

CloudMonkey runs directly through `asyncio.create_subprocess_exec`, never a host shell. Temporary credential configuration is mode 600 in tmpfs and removed after execution. Command and parameter policy is checked before dispatch, including blocking CloudMonkey's local file expansion. Async job IDs are polled under the same identity. Responses are bounded and redacted. The audit log records actor, operation, target, time and outcome without plaintext parameters or credentials.

## Optional MCP tools

Human administrators authorized for the main agent domain register HTTPS Streamable HTTP endpoints with encrypted bearer credentials. Per-agent exact tool-name assignments are intersected with each ancestor's assignments using live CloudStack parent links. Descendant administrators can narrow these grants without editing endpoint credentials. New agents have no external tools until explicitly assigned.

Pydantic AI's existing MCP support supplies the transport and tool schemas. The GUI automatically discovers the saved server's tools and shows an explicit assignment checklist, with a refresh action; discovery never grants access. The application filters exposed tools and rechecks authorization and configuration at dispatch. Server instructions, sampling and elicitation remain disabled. Results are bounded, redacted and returned as untrusted tool data. Generic MCP calls share the existing durable mutation path so completed calls are reused and uncertain side effects are not replayed automatically. The GUI's per-agent System prompt edits the existing agent instructions used on subsequent model calls.

## Durable operations

Subgroup provisioning persists intent before making CloudStack changes. Stable operation IDs appear in generated domain/account/key names. Each successful stage persists its IDs; retries find existing resources under the same parent. Credentials are validated before the new agent becomes visible. Lost key-registration responses are handled by finding and revoking that operation's keys before replacement.

Before creating a domain, the backend retrieves its actual parent path and level. The generated child name and full stored path must fit CloudStack's 255-character utf8mb3 columns. `MAX_HIERARCHY_DEPTH` defaults to 10, with native ROOT at level 0. The path-length limit may be reached before the configured depth when names are long. Neither bound depends on model-supplied ancestry.

Credential rotation stores its old keys, replacement keys and operation ID durably. It copies each purpose's exact ordered native rules, including denies and patterns, verifies native user/account/domain ownership, compares the replacement rules, and validates domain access before binding. Old keys are revoked afterward; retry resumes the same operation. Missing or changed native evidence fails closed. A human platform administrator may explicitly adopt selected CloudStack-issued key IDs after changing native policy; no automatic newest-key selection or Python policy edit is involved.

Managed VM templates use backend-generated cloud-init for unique non-root SSH credentials and a generated guest host key whose public half is pinned before first connection. Deployment intent and encrypted access information are saved before dispatch. A stable VM name permits recovery after a lost response. Ambiguous deployments are never automatically submitted a second time.

## Guest access and host boundary

Before each SSH operation the backend asks CloudStack for the VM using the calling agent's runtime identity. It obtains its current default NIC address, checks approved guest CIDRs, rejects host/local addresses, and verifies the recorded host key. Missing credentials fail closed. AsyncSSH has no access to the host SSH agent or SSH config. File transfers use directory-relative file descriptors, no-follow opens, per-agent workspaces and bounded sizes.

Host administration remains outside these tools. There is no generic shell on the server or arbitrary host mount. The optional GPU controller exposes only authenticated, policy-checked device lifecycle operations through its private socket; agents receive neither host credentials nor a host shell. Infrastructure permission changes belong in CloudStack. The local managed-agent creation switch controls an application workflow, not direct native API authorization.
