# Architecture

The application is one process in one Docker container. SQLite is stored in the `dirigentenstab_data` volume; its master key and TLS key are separate Docker secrets. Native CloudStack management, MySQL, libvirt/KVM and storage run on the host, outside Compose.

## Identity and hierarchy

CloudStack authenticates human logins. Only root and domain administrators can operate administrative agents. Each browser session stores an encrypted CloudStack session cookie and session key server-side. Protected HTTP requests, socket connections and UI operations revalidate the account. NiceGUI client IDs are additionally bound to the authenticated session and socket to prevent one browser from dispatching events to another browser's UI.

`agents` stores metadata and CloudStack UUID references. There is no mutable local domain tree or parent column. Domain relationships and visible human administrators come from current CloudStack API calls. CloudStack enforces domain ancestry; the backend independently checks which agents a human may operate and which subordinate agents a caller may delegate to.

Every agent gets a distinct CloudStack account in its own domain and one encrypted API key pair. CloudStack's current account, domain and role are the sole infrastructure API permission authority. Search, description, execution and managed subgroup provisioning use that same identity. New keys are issued without additional per-key allow/deny rules. There is no Python command blacklist, local infrastructure API permission copy or parent-key fallback. Native-authorized APIs such as `createServiceOffering` and `updateServiceOffering` remain available through the generic tools. Local transport validation still prevents shell injection, CloudMonkey file expansion and reading host credentials.

## Execution

Pydantic AI builds the selected Chat Completions or Responses model using a reusable encrypted provider configuration. A bounded event stream records text, tool calls and results. Model messages are encrypted in SQLite and owned by both human and agent. Delegation runs the child's model and tool closures, with its own credentials. A shared usage budget and depth limit bound recursive execution.

CloudMonkey runs directly through `asyncio.create_subprocess_exec`, never a host shell. Temporary credential configuration is mode 600 in tmpfs and removed after execution. API names and parameter shapes are validated against the calling account's live catalogue; local file expansion and transport credential overrides are blocked. Async job IDs are polled under the same identity. Responses are bounded and redacted. The audit log records actor, operation, target, time and outcome without plaintext parameters or credentials.

## Optional MCP tools

Human administrators authorized for the main agent domain register HTTPS Streamable HTTP endpoints with encrypted bearer credentials. Per-agent exact tool-name assignments are intersected with each ancestor's assignments using live CloudStack parent links. Descendant administrators can narrow these grants without editing endpoint credentials. New agents have no external tools until explicitly assigned.

Pydantic AI's existing MCP support supplies the transport and tool schemas. The GUI automatically discovers the saved server's tools and shows an explicit assignment checklist, with a refresh action; discovery never grants access. The application filters exposed tools and rechecks authorization and configuration at dispatch. Server instructions, sampling and elicitation remain disabled. Results are bounded, redacted and returned as untrusted tool data. Generic MCP calls share the existing durable mutation path so completed calls are reused and uncertain side effects are not replayed automatically. The GUI's per-agent System prompt edits the existing agent instructions used on subsequent model calls.

## Durable operations

Subgroup provisioning persists intent before making CloudStack changes. Stable operation IDs appear in generated domain/account/key names. Each successful stage persists its IDs; retries find existing resources under the same parent. Credentials are validated before the new agent becomes visible. Lost key-registration responses are handled by finding and revoking that operation's keys before replacement.

Before creating a domain, the backend retrieves its actual parent path and level. The generated child name and full stored path must fit CloudStack's 255-character utf8mb3 columns. `MAX_HIERARCHY_DEPTH` defaults to 10, with native ROOT at level 0. The path-length limit may be reached before the configured depth when names are long. Neither bound depends on model-supplied ancestry.

Credential rotation stores the old pair, replacement pair and operation ID durably. It verifies the native user/account/domain and validates the replacement before binding; old-key deletion follows the durable commit. A failed operation retains recovery state instead of substituting parent or root credentials. Schema upgrades preserve existing credentials and archive the retired provisioning pair encrypted for explicit cleanup; they do not revoke remote keys. A human platform administrator can explicitly adopt a selected replacement key for the same native owner.

An explicit `execute_api(..., managed=True)` deployment from a cloud-init-compatible template uses backend-generated cloud-init for unique non-root SSH credentials and a generated guest host key whose public half is pinned before first connection. A template without a local approval record receives no additional guest sudo grant; enrollment does not remove existing image privileges or secrets. Deployment intent and encrypted access information are saved before dispatch. A stable VM name permits recovery after a lost response. Ambiguous deployments are never automatically submitted a second time. The same explicit option on `createTemplate` selects private managed-image enrollment. Default native deployment/template calls preserve their supplied parameters and do not enroll SSH or approve images automatically; a managed failure never falls back to a second native submission.

## Guest access and host boundary

Before each SSH operation the backend asks CloudStack for the VM using the calling agent's runtime identity. It obtains its current default NIC address, checks approved guest CIDRs, rejects host/local addresses, and verifies the recorded host key. Missing credentials fail closed. AsyncSSH has no access to the host SSH agent or SSH config. File transfers use directory-relative file descriptors, no-follow opens, per-agent workspaces and bounded sizes.

Host administration remains outside local agent tools. There is no generic shell on the server or arbitrary host mount. An explicit `managed=true` GPU lifecycle request invokes the optional GPU controller under the current authenticated human and durable agent execution. It can prepare permitted profiles from unused owned capacity under every ancestor's GPU policy, while native VM dispatch uses the agent's own CloudStack credentials. Device ownership, verified libvirt attachments, native quotas and hardware limits constrain mdev changes. Policy and ownership grants remain human platform-administrator actions. Ordinary native requests never fall back to the controller after an API denial.
