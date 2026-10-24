# Architecture

The application is one process in one Docker container. SQLite is stored in the `dirigentenstab_data` volume; its master key and TLS key are separate Docker secrets. Native CloudStack management, MySQL, libvirt/KVM and storage run on the host, outside Compose.

## Identity and hierarchy

CloudStack authenticates human logins. Only root and domain administrators can operate administrative agents. Each browser session stores an encrypted CloudStack session cookie and session key server-side. Protected HTTP requests, socket connections and UI operations revalidate the account. NiceGUI client IDs are additionally bound to the authenticated session and socket to prevent one browser from dispatching events to another browser's UI.

`agents` stores metadata and CloudStack UUID references. There is no mutable local domain tree or parent column. Domain relationships and visible human administrators come from current CloudStack API calls. CloudStack enforces domain ancestry; the backend independently checks which agents a human may operate and which subordinate agents a caller may delegate to.

Every agent gets a distinct DomainAdmin account in its own domain. It has two expiring API key pairs. The runtime key allows a reviewed set of guest infrastructure APIs; the provisioning key allows only the account/domain/key APIs needed by trusted backend provisioning. Neither key can exceed its CloudStack account's role or domain boundary. API catalogue descriptions and signatures come from `listApis`, with CloudMonkey's maintained metadata cache.

## Execution

Pydantic AI builds the selected Chat Completions or Responses model using a reusable encrypted provider configuration. A bounded event stream records text, tool calls and results. Model messages are encrypted in SQLite and owned by both human and agent. Delegation runs the child's model and tool closures, with its own credentials. A shared usage budget and depth limit bound recursive execution.

CloudMonkey runs directly through `asyncio.create_subprocess_exec`, never a host shell. Temporary credential configuration is mode 600 in tmpfs and removed after execution. Command and parameter policy is checked before dispatch, including blocking CloudMonkey's local file expansion. Async job IDs are polled under the same identity. Responses are bounded and redacted. The audit log records actor, operation, target, time and outcome without plaintext parameters or credentials.

## Durable operations

Subgroup provisioning persists intent before making CloudStack changes. Stable operation IDs appear in generated domain/account/key names. Each successful stage persists its IDs; retries find existing resources under the same parent. Credentials are validated before the new agent becomes visible. Lost key-registration responses are handled by finding and revoking that operation's keys before replacement.

Credential rotation stores its old keys, replacement keys and operation ID durably. New keys are validated before the active credential record changes; old keys are revoked afterward. Retry resumes the same operation.

Managed VM templates use backend-generated cloud-init for unique non-root SSH credentials and a generated guest host key whose public half is pinned before first connection. Deployment intent and encrypted access information are saved before dispatch. A stable VM name permits recovery after a lost response. Ambiguous deployments are never automatically submitted a second time.

## Guest access and host boundary

Before each SSH operation the backend asks CloudStack for the VM using the calling agent's runtime identity. It obtains its current default NIC address, checks approved guest CIDRs, rejects host/local addresses, and verifies the recorded host key. Missing credentials fail closed. AsyncSSH has no access to the host SSH agent or SSH config. File transfers use directory-relative file descriptors, no-follow opens, per-agent workspaces and bounded sizes.

Host administration remains outside these tools. There is no generic shell on the server, no runtime API for host mounts, and no host filesystem bind in the application container beyond individual secret files. Extending the runtime API policy requires platform-administrator code review.
