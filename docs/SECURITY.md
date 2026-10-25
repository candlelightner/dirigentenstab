# Security

Dirigentenstab is an administrative application. An authorized agent can change and destroy CloudStack resources inside its delegated domain. Keep management and guest networks private and use CloudStack quotas, backups and domain boundaries.

## Credentials and sessions

All CloudStack keys, provider keys, guest private keys, CloudStack browser sessions, and conversation messages use Fernet authenticated encryption. The master key is a separate file mounted as a Docker secret. SQLite UUIDs, display names, provider URLs, conversation titles and audit metadata remain plaintext. Back up the master key independently; losing it makes encrypted records unrecoverable.

The application never stores a human CloudStack password. Login attempts are bounded by persistent per-client and per-username limits. Session cookies are opaque, HttpOnly, Secure and SameSite Strict; only hashes are indexed in SQLite. Logout revokes the local session even if CloudStack is temporarily unavailable. CloudStack user/account status is checked again on protected operations. There is no public registration.

HTTP mutations and socket handshakes require the configured exact HTTPS Origin. Logout also requires the session CSRF token. Socket events are bound to the session that created the NiceGUI client and to its registered socket. Reverse proxies must preserve Origin, cookies and WebSocket upgrades; do not add wildcard CORS or trust arbitrary forwarded client headers.

## Infrastructure keys

Keys are expiring CloudStack 4.23 key pairs, normally valid for 90 days. CloudStack's account role and native API-key rules are the sole infrastructure permission authority. The application discovers the effective APIs through that exact key's `listApis`; it has no infrastructure API allowlist or persisted permission copy. A newly created child's runtime grants derive from the parent's actual native runtime catalogue and its signing key's native permissions. CloudStack checks domain ownership, role and key restrictions on every request. Ordinary account/domain/VM/network/volume operations are available when that native identity permits them.

Runtime and provisioning credentials remain separate. Only trusted backend provisioning and credential-maintenance workflows receive the provisioning pair. Generic model tools cannot retrieve or issue keys, change authentication/role policy, execute host extensions, configure hypervisors/storage pools, or bypass the privileged GPU controller. These are technical host/credential boundaries, not a second infrastructure permission policy. API signatures are discovered, not manually specified. Parameters such as `extraconfig`, `details`, `hostid`, `hypervisor`, `path`, credential selectors and CloudMonkey file-input syntax are rejected. Never replace agent accounts with CloudStack root-admin accounts.

The managed subordinate-agent feature switch controls creating an application AI-agent entity, its model/instructions and durable provisioning workflow. It does not authorize or deny ordinary CloudStack APIs: native-authorized `createDomain`/`createAccount` remain usable through the runtime tools regardless of that feature switch. Conversation ownership, managed guest SSH enrollment and privileged host-helper policies remain application/host security boundaries.

Rotation reads and clones each pair's ordered native `listUserKeyRules` result, preserving allow/deny precedence and wildcard patterns. It never reconstructs permissions from SQLite or broadens an unavailable/expired key to its account role. Native rules and exact owner are verified before the replacement is committed; old-key deletion is durable and recoverable. Missing native proof stops rotation. To change the key-rule envelope, create a specifically scoped key through CloudStack, then have a human platform administrator explicitly adopt that exact key ID using `scripts/admin.py adopt-key`. No newest-key selection, Python code edit, or shared runtime/provisioning key is permitted. Native role changes remain constrained by the key's native rule envelope.

CloudStack permissions and quotas are the final infrastructure boundary. The installer must not expose unauthenticated libvirt TCP, disable host SSH protections, or attach existing host directories to guest VMs. Dedicated NFS secondary storage is owned and controlled by platform setup; it is not a general host export or an agent-selectable mount.

## Models and data

The configured provider receives the prompt, compact domain context and requested tool results. Choose local inference when these must remain on your machine. Provider configuration is platform-admin only. Keys are decrypted only inside the backend and are redacted from tool responses and stored histories. Treat tool results and model instructions as untrusted; authorization does not depend on prompts.

Managed template cloud-init includes a generated *guest host* private key, allowing a public key to be pinned before SSH. This key is unique to the guest and has no host privileges. User-data is encrypted locally and redacted from generic API responses. Models never receive guest client private keys, CloudStack keys or provider keys. Existing VMs without enrolled SSH credentials or host-key pins fail with a missing-access error.

Guest users have no password, no root SSH and no default sudo. File transfers expose only that agent's application workspace; local path arguments are basenames, with an 8 MiB file limit. The application has no Docker socket, hypervisor socket, SSH agent or arbitrary host directory mount.

## Operations

Keep `.env`, `secrets/`, databases and host setup state outside Git. Host setup logs and bootstrap identities are root-private. Never paste them into issues or model chats. Debug logging in CloudStack can contain sensitive API information; use INFO logging and revoke keys if diagnostic output exposes them.

Public GH Actions execute fixture-based tests only. Real infrastructure tests require explicit invocation on a trusted private environment. Do not run untrusted pull-request code on your administrative host. Images are published by version tags; deployment is a separate administrator action.

Private build capabilities are explicit: only an approved build template grants guest-local sudo, while non-root SSH, per-VM keys and host-key pins remain mandatory. Only owned stopped managed root volumes may become private templates; image publication and owner overrides are unavailable. Uncertain image creation requires reconciliation before repetition. Operator-approved assets are separately bound to exact agent IDs and verified by size/SHA-256 before SFTP; arbitrary workspace transfers keep their 8 MiB bound. The existing application volume holds these read-only binaries; no additional host mount is introduced. Dashboard quicklinks are human platform-admin only, contain no credentials and use a separately configured browser endpoint.
