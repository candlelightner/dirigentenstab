# Security

Dirigentenstab is an administrative application. An authorized agent can change and destroy CloudStack resources inside its delegated domain. Keep management and guest networks private and use CloudStack quotas, backups and domain boundaries.

## Credentials and sessions

All CloudStack keys, provider keys, guest private keys, CloudStack browser sessions, and conversation messages use Fernet authenticated encryption. The master key is a separate file mounted as a Docker secret. SQLite UUIDs, display names, provider URLs, conversation titles and audit metadata remain plaintext. Back up the master key independently; losing it makes encrypted records unrecoverable.

The application never stores a human CloudStack password. Login attempts are bounded by persistent per-client and per-username limits. Session cookies are opaque, HttpOnly, Secure and SameSite Strict; only hashes are indexed in SQLite. Logout revokes the local session even if CloudStack is temporarily unavailable. CloudStack user/account status is checked again on protected operations. There is no public registration.

HTTP mutations and socket handshakes require the configured exact HTTPS Origin. Logout also requires the session CSRF token. Socket events are bound to the session that created the NiceGUI client and to its registered socket. Reverse proxies must preserve Origin, cookies and WebSocket upgrades; do not add wildcard CORS or trust arbitrary forwarded client headers.

## Infrastructure keys

Keys are expiring CloudStack 4.23 restricted key pairs, normally valid for 90 days. Rotate them before expiry from agent settings. Runtime keys do not permit account/domain/key creation or modification. Only the backend's subgroup tool receives provisioning credentials. A child is created as a DomainAdmin in the actual parent domain; callers cannot choose a parent domain or elevate its account type.

The runtime allowlist is deliberately reviewed and finite. API signatures are discovered, not manually specified. Host configuration, libvirt, storage pools, extension execution, arbitrary extra VM configuration and host paths are unavailable. Parameters such as `extraconfig`, `details`, `hostid`, `hypervisor`, `path`, credential selectors and CloudMonkey file-input syntax are rejected. This applies even if an LLM asks for them. Never replace agent accounts with CloudStack root-admin accounts.

CloudStack permissions and quotas are the final infrastructure boundary. The installer must not expose unauthenticated libvirt TCP, disable host SSH protections, or attach existing host directories to guest VMs. Dedicated NFS secondary storage is owned and controlled by platform setup; it is not a general host export or an agent-selectable mount.

## Models and data

The configured provider receives the prompt, compact domain context and requested tool results. Choose local inference when these must remain on your machine. Provider configuration is platform-admin only. Keys are decrypted only inside the backend and are redacted from tool responses and stored histories. Treat tool results and model instructions as untrusted; authorization does not depend on prompts.

Managed template cloud-init includes a generated *guest host* private key, allowing a public key to be pinned before SSH. This key is unique to the guest and has no host privileges. User-data is encrypted locally and redacted from generic API responses. Models never receive guest client private keys, CloudStack keys or provider keys. Existing VMs without enrolled SSH credentials or host-key pins fail with a missing-access error.

Guest users have no password, no root SSH and no default sudo. File transfers expose only that agent's application workspace; local path arguments are basenames, with an 8 MiB file limit. The application has no Docker socket, hypervisor socket, SSH agent or arbitrary host directory mount.

## Operations

Keep `.env`, `secrets/`, databases and host setup state outside Git. Host setup logs and bootstrap identities are root-private. Never paste them into issues or model chats. Debug logging in CloudStack can contain sensitive API information; use INFO logging and revoke keys if diagnostic output exposes them.

Public GH Actions execute fixture-based tests only. Real infrastructure tests require explicit invocation on a trusted private environment. Do not run untrusted pull-request code on your administrative host. Images are published by version tags; deployment is a separate administrator action.

Private build capabilities are explicit: only an approved build template grants guest-local sudo, while non-root SSH, per-VM keys and host-key pins remain mandatory. Only owned stopped managed root volumes may become private templates; image publication and owner overrides are unavailable. Uncertain image creation requires reconciliation before repetition. Operator-approved assets are separately bound to exact agent IDs and verified by size/SHA-256 before SFTP; arbitrary workspace transfers keep their 8 MiB bound. The existing application volume holds these read-only binaries; no additional host mount is introduced. Dashboard quicklinks are human platform-admin only, contain no credentials and use a separately configured browser endpoint.
