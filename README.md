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

## Security boundaries

- Human passwords remain with CloudStack. Application sessions are server-side, expiring and revocable; cookies use HttpOnly, Secure and SameSite Strict.
- Agents are distinct CloudStack **domain administrators**, never host administrators. Runtime and provisioning API keys are separate, restricted and encrypted.
- Host filesystems, libvirt, host mounts, storage pools, extensions and hypervisor configuration are platform-administrator operations. Runtime tools reject them, including `extraconfig`, `details`, host-path parameters and CloudMonkey `@file` expansion.
- Guest SSH uses a dedicated non-root user, a unique per-VM client key and a verified host-key pin. Transfers are confined to the agent's application workspace. No Docker socket or arbitrary host directories are mounted in the application.
- Infrastructure operations can change or delete resources within the agent's CloudStack permissions. Only configure agents and providers you intend to authorize.

Read [architecture](docs/ARCHITECTURE.md), [security](docs/SECURITY.md), [recovery](docs/RECOVERY.md), and [testing](docs/TESTING.md) before operating a cloud containing valuable data.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps -e .
.venv/bin/ruff check .
.venv/bin/pytest -q -m 'not browser and not live'
```

CI runs unit and integration checks and builds the image. Chromium browser tests run in their own job. A version tag publishes `ghcr.io/candlelightner/dirigentenstab:<version>`. Pushing or publishing an image never deploys it to your host.

CloudStack 4.23 is a regular release supported until the next regular or LTS release. It is pinned for restricted API-key support; schedule upgrades using the upstream release notes rather than enabling unattended CloudStack upgrades. Third-party components retain their own licenses; see [third-party notices](docs/THIRD_PARTY.md).
