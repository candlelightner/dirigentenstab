# Installation

The native installer targets Ubuntu Server 24.04 LTS on x86-64 with working `/dev/kvm`, at least 8 GiB available RAM and 50 GiB free disk. Allocate more space for guest images. It installs a real KVM environment, never a simulator. Use an existing CloudStack installation when the host already has libvirt VMs or MySQL databases: the installer refuses to adopt, delete, or upgrade those resources.

```sh
git clone https://github.com/candlelightner/dirigentenstab.git
cd dirigentenstab
cp .env.example .env
nano .env
sudo ./setup.sh --preflight
sudo ./setup.sh --install
docker compose up -d
sudo ./setup.sh --verify
```

Run Docker with the privileges appropriate to your installation (`sudo docker compose ...` if your user cannot access the daemon). The application defaults to `127.0.0.1:3000`. If another application owns that port, change both `BIND_PORT` and `PUBLIC_ORIGIN`; the reference host uses port 3001 to preserve Agentor. Set a single HTTPS `PUBLIC_ORIGIN` that matches the browser URL exactly. The installer creates a local certificate, separate encryption key and persistent application volume, installs the pinned Python environment, and bootstraps the first agent. No source-code edits are required.

The native installation creates CloudStack's `admin` human identity and immediately replaces the installation password with a random password. Retrieve it using a local privileged editor on `/var/lib/dirigentenstab/setup/initial-admin.json`, then place it in your password manager. Dirigentenstab never stores this password in SQLite. Use the same identity in either web interface. CloudStack bootstrap API keys remain in a separate root-private installation file; they are not mounted in the application container.

## Versions and upstream support

CloudStack **4.23.0.0** is pinned in APT. It is the current 4.23 patch release verified for this implementation, released September 2026, and a **regular**, not LTS, release. Its support ends at the next regular or LTS release; plan the next supported upgrade rather than treating this pin as permanent. Consult the [release downloads](https://cloudstack.apache.org/downloads/), [4.23 compatibility matrix](https://docs.cloudstack.apache.org/en/4.23.0.0/releasenotes/compat.html), and [upgrade guide](https://docs.cloudstack.apache.org/en/4.23.0.0/upgrading/) before changing the pin.

Native dependencies are Java 17, MySQL 8.4 LTS from Oracle's signed repository, Ubuntu's libvirt/QEMU packages, and NFSv4. The tested MySQL package is 8.4.13 on Ubuntu 24.04. APT continues to supply MySQL 8.4 maintenance releases; review and test these updates. The CloudStack and Oracle keys use dedicated `signed-by` keyrings with fingerprint validation. CloudMonkey **6.6.0** uses a pinned SHA-256 verified binary. Python runtime dependencies are pinned in `requirements.lock`.

CloudStack's 4.23 package intentionally bundles the compatible **4.22.0 system VM template**, which is automatically seeded through CloudStack's supported mechanism. Managed guest deployments use an immutable official Ubuntu 24.04 image from release **20261017**, with its SHA-256 passed to CloudStack. Updating guest images is a platform-administrator action and does not modify existing guest disks.

## What native setup changes

The installer inventories virtualization, routes, listening ports, PCI devices, memory and storage. It creates an isolated bridge `dscloud0`, a `dummyds0` carrier, private subnet `10.253.80.0/24`, and CloudStack's own link-local control bridge. It never attaches the host uplink to that bridge or replaces the default route. A collision with an existing subnet or link-local metadata route stops setup before native configuration.

CloudStack management listens on `10.253.80.1:8080`; MySQL stays on loopback. A dedicated dual-stack nftables input table restricts native management/storage ports to loopback and the private bridge, with only the application container `172.30.253.2` additionally allowed to reach port 8080. A separate scoped IPv4 NAT rule provides guest outbound connectivity. Existing firewall tables are not flushed. The application uses its own Docker bridge `172.30.253.0/24` and exposes only its configured local port.

Primary storage lives in `/var/lib/libvirt/images/dirigentenstab`, accessible to the non-root `libvirt-qemu` identity. Secondary storage is a dedicated directory `/var/lib/dirigentenstab/secondary`, exported with **root squashing** only to the host and system-VM management ranges `.16/28` and `.32/28`. Ordinary guest allocation `.100-.220` is excluded from this export ACL. AppArmor remains enabled; libvirt uses its local Unix socket. The installer does not enable unauthenticated libvirt TCP, public SSH forwarding, root SSH, or host filesystem shares for agents.

The Basic zone uses CloudStack security groups. Managed guest SSH needs ingress TCP 22 from the application's effective internal source, normally `10.253.80.1/32` after Docker NAT. Apply the rule to the managed account/security group, never `0.0.0.0/0`. No guest ports need publication on the physical host. Native setup also installs `dirigentenstab-guest-ssh.timer`: it maintains tagged application-to-guest TCP/22 exceptions and the isolated guest network's routed Internet path ahead of CloudStack bridge drops. Routed guest traffic retains each native VM's source-IP anti-spoof guard and live security-group egress chain; trusted system-VM traffic follows its native chain, and return traffic requires an established/related connection. Unknown guest ports remain blocked. It starts handling the Docker bridge when `docker compose up` creates it. On an existing native installation, apply this prerequisite with `sudo ./setup.sh --guest-ssh`; this narrow mode does not rerun CloudStack/storage setup or restart the application/native services. The helper has a `--remove` rollback; see [release notes](RELEASE_0.1.4.md).

CloudStack 4.23 performs an upstream whole-filesystem VMware VDDK library search during KVM initialization and capability discovery. Hosts with large archive trees may start slowly even when VMware migration is unused. Allow this search to finish before diagnosing KVM failure; it does not imply a need to install proprietary VMware libraries. Installer retries preserve the existing zone and credentials.

## Existing CloudStack

Configure the private `CLOUDSTACK_URL`, HTTPS `PUBLIC_ORIGIN` and a root-private JSON credential file containing `apikey` and `secretkey`. Set `CLOUDSTACK_BOOTSTRAP_CREDENTIALS_FILE` to its path and restrict it to mode 0600. The API identity must be authorized to create the top-level Agents domain and issue one API key pair for its managed account without extra per-key rules.

```sh
sudo ./setup.sh --install --existing
docker compose up -d
sudo ./setup.sh --verify --existing
```

This path prepares only application prerequisites, credentials, SQLite and the first agent. It neither installs CloudStack nor modifies its zone, storage or hypervisor. The remote API and approved guest networks must be reachable from the application container. Register trusted Linux cloud-init templates through the platform administrator configuration before managed guest creation.

## Stopped VM capacity reservations

CloudStack 4.23 defaults `capacity.skipcounting.hours` to **3600 seconds**, despite its name. Stopped VMs retain CPU/RAM reservations during that interval. A deployment with frequent start/stop operations can therefore report `No destination found` while the host has free physical resources. Inspect actual allocated/reserved capacity and the unchanged admission thresholds first; wait for reservation expiry when appropriate.

A platform administrator may explicitly choose a shorter interval, such as 60 seconds, for an owned deployment. This is a **global CloudStack policy**, affecting the entire connected installation. The 4.23 capacity manager reads it at management-server configuration time, so applying or rolling back the change requires restarting only `cloudstack-management`. Record the previous value and obtain the deployment administrator's authorization before changing it through CloudStack Global Settings or its supported `updateConfiguration` API. Do not increase CPU/RAM overcommit ratios or disable capacity thresholds to work around stopped reservations. Neither the installer nor `--existing` changes this policy automatically.

The implementation is visible in Apache's [capacity manager](https://github.com/apache/cloudstack/blob/463f8d0294702a920e8020b62ae3b67f52ae1473/server/src/main/java/com/cloud/capacity/CapacityManagerImpl.java) and [configuration definition](https://github.com/apache/cloudstack/blob/463f8d0294702a920e8020b62ae3b67f52ae1473/server/src/main/java/com/cloud/configuration/Config.java). Recheck these semantics when upgrading CloudStack.

## HTTPS, Cloudflare Tunnel, Tailscale and consoles

For the reference host's scoped persistent CPVM route, installation and Windows
reboot checks, see [CONSOLE_ACCESS.md](CONSOLE_ACCESS.md). The optional
[Ubuntu XFCE template procedure](DESKTOP_TEMPLATE.md) is future work for new,
explicitly authorized builder VMs; it does not modify running guests.

The local application serves HTTPS and NiceGUI WebSockets on the same port. Accept the generated development certificate locally or replace the certificate/key secret with a certificate trusted by your clients. `PUBLIC_ORIGIN` must match your actual HTTPS origin, including any non-default port. Secure cookies deliberately do not work over plain HTTP.

For Cloudflare Tunnel, configure a route only when you choose to publish it, targeting the local HTTPS application listener; configure origin certificate trust or an explicit origin TLS policy for that tunnel. Forward WebSocket upgrades and preserve the browser Host/Origin. For Tailscale Serve, target the local HTTPS listener and configure the corresponding tailnet HTTPS origin. Do not overwrite existing tunnel/Serve routes; the installer leaves Cloudflare Tunnel, Tailscale and SSH untouched.

The CloudStack interface and its API remain private. Access the management interface using an SSH local forward or an explicitly configured private HTTPS proxy. CloudStack's console proxy is a separate endpoint: browser console use requires routing to the CPVM's private address and the console ports configured in CloudStack, plus a console-proxy HTTPS certificate/domain that browsers trust. Configure that private route deliberately; forwarding only the Dirigentenstab port does not forward CloudStack consoles. Do not publish management APIs, console VNC ports, NFS, libvirt or guest SSH to the Internet.

Versioned images are published to GHCR when a version change in `pyproject.toml` reaches main, or through an explicit matching version tag. The release workflow creates its tag and release notes using the repository-scoped GitHub Actions token and refuses to repoint an existing version tag. Production deployment is manual: review the image/version, back up the database and independent master key, set `IMAGE`, pull, and run `docker compose up -d`. There is no push-triggered host deployment.

## Native CloudStack dashboard quicklink

Set optional `CLOUDSTACK_UI_URL` to the native dashboard URL reachable from the **browser**, for example a separately configured private Tailscale HTTPS endpoint ending in `/client`. Do not derive it from the internal `CLOUDSTACK_URL` API address. Blank disables the link. Human platform administrators can override or hide it through **Platform settings**; domain administrators and agents do not receive this setting. Both desktop header and mobile navigation expose the same external link, using ordinary CloudStack login in a separate tab. URLs containing embedded credentials, queries or fragments are rejected.

Creating the private reverse proxy is an operator action. On the reference host only, the added tailnet-only route is `tailscale serve --bg --https=3002 http://10.253.80.1:8080`, with browser URL `https://homeserver.tail3e59e6.ts.net:3002/client`. Existing 3000/3001/9443 routes were preserved. Do not enable Funnel or bind CloudStack's management API publicly. A fresh installation leaves the URL blank until its operator supplies a suitable private endpoint.

GPU build preparation is optional; see [GPU_PREPARATION.md](GPU_PREPARATION.md). Set `ENABLE_GPU_CONTROL=true` before standard setup to install its dependencies and persistent private controller automatically. The standard installer requires no imported hierarchy/workspaces and does not automatically install NVIDIA drivers, partition GPUs or grant policies/change quotas. NVIDIA's licensed host manager and any private guest bundle remain operator-supplied prerequisites.

## Network configuration

Set the literal `CLOUDSTACK_BRIDGE`, `CLOUDSTACK_NETWORK`, `CLOUDSTACK_GATEWAY`,
`CLOUDSTACK_SYSTEM_START/END`, `CLOUDSTACK_GUEST_START/END`, `APP_NETWORK`,
`APP_ADDRESS` and `TAILSCALE_INTERFACE` values in `.env` before setup.
`.env.example` shows the reference host's values. The CloudStack API URL and
application `SSH_NETWORKS` can derive from these values using Compose/dotenv
interpolation. `SSH_SOURCE_CIDR` is retired: managed deployment no longer
creates a security group. Network isolation is an explicit CloudStack decision
by the user/agent; SSH authentication and guest ownership checks still apply.

Existing networks are not moved by changing `.env`. Installers snapshot validated
network values into `/etc/dirigentenstab-network.env` for the host timers; rerun
`sudo python3 scripts/native_setup.py --guest-ssh` and
`sudo python3 scripts/install_console_forwarding.py` to update forwarding.
See [Tailscale VM access](CONSOLE_ACCESS.md) for route and client checks.
