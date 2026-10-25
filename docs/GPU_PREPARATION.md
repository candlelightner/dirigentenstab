# P40 guest build preparation

The final GPU image build and workload acceptance must be started by the human through **Main Agent in the web UI**. Preparation includes disposable native GPU allocation/lifecycle tests, but does not build a GPU-worker image, install guest NVIDIA software, or run a GPU workload.

## Verified host and CloudStack prerequisites

On the reference host (2026-10-25), NVIDIA vGPU Manager **535.309.01 / vGPU 16.14** remains installed on Tesla P40 `0000:07:00.0`. The GPU uses the NVIDIA driver, IOMMU group 12, a 32 GiB BAR1 aperture, and 24 GiB framebuffer. No driver, PCI, BAR, kernel or storage configuration was changed. The manager is active.

The host exposes these real mediated profiles: Q-series 1/2/3/4/6/8/12/24 GiB, A-series 1/2/3/4/6/8/12/24 GiB, B-series 1/2 GiB, P40-1B4 and P40-2B4. Profile capacities are alternatives on one physical GPU, not additive independent pools.

CloudStack 4.23's installed `gpudiscovery.sh` enumerates **instantiated** mdevs. Initially none existed; rediscovery therefore exposed only passthrough. Its `createGpuDevice` API registers inventory records; it does not instantiate a Linux mdev ([implementation](https://github.com/apache/cloudstack/blob/4.23.0.0/server/src/main/java/org/apache/cloudstack/gpu/GpuServiceImpl.java#L460)). The optional controller uses standard `mdevctl` persistent automatic definitions, then native rediscovery. The installer also supplies `xmlstarlet`: without it, native discovery incorrectly reported an attached mdev as Free. The controller independently checks actual libvirt attachments and fails closed on disagreement. No inventory entry is fabricated.

| Prerequisite | Reference deployment |
| --- | --- |
| Real profiles | `nvidia-47` / P40-2Q (up to 12), `nvidia-51` / P40-8Q (up to 3), `nvidia-53` / P40-24Q (1) |
| Original 2Q offering | `dc76eb30-18e9-4046-a14f-ddc8c3fc3058`, 2 CPUs / 4 GiB RAM |
| Small 8Q offering | `fa8a6b79-ac61-4a99-9fdf-db8a3f7114b2`, 1 CPU / 1 GiB RAM |
| Small 24Q offering | `bfb6f638-5d75-4a17-bff8-fc6b634a2bc4`, 1 CPU / 1 GiB RAM |
| Offering settings | `gpucount=1`, actual native mdev profile, 20 GiB local root disk; platform administrator creates offerings through GPU policies UI |
| Scope | Main Agent domain `44752458-45ae-4821-a6a2-bb112ab31754` (and authorized descendants); verified visible with Main Agent's restricted key |
| GPU quotas | Main domain explicitly capped at 3 through native resource type 16; account limit remains 20. Both Native ROOT and Main have explicit restrictive policy documents. Missing child policy denies GPU operations |
| Approved Ubuntu build base | `c2d0a60b-460d-46d5-bf75-85cce3a8b4c0`, private Ubuntu 22.04, immutable Canonical release 20261020 |
| Base SHA-256 | `2099e63da0b822ef8e05e3d596c1b402eaaae658fc08ab919cb8495bfcdc488b` |

The pristine base contains no NVIDIA components. Registration used Canonical's immutable image URL and CloudStack's `{SHA-256}` checksum syntax. An administrator explicitly approved guest sudo for new VMs from this build template. Other existing templates retain their previous guest permissions. Private templates derived through the controlled creation path inherit that approval. SSH still uses a non-root identity and a unique per-VM key and host-key pin.

Primary/secondary storage on the host's root filesystem has approximately 58 GiB available at preparation time; the existing archive primary pool has approximately 1.5 TiB available. Check actual free space and CloudStack placement before the later build and clone, allowing room for image copies and package installation. No disk, pool or existing volume was reformatted or moved.

## Private driver delivery

The matching **535.309.01** guest `.run` installer is staged by an operator in the existing application's private volume. Neither the archive nor any binary payload is committed, included in the container image, sent to a provider, or served over HTTP. No extra host mount or public endpoint is introduced.

Main Agent's approved asset ID is `nvidia-grid-535-309-01`, size **347,794,609 bytes**, SHA-256 `a5fa966d2de4953b4e7cb8016064bc23a8f9a0cd23f56e10cd122a785426d5ff`. The backend streams it only to an authorized managed guest through pinned-key SFTP:

```text
transfer_vm_file(vm_id=AUTHORIZED_VM_ID,
                 source="asset:nvidia-grid-535-309-01",
                 destination="/tmp/nvidia-guest.run", direction="upload")
```

The model receives metadata/receipts, not binary contents or host paths. The normal workspace upload/download limit stays **8 MiB**. Only explicitly approved assets may exceed it (hard maximum 512 MiB); the backend verifies the staged file's digest and size before opening the remote destination. Symlink sources, unrelated-agent assets and tampered payloads fail closed. The operator owns the staged read-only directory/files.

To prepare another installation, use `scripts/stage_guest_asset.py --source PRIVATE_LOCAL_BUNDLE --id ASSET_ID --name DISPLAY_NAME --agent-id APPROVED_AGENT_ID --sha256 EXPECTED_SHA256` as root. Verify acquisition and licensing through your authorized supplier. Never put license credentials in the command line or chat. This setup requires no Agentor imports.

## Agent capabilities and administrator boundary

`createTemplate` and `changeServiceForVirtualMachine` are the only added runtime APIs. Existing `listServiceOfferings` selects an authorized offering; GPU offering administration is not exposed as an agent tool. Physical discovery, offering creation, quotas and policy changes remain authenticated human platform-administrator operations. The scoped controller performs only lifecycle actions explicitly permitted by those policies.

For an existing agent, a human platform administrator explicitly enables the new API using the existing durable key rotation:

```sh
sudo .venv/bin/python scripts/admin.py rotate AGENT_ID --allow-api createTemplate
sudo .venv/bin/python scripts/admin.py rotate AGENT_ID --allow-api changeServiceForVirtualMachine
sudo .venv/bin/python scripts/admin.py approve-template TRUSTED_TEMPLATE_ID --guest-admin
```

Template approval is an explicit guest privilege grant: use it only for a trusted build base. Ordinary key rotation preserves previous policy; it does not silently grant new APIs. Newly provisioned agents receive the current scoped runtime allowlist. No unrestricted administrator key enters the agent container or context.

Private template creation accepts only an owned, stopped managed VM's root volume. Public/featured images, owner overrides, arbitrary URLs and unmanaged sources are denied. The app verifies native account/domain ownership and readiness before approving the result for managed deployment. Creation intent/result is encrypted and durable; unresolved dispatches block repetition. `recover-templates` only locates and binds existing ready private templates; it never creates another image. An owned interrupted chat can then use `repair-execution RUN_ID --deployment-id TEMPLATE_OPERATION_ID` and its existing Continue action.

Before creating a reusable image, the agent must remove temporary installers and machine-specific secrets, remove the source's authorized SSH keys/host keys, run `cloud-init clean --logs --machine-id`, and stop the source. Subsequent deployment receives fresh backend-generated guest credentials. Do not bake licensing tokens into a reusable image.

## Persistent installation and GPU policies

On a compatible host with its licensed NVIDIA vGPU Manager already installed, set `ENABLE_GPU_CONTROL=true` in `.env` **before the standard installer**. `setup.sh --install` (or `--existing`) installs `mdevctl`/`xmlstarlet`, detects the single local mdev-capable GPU and verified native KVM host, installs the socket-activated root controller, and adds the private Compose socket mount. With multiple candidate GPUs, specify `GPU_PARENT`. Existing Compose override files are preserved. No Agentor import or manual package installation is needed. The licensed NVIDIA manager and private guest bundle are supplied by the operator, not redistributed by this repository.

The helper has no public listener or generic host-command API. The socket accepts only root/the backend UID, and the backend verifies the root peer. Root-owned `/var/lib/dirigentenstab/gpu-control.db` stores policies, explicit pool owners and operation receipts. CloudStack remains authoritative for hierarchy, accounts, authorization, GPU quotas and reservations. Persistent mdev definitions live in `/etc/mdevctl.d`; systemd and mdevctl restore service/device state after boot. An actual host reboot is not part of this update's validation.

Use **GPU policies** as a human platform administrator to set profiles, native maximum allocations, release on stop, unused-pool reconfiguration and subgroup capacity permissions. Every ancestor must grant permission; a child only narrows it. Existing free devices require an explicit administrator ownership claim. Agents cannot create policies, claim devices, create offerings or access host credentials. A requesting group may change only devices owned by itself or descendants, with the device owner's policy also enforced. Unknown owners, foreign devices, allocated/reserved devices and actual libvirt attachments prevent reconfiguration. Because native allocation offers no domain-specific device selector, ambiguous same-profile capacity in other pools/hosts is rejected rather than risking a foreign assignment.

GPU operations are serialized and use stable server-side run/tool-call identifiers. Native VM mutations use the requesting agent's restricted credentials. Stop applies the authorized domain-scoped native `gpu.detach.on.stop`; stopped GPU-to-CPU offering changes release quota. Resource resizing on a stopped VM may retain the exact same profile/count. Profile changes require release to CPU first. Unused, owned homogeneous pools can then transition from three 8Q devices to one 24Q device when every effective policy, native reservation and physical constraint permits it. No unrelated VM is stopped.

Interrupted dispatches require read-only reconciliation before another GPU change. Administrators can inspect/reconcile saved GPU operations in the same dialog; pre-dispatch plans may be resumed. The original conversation's **Check GPU recovery** verifies the controller's receipt against its original human and agent, preserves completed activity, and offers the existing safe continuation action. It never repeats an ambiguous deployment. Back up both SQLite databases, their matching app key/configuration and mdev definitions before upgrades; see [RECOVERY.md](RECOVERY.md).

For repeatable hardware acceptance, `scripts/gpu_lifecycle_acceptance.py --run --cleanup` uses a real CloudStack-backed human login, Main Agent, the normal web UI, durable conversation continuation, native result verification and desktop/mobile screenshots. It stops before any NVIDIA installation/image/workload. Supply root-private `/var/lib/dirigentenstab/setup/gpu-lifecycle-test.json` with `origin`, `zone_id`, `template_id`, `offering8`, `offering24`, and `cpu_offering`; these identify already approved resources, not credentials. Human login is read only from the protected setup file (or `--credentials-file`), never a fixture/provider key. The optional manual private-cloud CI input enables this test on an already prepared acceptance runner with Playwright; it defaults off. Its saved receipt prevents resubmission after interruption. Cleanup is a separately authorized root-operator action using protected maintenance credentials: the agent's runtime role is not widened to allow expunge. Cleanup verifies the exact four IDs, native account/domain, test names and stopped CPU-only offerings, excludes every baseline VM, and checks the original inventory afterward. Archive a completed receipt deliberately before starting a new acceptance run.

## Licensing is separate from assignment

The operator will handle licensing inside the future guests. This update does not deploy a license service, transfer tokens, bypass enforcement or validate entitlement. A P40 Q-series profile requires the appropriate NVIDIA vWS entitlement and authorized NVIDIA License System configuration; successful mdev assignment alone does not prove licensing or usable CUDA. See [NVIDIA's licensing requirements](https://docs.nvidia.com/vgpu/sizing/virtual-workstation/latest/overview.html) and [release matrix](https://docs.nvidia.com/vgpu/index.html). The 16.x branch's listed vendor support period ended July 2026; the working host installation was intentionally preserved. Any future upgrade is a separate platform-administrator decision.

## Remaining acceptance gate

The final GPU-worker image and GPU workload have **not** been built or tested. Start the later task in the normal web UI. Require the selected real 2Q offering, approved Ubuntu build base, private bundle delivery, authorized guest licensing, driver/device verification, creation of a private reusable template, a second deployment and actual GPU workload evidence. Select a guest CUDA/application stack compatible with Pascal and the installed 535 driver. Preserve all pre-existing VMs and stop on ambiguous outcomes rather than replaying creation.
