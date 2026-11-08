# Firecracker microVMs as a CloudStack extension

## Status: parked

Parked 2026-11-08; the KVM slim-VM path ships instead. All CloudStack registrations and the systemd units were removed;
only `/opt/dirigentenstab/firecracker` artifacts stay on the host (they speed up a retry).

Blockers (details under Limits): (1) CloudStack 4.23 cannot deploy External templates as registered (needs a CloudStack DB
edit or a release that fixes it, an owner decision); (2) the Basic-zone security-group iptables drop traffic to unregistered
taps (needs `security_group.py default_network_rules` per tap on start, or equivalent rules). Unverified risk: the real
`deployVirtualMachine` payload was never observed, so NIC/userdata/SSH-key (`vmData`) handling is assumed.

Retry: rerun `install.sh`, register an External template once blocker 1 is resolved, add the per-tap `security_group.py`
calls, capture one real payload, then run the staging end-to-end checks.

Spike result: host side works (boot, cloud-init, persistence, tap on the guest bridge). End-to-end through
`deployVirtualMachine` is blocked by two CloudStack 4.23 issues, see Limits.

## How it works

CloudStack 4.21+ "Extensions" (Orchestrator type, hypervisor `External`) call
`<extensions dir>/firecracker/firecracker.py <action> <payload.json> <timeout>` as user `cloud`. Actions implemented:
`prepare, create, start, stop, reboot, delete, status, statuses`. No management restart is needed to register an
extension (`createExtension` marks the path ready immediately).

* `cloud` cannot create taps or systemd units, so `firecracker.py` as `cloud` only forwards the payload to
  `/run/dirigentenstab-firecracker.sock`. That socket is systemd socket-activated (`Accept=yes`, group `cloud`); each call
  runs `/opt/dirigentenstab/firecracker/bin/firecracker.py --worker` as root, which does the work and exits. No daemon.
* Per VM, `/var/lib/dirigentenstab/firecracker/<vm uuid>/` holds a sparse copy of the Ubuntu 24.04 rootfs (persists
  across stop/start, removed on `delete`), `vm.json` (Firecracker config), `seed.img` (cloud-init), `console.log` (serial).
* Firecracker runs as transient unit `fc-<uuid>.service` (`systemd-run`), so it survives management/worker restarts.
* One tap `fc<uuid8>n<i>` per NIC, enslaved to the guest bridge (`dscloud0`), MAC = CloudStack NIC MAC. Taps are removed
  on stop/delete.
* cloud-init: second block device `seed.img`, an ext4 volume labelled `cidata`. The Firecracker guest kernel has no
  iso9660/vfat, and cloud-init's blkid lookup races virtio probing, so the rootfs mounts `/dev/vdb` as
  `/var/lib/cloud/seed/nocloud` before `cloud-init-local` (`guest-seed.sh`). Hostname, SSH keys and user-data come from
  the payload's `cloudstack.vm.details.vmData` (assumed shape, see below); network config is DHCP on the NIC MAC.
* Artifacts (pinned, checksum-verified by `install.sh`): Firecracker v1.17.0, CI guest kernel 6.1.188, Ubuntu 24.04
  cloud image release-20261017 converted to a bare ext4 (snapd and other idle services masked, boot is ~3 s to ssh).

## Install

    scripts/cloudstack-extensions/firecracker/install.sh

Idempotent. Places files, enables the socket, and registers extension `firecracker`, cluster `fc-cluster` and host
`http://fc-host-homeserver` (external detail `bridge=dscloud0`). Nothing is restarted.

Uninstall: `deleteTemplate`/`deleteExtension` objects named `fc-*`/`firecracker` via the API (host and cluster first),
`sudo systemctl disable --now dirigentenstab-firecracker.socket`, remove
`/etc/systemd/system/dirigentenstab-firecracker*`, `/etc/cloudstack/extensions/firecracker`,
`/opt/dirigentenstab/firecracker`, `/var/lib/dirigentenstab/firecracker`.

## Limits and open problems

1. External templates cannot be deployed on 4.23 as registered. `registerTemplate hypervisor=External extensionid=...`
   creates a `template_store_ref` row with `store_id NULL`, `store_role NULL`, `size NULL`; `deployVirtualMachine` then
   fails with "Template ... has not been completely downloaded to zone" (with `rootdisksize`: NPE on
   `VMTemplateVO.getSize()`). `directdownload=true` is refused for External; ISOs have no extension so the planner
   (`ExternalServerPlanner`) rejects them. Untested workaround: set `vm_template.size` and `template_store_ref`
   (`store_role='Image'`, `download_state='BYPASSED'`, `size`) for the template row in the CloudStack DB, mirroring a KVM
   direct-download template. This is a DB edit and was not applied.
2. Basic zone security groups: CloudStack's KVM agent registers each `vnetN` in iptables chains `BF-dscloud0*`. An
   unregistered tap is dropped for everything routed or bridged *to* it (`FORWARD -o dscloud0 -j DROP`): the virtual
   router's DHCP offers reach the bridge but not the guest (verified with tcpdump and the drop counter). Needed: run
   CloudStack's `security_group.py default_network_rules` for the tap on start (and `destroy_network_rules_for_vm` on
   stop), or equivalent accept rules. Host-originated traffic (ssh from the host, staging hub) and guest-to-host traffic
   already work without it.
3. The External host reports 0 CPU / 0 memory; capacity checks may need host details.
4. Stop is a hard power-off (no ACPI/agent; `SendCtrlAltDel` is ignored by the guest).
5. Guest kernel has no modules (no iptables/docker/overlay in the guest beyond what is built in) and no jailer: the
   Firecracker process runs as root with its default seccomp filter only.
6. Payload shape for NIC MACs is taken from the shipped Proxmox/HyperV examples (`cloudstack.vm.details.nics[].mac`,
   `.name`, `.cpus`, `.minRam`); userdata/SSH keys (`vmData`) and `virtualmachineid` were not observed in a real payload.
   The CloudStack docs state user data is unsupported for external VMs at the framework level.
7. `getconsole` is not implemented; the serial log is on disk.
