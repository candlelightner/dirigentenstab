# Recovery and migration

Keep the SQLite database and its encryption master key in **independent backups**. Losing the key makes encrypted credentials and conversations unrecoverable. Store a protected copy of `.env`, the TLS key/certificate, and root-private native installation state separately from public source code. Use your normal encrypted backup system; never commit these files.

## Application backup and restore

For a simple consistent backup, stop only the Dirigentenstab application with `docker compose stop app`, copy the persistent Docker volume `dirigentenstab_data`, and restart it. Preserve ownership UID/GID 10001. An online SQLite backup must use SQLite's backup interface; copying an active database without its WAL is unsafe.

Restore the complete volume, restore the **matching** master-key secret, retain its restrictive permissions and UID 10001 readability, then run the selected image. The master key is never in the Docker image or database. A mismatched key must be corrected by restoring the right backup; do not generate a replacement key over an existing database. Restore the application's TLS secret pair as well. Sessions can be revoked; restore does not require recovering human passwords because CloudStack remains authoritative.

Before an application upgrade, make a consistent backup. Migrations run transactionally from numbered SQL files. When reverting an image whose schema expectations differ, restore its matching database snapshot rather than attempting an improvised reverse migration.

## Interrupted native installation

Native state is root-private under `/var/lib/dirigentenstab/setup`:

- `*.started` / `*.done` record installation stages.
- `originals/` retains the original versions of changed configuration files.
- `changed-files` identifies files written by setup.
- `commands.log` holds protected native package/setup diagnostics.
- `database-secrets.json`, `initial-admin.json` and `cloudstack-admin.json` are credentials, not public diagnostics.
- `zone.json` records actual CloudStack resource IDs and the pinned trusted guest image.

Rerun `sudo ./setup.sh --install` after resolving an interrupted package download or service prerequisite. Completed database initialization is skipped. If a `cloud` database exists without the completion marker, setup **stops**: inspect the native setup result and restore a database backup or validate the completed stage before continuing. Do not drop that database or remove markers merely to force a retry.

Use `sudo ./setup.sh --verify` for native service, KVM and actual API/zone checks. `--verify --existing` tests the configured existing CloudStack API through CloudMonkey without modifying native services. Verification requires the protected setup/bootstrap credentials to remain valid; rotate that installation credential deliberately when revoking it.

Useful service checks are `systemctl status cloudstack-management cloudstack-agent mysql libvirtd` and `virsh -c qemu:///system list --all`. Inspect native logs locally as an administrator. Keep API/debug logging disabled: verbose CloudStack request logging can expose credential material. Redact diagnostic exports before sharing them.

KVM launch failures reporting UID 64055 permission errors often indicate that a parent storage directory is not traversable by `libvirt-qemu`. Keep the dedicated primary directory owned by root with the QEMU primary group and mode 0750. Do not solve this by running all QEMU processes as root or disabling AppArmor. The native installer preserves AppArmor, verifies guest disk ownership through libvirt, and keeps libvirt on its Unix socket.

If strict HTTPS template validation fails, verify that the agent JKS contains both the CloudStack private CA/client key and the maintained system CA trust anchors. Do not disable certificate verification. The installer imports the system Java trust store while preserving the client key. CloudStack manages native certificate lifecycle; platform administrators must test renewal and refresh CA trust during upgrades.

## Partial subgroup and VM provisioning

Subgroup creation has durable SQLite stages because CloudStack and SQLite cannot share a transaction. Retry the recorded operation through the application after correcting the cause; inspect its phase and CloudStack resource IDs. Do not manually create a second account/domain with the same intended name. If an issued key could not be committed locally, reconcile or revoke it before retrying. CloudStack 4.23 requires the provisioning key's permission envelope to contain every permission it is authorized to delegate, while the application keeps that key inaccessible to generic agent tools.

Use `sudo .venv/bin/python scripts/admin.py status` to list incomplete operations. `recover-deployments` only queries CloudStack and binds a uniquely named Running or Stopped VM in the agent's exact account/domain to its prepared SSH record; it never creates another VM. Failed asynchronous jobs can leave VM records, so `failed` operations remain blocked until reconciled. Error, Destroyed, Expunging and transient VM states are never marked complete. Missing or ambiguous VMs and missing SSH records require administrator review. If an administrator confirms a definitive server rejection in private logs, verifies no VM/job exists, and needs to clear that attempt, use `resolve-rejection OP_ID --confirmed-rejection`. This explicit recovery action marks the operation `rejected`; it never automatically retries a deployment. Newly captured definitive API validation rejections also use the `rejected` terminal phase.

`repair-provisioning OP_ID` retries a subordinate operation with credential reconciliation. `rotate AGENT_ID` and `revoke AGENT_ID` authenticate a human administrator and check domain access. Revocation disables execution first and includes keys from interrupted rotations; rerun the CLI if a network error interrupts remote revocation. Disabled agents cannot be reselected for chat. Runtime restrictions are persisted so rotation after expiry cannot widen them; an unknown prior policy fails closed.

Guest SSH keys are unique per VM and encrypted in the application database. Restore that database and key together. Existing VMs without a stored managed SSH identity remain inaccessible through the SSH tools until an administrator establishes governed access. Host-key changes require administrator investigation and re-enrollment; never disable SSH host-key checking to recover access.

A failed asynchronous deployment can still leave a real Stopped VM. Reconcile its exact UUID, operation name, account and domain through `recover-deployments`; bind only the original pending encrypted SSH record. Do not create another VM or generate replacement keys merely because a job reported failure. For `No destination found`, inspect stopped-VM reservations as described in [INSTALLATION.md](INSTALLATION.md#stopped-vm-capacity-reservations). If an authorized administrator shortened the reservation policy, restore the recorded prior value through the supported configuration API and restart only the management server to roll it back. Existing native guests and host administrative services do not need to stop.

Failed creation can instead leave an `Error` VM, which CloudStack cannot start. A platform administrator must verify its exact operation/account/domain/UUID, terminal failed job, never-booted state, absent workspace copy and absent usable disks before expunging that empty placeholder through CloudStack's supported API. Preserve a private recovery receipt and the original encrypted SSH record. After confirming VM/volume absence and no pending job, use `resolve-rejection` to close that failed attempt; an explicit new attempt creates a new VM with its own SSH keypair. Existing workload VMs require their own data recovery procedure.

## Native rollback

Do not run a blanket uninstall on a host with guests. Stop new deployments, take CloudStack database and guest-disk backups, and export the current CloudStack configuration before maintenance. Original configuration copies and the changed-files ledger identify the limited native files introduced by Dirigentenstab. Review and restore individual files only after confirming which running VMs depend on them. Restart only the affected native service. Keep the host uplink, SSH and existing tunnel/Serve routes unchanged.

The installer deliberately provides no automatic destructive rollback: removing storage, MySQL, bridges or firewall rules while guests run can lose data or expose management endpoints. CloudStack management/database upgrades must follow the upstream supported sequence and include the relevant System VM template upgrade. A VM disk snapshot alone is not a backup of the management database or the application's encryption master key.

## Migrating from Agentor

Run Dirigentenstab alongside Agentor on a different local port until authentication, restricted keys, domain isolation, VM lifecycle, guest SSH and file transfer pass against real CloudStack. Existing Incus VMs and Agentor conversations are not automatically imported or deleted. Record every old VM, disk, workload, mount, network and external route, and back them up before moving a workload.

Recreate a workload as a CloudStack-managed VM, transfer application data at its own supported consistency boundary, validate the new workload, and cut over only that workload's endpoint. Maintain a tested route back to the old instance until its data has been reconciled. An image conversion/import needs CloudStack's supported import tools and an explicit administrator review of guest hardware, networking and data consistency. Group agents must never recreate legacy arbitrary host directory shares.

Retire Agentor/Incus only after all workloads are verified and backups/recovery have been exercised. The implementation preserves the existing Agentor container, its running administrative VM, Cloudflare Tunnel, Tailscale and host SSH; deployment of the new application alone is not evidence that migration has finished.

The approved workspace-and-history import follows [MIGRATION.md](MIGRATION.md) and [HISTORY_MIGRATION.md](HISTORY_MIGRATION.md). It retains legacy operating-system disks for rollback. Include the migration manifest, dedicated external CloudStack primary pool, encrypted original archives and per-file verification reports in the backup inventory. The application's SQLite database alone does not contain guest workspace disks. Restore the native CloudStack databases and every corresponding primary-storage filesystem together; never format or replace the external filesystem while recovering a management service.

### Verified legacy inventory

`sudo python3 scripts/migration_inventory.py` collects metadata only and writes a root-private inventory under native setup state. It reads container mounts, Incus device/volume metadata, disk file sizes, and SQLite schema/row counts. It does not read conversation rows, credential contents, guest files or shared-directory contents, and does not stop, snapshot, export, mount or modify a legacy VM.

The reference deployment contains **nine legacy VMs: one running and eight stopped**, with nine root disk files and **54 additional custom storage volumes**. Of those custom volumes, 23 have recorded references and 31 do not. Unattached volumes remain retained data; they are not automatically considered disposable. Root disk files account for approximately 68 GiB of allocated space, before custom-volume data and backups.

Seven legacy workers depend on host-mounted shared credential/configuration/data directories, and two also have a host shared-skills mount: **23 host-path device attachments across four distinct sources**. The legacy authentication database has four tables and one human identity; its sessions and account records are not CloudStack identities and cannot be copied into Dirigentenstab's session database. Historical agent state/workspace data are held separately from the VM root disks. Therefore, importing only root disks would omit required data, and reproducing the old credential/host mounts would violate the new guest boundary.

A safe cutover must inventory each workload's root disk **and every attached custom volume**, retain the unattached volumes and original backups, establish a workload-specific consistency boundary, and transfer the approved workspace/application datasets into guest-owned storage. Reconfigure providers and human identities through the new platform rather than copying legacy host credential directories into guests. Validate the workload and its data in CloudStack, then change only its endpoint while retaining a rollback route. The existing running administrator requires its own tested replacement before shutdown. This inventory phase is complete; legacy workload and conversation migration are explicitly **not complete** until those checks and transfers are performed.
