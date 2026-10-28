# Recovery and migration

Keep the SQLite database and its encryption master key in **independent backups**. Losing the key makes encrypted credentials and conversations unrecoverable. Store a protected copy of `.env`, the TLS key/certificate, and root-private native installation state separately from public source code. Use your normal encrypted backup system; never commit these files.

## Application backup and restore

For a simple consistent backup, stop only the Dirigentenstab application with `docker compose stop app`, copy the persistent Docker volume `dirigentenstab_data`, and restart it. Preserve ownership UID/GID 10001. An online SQLite backup must use SQLite's backup interface; copying an active database without its WAL is unsafe.

Restore the complete volume, restore the **matching** master-key secret, retain its restrictive permissions and UID 10001 readability, then run the selected image. The master key is never in the Docker image or database. A mismatched key must be corrected by restoring the right backup; do not generate a replacement key over an existing database. Restore the application's TLS secret pair as well. Sessions can be revoked; restore does not require recovering human passwords because CloudStack remains authoritative.

Before an application upgrade, make a consistent backup. Migrations run transactionally from numbered SQL files. When reverting an image whose schema expectations differ, restore its matching database snapshot rather than attempting an improvised reverse migration.

## Interrupted conversations

Accepted work runs independently of the browser and human session. After an application restart, the runtime resumes the latest active execution in each conversation under its agent’s own credentials. Explicit owner stops and agent pauses are preserved. Full transcripts, known tool outcomes and uncertain action details remain encrypted in SQLite.

The runtime never silently replays an interrupted tool call. It gives the agent the saved action details and an unknown-outcome result so it can inspect actual infrastructure state. The agent can use native API tools and `recover_operation` for its own saved managed VM/template operations; that recovery tool inspects and binds existing resources without creating another resource. A lost response or missing result does not prove a mutation failed. For saved GPU actions, `execution_state` reads the controller’s known outcome; `recover_operation` can explicitly resume an existing pre-dispatch preparation plan under current authority without resubmitting an uncertain VM dispatch. The agent decides whether further inspection, an explicit retry, safe remaining work or owner input is appropriate. Administrator commands below remain available for exceptional repair; routine conversation recovery does not require them.

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

### KVM host Disconnected after an agent restart

Symptom: the host stays Disconnected after `cloudstack-agent` restarts (for example from an unattended upgrade). The agent log shows "Broken pipe" and the management log shows "Certificate ownership verification failed".

Cause: the agent certificate only covers the `dscloud0` bridge address (`CLOUDSTACK_GATEWAY`, normally `10.253.80.1`), but the management server pushes the global setting `host` to agents, and CloudStack auto-detects that as the default-route NIC address. Setup now sets `host` to the bridge address and restarts `cloudstack-management` only when it differs.

Fix on an existing install: set global `host` to the bridge address (`updateConfiguration name=host value=10.253.80.1`), restart `cloudstack-management`, then confirm `/etc/cloudstack/agent/agent.properties` has `host=10.253.80.1@static` and the host returns to Up (`listHosts`). Rerunning `sudo ./setup.sh --install` does the same.

## Partial subgroup and VM provisioning

Subgroup creation has durable SQLite stages because CloudStack and SQLite cannot share a transaction. Retry the recorded operation after correcting the cause; inspect its phase and native resource IDs. Do not manually create a second account/domain with the same intended name. If an issued key could not be committed locally, reconcile it before retrying. The parent's one API key pair performs provisioning using its current CloudStack account/domain/role permissions; a denial never triggers a more privileged fallback.

Use `sudo .venv/bin/python scripts/admin.py status` to list incomplete operations. `recover-deployments` only queries CloudStack and binds a uniquely named Running or Stopped VM in the agent's exact account/domain to its prepared SSH record; it never creates another VM. Failed asynchronous jobs can leave VM records, so `failed` operations remain blocked until reconciled. Error, Destroyed, Expunging and transient VM states are never marked complete. Missing or ambiguous VMs remain unresolved for investigation; missing SSH records must be restored or governed access established. If an administrator confirms a definitive server rejection in private logs, verifies no VM/job exists, and needs to clear that attempt, use `resolve-rejection OP_ID --confirmed-rejection`. This explicit recovery action marks the operation `rejected`; it never automatically retries a deployment. Newly captured definitive API validation rejections also use the `rejected` terminal phase. The agent can also close an unresolved managed deployment itself with `recover_operation(..., abandon=true)`: after the normal recovery check it re-lists the exact-name VMs in its own account, refuses while any match is not Destroyed, Expunging, Expunged or Error, and otherwise marks the operation `rejected` and drops the unused prepared SSH identity. It only reads CloudStack; nothing is deleted or redeployed.

`repair-provisioning OP_ID` retries a subordinate operation with credential reconciliation. `rotate AGENT_ID` and `revoke AGENT_ID` authenticate a human administrator and check domain access. Rotation replaces the single pair only after exact native ownership and access validation; revocation disables execution first and includes keys from interrupted rotations. Rerun recovery if remote revocation was interrupted. Schema migration preserves the active credential and archives the retired provisioning pair encrypted; inspect and clean up legacy remote pairs explicitly after a backup. A human platform administrator can explicitly adopt an exact replacement key for the same native owner; no newest-key selection or root fallback is used.

Guest SSH keys are unique per VM and encrypted in the application database. Restore that database and key together. Existing VMs without a stored managed SSH identity remain inaccessible through the SSH tools until an administrator establishes governed access. Host-key changes require administrator investigation and re-enrollment; never disable SSH host-key checking to recover access.

A failed asynchronous deployment can still leave a real Stopped VM. Reconcile its exact UUID, operation name, account and domain through `recover-deployments`; bind only the original pending encrypted SSH record. Do not create another VM or generate replacement keys merely because a job reported failure. For `No destination found`, inspect stopped-VM reservations as described in [INSTALLATION.md](INSTALLATION.md#stopped-vm-capacity-reservations). If an authorized administrator shortened the reservation policy, restore the recorded prior value through the supported configuration API and restart only the management server to roll it back. Existing native guests and host administrative services do not need to stop.

Failed creation can instead leave an `Error` VM, which CloudStack cannot start. A platform administrator must verify its exact operation/account/domain/UUID, terminal failed job, never-booted state, absent workspace copy and absent usable disks before expunging that empty placeholder through CloudStack's supported API. Preserve a private recovery receipt and the original encrypted SSH record. After confirming VM/volume absence and no pending job, use `resolve-rejection` to close that failed attempt; an explicit new attempt creates a new VM with its own SSH keypair. Existing workload VMs require their own data recovery procedure.

## Native rollback

Do not run a blanket uninstall on a host with guests. Stop new deployments, take CloudStack database and guest-disk backups, and export the current CloudStack configuration before maintenance. Original configuration copies and the changed-files ledger identify the limited native files introduced by Dirigentenstab. Review and restore individual files only after confirming which running VMs depend on them. Restart only the affected native service. Keep the host uplink, SSH and existing tunnel/Serve routes unchanged.

The installer deliberately provides no automatic destructive rollback: removing storage, MySQL, bridges or firewall rules while guests run can lose data or expose management endpoints. CloudStack management/database upgrades must follow the upstream supported sequence and include the relevant System VM template upgrade. A VM disk snapshot alone is not a backup of the management database or the application's encryption master key.

## Moving existing agents to one native account key

Back up the database and master key before changing remote credentials. The schema upgrade keeps the old active pair and archives the retired provisioning pair encrypted; it does not issue, widen or revoke CloudStack keys. After reviewing the managed account's current native role, a human administrator can explicitly migrate all agents in their visible scope:

```sh
sudo .venv/bin/python scripts/admin.py migrate-keys
```

Use `migrate-key AGENT_ID` for one account, or `adopt-key AGENT_ID --key-id CLOUDSTACK_KEY_PAIR_UUID` to select an existing replacement. Adoption preserves that key's native CloudStack permissions. To replace legacy per-key restrictions with account-role authentication, use `rotate` or `migrate-key`, which issues a fresh pair through the human session. `listUserKeyRules` returns effective permissions, including inherited role rules, so its rule count cannot identify explicit key restrictions. Migration validates a single-user managed account and replacement access, commits the one active pair, then cleans up the superseded keys owned by that account. Ambiguous ownership or failure stops with recovery state; no privileged key is substituted. Native role/domain changes thereafter take effect without editing application policy.

## Migrating from Agentor

Run Dirigentenstab alongside Agentor on a different local port until authentication, native account permissions, domain isolation, VM lifecycle, guest SSH and file transfer pass against real CloudStack. Existing Incus VMs and Agentor conversations are not automatically imported or deleted. Record every old VM, disk, workload, mount, network and external route, and back them up before moving a workload.

Recreate a workload as a CloudStack-managed VM, transfer application data at its own supported consistency boundary, validate the new workload, and cut over only that workload's endpoint. Maintain a tested route back to the old instance until its data has been reconciled. An image conversion/import needs CloudStack's supported import tools and an explicit administrator review of guest hardware, networking and data consistency. Group agents must never recreate legacy arbitrary host directory shares.

Retire Agentor/Incus only after all workloads are verified and backups/recovery have been exercised. The implementation preserves the existing Agentor container, its running administrative VM, Cloudflare Tunnel, Tailscale and host SSH; deployment of the new application alone is not evidence that migration has finished.

The approved workspace-and-history import follows [MIGRATION.md](MIGRATION.md) and [HISTORY_MIGRATION.md](HISTORY_MIGRATION.md). It retains legacy operating-system disks for rollback. Include the migration manifest, dedicated external CloudStack primary pool, encrypted original archives and per-file verification reports in the backup inventory. The application's SQLite database alone does not contain guest workspace disks. Restore the native CloudStack databases and every corresponding primary-storage filesystem together; never format or replace the external filesystem while recovering a management service.

### Verified legacy inventory

`sudo python3 scripts/migration_inventory.py` collects metadata only and writes a root-private inventory under native setup state. It reads container mounts, Incus device/volume metadata, disk file sizes, and SQLite schema/row counts. It does not read conversation rows, credential contents, guest files or shared-directory contents, and does not stop, snapshot, export, mount or modify a legacy VM.

The reference deployment contains **nine legacy VMs: one running and eight stopped**, with nine root disk files and **54 additional custom storage volumes**. Of those custom volumes, 23 have recorded references and 31 do not. Unattached volumes remain retained data; they are not automatically considered disposable. Root disk files account for approximately 68 GiB of allocated space, before custom-volume data and backups.

Seven legacy workers depend on host-mounted shared credential/configuration/data directories, and two also have a host shared-skills mount: **23 host-path device attachments across four distinct sources**. The legacy authentication database has four tables and one human identity; its sessions and account records are not CloudStack identities and cannot be copied into Dirigentenstab's session database. Historical agent state/workspace data are held separately from the VM root disks. Therefore, importing only root disks would omit required data, and reproducing the old credential/host mounts would violate the new guest boundary.

A safe cutover must inventory each workload's root disk **and every attached custom volume**, retain the unattached volumes and original backups, establish a workload-specific consistency boundary, and transfer the approved workspace/application datasets into guest-owned storage. Reconfigure providers and human identities through the new platform rather than copying legacy host credential directories into guests. Validate the workload and its data in CloudStack, then change only its endpoint while retaining a rollback route. The existing running administrator requires its own tested replacement before shutdown. This inventory phase is complete; legacy workload and conversation migration are explicitly **not complete** until those checks and transfers are performed.

## Private templates and optional GPU preparation

Managed deployment and private-image recovery apply to operations explicitly requested with `managed=true`. Ordinary native API calls preserve supplied parameters and do not enroll managed SSH or approve derived images automatically. Never repeat a failed managed operation through the native path to bypass reconciliation.

`admin.py status` includes template creation IDs. Use `recover-templates` to bind a uniquely named, ready private template in the saved agent's exact native account/domain. It never creates or deletes an image. The agent can request the same read-only inspection/binding through `recover_operation` and continue from its saved conversation. The legacy `repair-execution RUN_ID --deployment-id TEMPLATE_OPERATION_ID` command remains available for explicit administrator repair. Missing/ambiguous images or failed jobs remain unresolved; absence alone does not justify repeating creation.

Compatible new managed VMs receive guest-admin access by default. The centrally configured owner SSH public key is added alongside agent access. Existing VMs are not modified; changing an existing guest requires its own authorized guest operation. Remove an approved asset's manifest entry as platform administrator to prevent future transfers; already delivered guest files require their own cleanup.

For GPU control, also use SQLite's backup interface on root-owned `/var/lib/dirigentenstab/gpu-control.db` and preserve `/var/lib/dirigentenstab/setup/gpu-controller.json`, `/etc/mdevctl.d`, the GPU systemd units and `.env` Compose/opt-in settings. Do not restore only the controller journal while native VM/device allocations continue changing. Reconcile native CloudStack inventory and actual libvirt attachments before resuming operation. Existing persistent mdev definitions restore through `mdevctl`; never stop/undefine an allocated or reserved device.

The platform-administrator **GPU policies** dialog lists durable operations. Reconcile performs read-only proof of the original VM dispatch/result; Resume is limited to a saved pre-dispatch plan. Saved conversations retain the corresponding action details for investigation; legacy execution repair commands remain available to administrators. Definitive native rejection is closed only after the existing `resolve-rejection` checks prove absence of its exact VM and pending jobs. No recovery path creates a replacement for an uncertain dispatch. A missing/foreign pool owner or disagreement between native Free state and libvirt attachments must be corrected by an administrator, never by bypassing policy.

The private dashboard route can be removed independently with `tailscale serve --https=3002 off`; retain the other Serve routes. See [GPU_PREPARATION.md](GPU_PREPARATION.md) for scope and identifiers.

When CloudStack returns a vague error for a well-known case (for example 533 insufficient capacity, resource limits, invalid parameters, unavailable APIs, VM state), the agent sees the native error text first, followed by a labelled hint (`ERROR_HINTS` in `dirigentenstab/diagnostics.py`). A hint lists likely causes to check; it is never a verified cause, since the precise reason often appears only in the CloudStack management log. Every error shown to a user or agent carries its category, a `Reference` ID and the real message, redacted of credentials, keys, tokens and user-data and capped at 1,000 characters; tracebacks in the admin log stay payload-free.
