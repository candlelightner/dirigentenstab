# Legacy workspace migration

The migration helper imports approved agent-owned workspaces into new CloudStack-managed Linux VMs. It retains the original Incus VMs, their volumes, Agentor services and human authentication data unchanged. It does not migrate whole operating-system disks, privileged host mounts, shared credentials, GPU configuration or the old orchestration software.

This is an operator procedure, separate from agent tools. Run it on the host with the project Python environment and root access. Its private manifest is `/var/lib/dirigentenstab/setup/data-migration.json`; it contains source paths and identifiers and must not be committed or published. Conversation migration uses the same identity mapping; see [HISTORY_MIGRATION.md](HISTORY_MIGRATION.md).

## Storage and identities

Source ownership comes from the existing registry and Incus custom-volume metadata. Missing or ambiguous ownership, incomplete group relationships and hierarchy cycles fail closed. CloudStack creates a migration parent domain, the source groups and each individual agent identity through the application's durable subgroup-provisioning operation. Existing administrative personas map to the corresponding migration/group agent. Display names remain local metadata; CloudStack remains authoritative for domain relationships.

Large workspaces need a dedicated CloudStack primary pool with enough space for both the transferred archive and extracted files. The deployment uses CloudStack's supported KVM host-local `Filesystem` storage on a dedicated directory of an existing mounted filesystem. The operator creates and tags that pool and a customized local disk offering with the same tag. No disk is formatted by the host, no existing data is moved, and no host directory is mounted inside an agent VM. Store the pool identifier, offering identifier and dedicated directory as root-only `migration-storage.json` beside the manifest:

```json
{"pool_id":"CloudStack pool UUID","disk_offering_id":"CloudStack offering UUID","path":"/mounted-disk/dedicated-primary"}
```

The helper verifies through the platform administrator API that each new data disk actually uses that pool. The template and small CPU/RAM offering come from the native installer's private `zone.json`. A backend-only cloud-init profile initializes the VM's new `/dev/vdb` data disk without overwriting an existing filesystem, mounts it at `/home/dirigent/workspace`, and assigns it to the non-root guest account. Start with the small administrator workspace probe before copying bulk data.

## Capture and restore

```bash
sudo .venv/bin/python scripts/migrate_data.py discover
sudo .venv/bin/python scripts/migrate_data.py provision
sudo .venv/bin/python scripts/migrate_data.py probe
sudo .venv/bin/python scripts/migrate_data.py export
sudo .venv/bin/python scripts/migrate_data.py verify
sudo .venv/bin/python scripts/migrate_data.py restore
```

Capture reads regular files without following symlinks, verifies file and tree metadata before and after capture, and fails if the source changes. Avoid editing source workspaces during capture. Capture preserves complete original contents and metadata in root-only AES-256 GPG archives on the archive filesystem; the existing application master-key file supplies the passphrase without putting its value in arguments or environment variables. Back up this key independently. The encrypted archive retains files which are excluded from an agent's usable copy. The `verify` phase independently reads the stored ciphertext, checks its SHA-256 checksum, authenticates GPG decryption, and parses tar headers without extracting private files. Regular-file, symlink and logical-byte totals must match captured source metadata; hard links count as their original logical files. Restore requires this recoverability check to pass first.

The usable copy excludes credential/runtime directories, environment files, private-key/configuration files, Git remote configuration and files containing recognized private-key material or known credential values. Absolute, escaping and credential-targeting symlinks are quarantined. Internal relative links are retained. Quarantine reports list paths and reasons privately; they never print file contents. Original archives preserve these bytes for a human administrator's recovery review. File ownership in the guest is normalized to the unprivileged guest account, with owner read/write access and directory traversal; original ownership, modes, ACLs and extended attributes remain available in the encrypted original archive.

Python's maintained `tarfile.data_filter` remains enabled during extraction. It can normalize redundant `.` or slash components in relative symlink targets. Verification accepts these spelling changes only when no named component is cancelled by `..`; removing a trailing directory requirement additionally requires the target to be a real directory. Other target differences fail closed. The receipt counts accepted `normalized_links`, and encrypted originals retain every exact source target. A resumed verification checks the existing final directory without extracting over its contents.

Restore creates one managed VM and dedicated data disk for each source persona, transfers bounded SFTP chunks with its unique encrypted SSH identity and pinned host key, verifies the archive and every regular-file SHA-256 checksum, checks retained link targets, and records totals in the private manifest. It extracts into a dedicated staging directory and never overwrites an unrelated existing destination. Successfully verified new VMs are stopped to conserve host resources; start an individual VM through its agent when its workspace is needed. Old VMs are never stopped by this helper.

## Resume and recovery

Keep the manifest, encrypted originals, master key and application database together in the recovery inventory, but back up the master key separately. Captures and imports record source fingerprints, archive checksums, per-file hashes, target VM/disk/pool identifiers and verification totals. Rerunning a completed phase skips its completed checkpoints. A source changed after capture is an explicit conflict: preserve both versions and make a new reviewed capture rather than replacing the prior record.

CloudStack VM creation uses the application's durable deployment record. An interrupted dispatch is reconciled with CloudStack before retrying; the helper does not blindly create another VM. Investigate any unresolved deployment phase before continuing. A failed copy can upload its archive again and resume the known staging directory; the verified final directory is accepted only when its migration marker matches the expected archive checksum. Keep the legacy workloads available until the imported workspace and conversation counts have been independently reviewed. This is a point-in-time import, not ongoing synchronization.
