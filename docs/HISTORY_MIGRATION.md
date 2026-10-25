# Importing legacy conversation history

`scripts/migrate_history.py` imports approved Codex rollout JSONL and Claude project JSONL histories into existing Dirigentenstab agents. Codex prompt-history and session-index JSONL sidecars are retained as separately labeled private reference transcripts, including orphaned prompts and original titles. It preserves human/assistant turns, quoted historical instructions, tool calls, tool results and other historical events as inert text. It never executes old tools, restores old system instructions, migrates passwords or configures provider credentials.

The destination agents must already exist through normal CloudStack-backed provisioning. The administrator supplies a private mapping from each old persona's agent-data directory to its new local agent ID and the authoritative CloudStack human user ID. Workspace migration uses the same mapping; this history tool does not copy workspaces, host mounts, VM disks or credential directories.

Example private mapping (synthetic identifiers):

```json
{
  "version": 1,
  "human_id": "cloudstack-human-uuid",
  "secret_references": ["/private/legacy/credentials/codex.json"],
  "agents": [{
    "source_id": "legacy-persona-id",
    "target_agent_id": "existing-dirigentenstab-agent-id",
    "agents_path": "/private/approved-agent-volume"
  }]
}
```

Secret reference files are read by trusted Python code into memory only, to redact known values. They are never copied, logged or imported as credentials. JSON tool arguments are also redacted structurally; private-key blocks and common token/assignment patterns are masked. Unknown historical secrets cannot be recognized with certainty, so imported transcripts remain private and are never automatically sent to a model.

Run with the project's Python environment on the host:

```sh
sudo .venv/bin/python scripts/migrate_history.py --dry-run \
  --mapping /private/history-map.json \
  --database /private/application/dirigentenstab.db \
  --key-file /private/master_key \
  --archive-dir /private/encrypted-history

sudo .venv/bin/python scripts/migrate_history.py --run --progress \
  --mapping /private/history-map.json \
  --database /private/application/dirigentenstab.db \
  --key-file /private/master_key \
  --archive-dir /private/encrypted-history
```

Mapping/key files must be mode 0600 or 0400; the archive directory must be mode 0700. The tool prints only counts, hashes and bounded operational errors. Do not commit the mapping, archives, receipts, source histories or imported databases. Run application migrations first so the `conversations.imported` column exists.

After completion, repeat the command with `--verify` instead of `--run`. Verification stream-decrypts every GnuPG archive, authenticates it, compares its exact original-byte SHA-256 and byte count, and checks every encrypted transcript chunk. It also verifies the encrypted pre-import SQLite backup. No original text is printed or sent to a model.

Before import, SQLite's online backup API captures the destination database consistently; GnuPG immediately encrypts that backup. Source JSONL files are streamed to AES-256 GnuPG archives while readable transcripts are converted into encrypted chunks of at most 1 MiB. Only the master-key file path is passed to GnuPG; its value never appears in arguments or environment variables. Snapshotting does not stop or modify old VMs/services. Changing source files are checked against the captured prefix before their data is admitted.

Every original JSONL byte, including a malformed or oversized historical record, is retained in the encrypted source archive. An unreadable record gets an explicit marker in the UI and increments the migration report's `malformed_records` count. Internal runtime bookkeeping stays in the exact archive rather than being promoted into chat messages. Some CLI releases emit both canonical turns and UI events; their provenance labels distinguish them in the imported transcript.

Imported transcript titles contain generated references and chronological part numbers. Their bodies are encrypted in SQLite and marked read-only. Selecting an imported conversation restores its transcript; sending a new message starts a new conversation with empty model history and leaves the imported record unchanged.

The private manifest and deterministic conversation IDs make reruns resume safely. Captured sources are immutable point-in-time snapshots: later appends to an old CLI file are not silently merged into an earlier import. A changed mapping, corrupt archive or conflicting destination record stops the tool without overwriting data. Capturing a later cutover point requires a separately reviewed migration generation; this command never appends over an earlier import.

Keep the encryption master backed up independently. To recover an exact original into another private file:

```sh
umask 077
gpg --batch --pinentry-mode loopback --passphrase-file /private/master_key \
  --output /private/recovered-original.jsonl \
  --decrypt /private/encrypted-history/SOURCE_HASH/original.jsonl.gpg
```

The encrypted pre-import database is `destination-before.sqlite.gpg`. Restore it only while the application is stopped, after preserving a copy of the current database. Old VMs and source volumes remain the rollback authority until an administrator approves retirement separately.
