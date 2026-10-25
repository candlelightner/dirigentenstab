ALTER TABLE agents ADD COLUMN compaction_provider_id TEXT REFERENCES providers(id);
ALTER TABLE agents ADD COLUMN compaction_model TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN auto_compact_percent INTEGER
 CHECK(auto_compact_percent BETWEEN 1 AND 99);
ALTER TABLE agents ADD COLUMN context_window INTEGER CHECK(context_window BETWEEN 2 AND 2147483647);
CREATE TABLE conversation_compactions (
 conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
 covered_messages INTEGER NOT NULL CHECK(covered_messages > 0),
 prefix_hash TEXT NOT NULL,
 summary BLOB NOT NULL,
 updated REAL NOT NULL
);
