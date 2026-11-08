CREATE TABLE mcp_export_keys (
 id TEXT PRIMARY KEY, agent_id TEXT REFERENCES agents(id), label TEXT NOT NULL, hash TEXT NOT NULL,
 sealed BLOB, created_by TEXT NOT NULL, created REAL NOT NULL, last_used REAL, revoked REAL);
ALTER TABLE conversations ADD COLUMN mcp_key_id TEXT REFERENCES mcp_export_keys(id);
CREATE UNIQUE INDEX conversations_mcp_key_agent ON conversations(mcp_key_id, agent_id) WHERE mcp_key_id IS NOT NULL;
