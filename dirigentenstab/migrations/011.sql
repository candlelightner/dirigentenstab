CREATE TABLE mcp_servers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL,
 token BLOB NOT NULL, enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE mcp_assignments (
 agent_id TEXT NOT NULL REFERENCES agents(id),
 server_id TEXT NOT NULL REFERENCES mcp_servers(id), tools TEXT NOT NULL,
 PRIMARY KEY(agent_id,server_id)
);
