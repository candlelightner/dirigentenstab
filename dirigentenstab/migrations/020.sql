CREATE TABLE IF NOT EXISTS skills (
 id TEXT PRIMARY KEY,
 creator_agent_id TEXT NOT NULL REFERENCES agents(id),
 name TEXT NOT NULL,
 description TEXT NOT NULL,
 text BLOB NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1,
 global_revision INTEGER,
 shared_agent_ids TEXT NOT NULL DEFAULT '[]',
 created REAL NOT NULL,
 updated REAL NOT NULL
);
