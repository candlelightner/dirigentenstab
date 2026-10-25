CREATE TABLE chat_runs (
 id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id),
 status TEXT NOT NULL CHECK(status IN ('running','completed','failed','interrupted','reconciliation')),
 agent_id TEXT NOT NULL REFERENCES agents(id), tool TEXT, category TEXT,
 created REAL NOT NULL, updated REAL NOT NULL, events BLOB NOT NULL
);
CREATE INDEX chat_runs_conversation ON chat_runs(conversation_id,created);
