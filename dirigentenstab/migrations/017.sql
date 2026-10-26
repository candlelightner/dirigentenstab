ALTER TABLE agents ADD COLUMN compute_offering_requests_enabled INTEGER NOT NULL DEFAULT 1 CHECK(compute_offering_requests_enabled IN (0,1));
CREATE TABLE compute_offering_requests (
 id TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES agents(id),
 conversation_id TEXT NOT NULL REFERENCES conversations(id),
 run_id TEXT NOT NULL REFERENCES chat_runs(id),
 call_id TEXT NOT NULL,
 human_id TEXT NOT NULL,
 params BLOB NOT NULL,
 result BLOB,
 status TEXT NOT NULL CHECK(status IN ('pending','applying','approved','deferred','uncertain','failed')),
 created REAL NOT NULL,
 updated REAL NOT NULL,
 delivery_run_id TEXT REFERENCES chat_runs(id),
 UNIQUE(run_id,call_id)
);
