CREATE TABLE credential_rotations (
 agent_id TEXT PRIMARY KEY REFERENCES agents(id), operation_id TEXT NOT NULL,
 previous BLOB NOT NULL, replacement BLOB, phase TEXT NOT NULL, updated REAL NOT NULL
);
CREATE TABLE vm_deployments (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), name TEXT NOT NULL UNIQUE,
 params BLOB NOT NULL, vm_id TEXT, phase TEXT NOT NULL, updated REAL NOT NULL
);
CREATE TABLE managed_templates (id TEXT PRIMARY KEY, name TEXT NOT NULL);
