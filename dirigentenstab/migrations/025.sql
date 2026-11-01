CREATE TABLE vm_deployments_new (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), name TEXT NOT NULL,
 params BLOB NOT NULL, vm_id TEXT, phase TEXT NOT NULL, updated REAL NOT NULL
);
INSERT INTO vm_deployments_new SELECT id, agent_id, name, params, vm_id, phase, updated FROM vm_deployments;
DROP TABLE vm_deployments;
ALTER TABLE vm_deployments_new RENAME TO vm_deployments;
