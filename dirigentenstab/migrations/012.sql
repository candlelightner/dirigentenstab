CREATE TABLE legacy_agent_credentials (
 agent_id TEXT PRIMARY KEY REFERENCES agents(id), credentials BLOB NOT NULL
);
INSERT INTO legacy_agent_credentials(agent_id,credentials) SELECT id,provisioning FROM agents;
ALTER TABLE agents RENAME COLUMN runtime TO credentials;
ALTER TABLE agents DROP COLUMN provisioning;
