ALTER TABLE provisioning ADD COLUMN provider_id TEXT REFERENCES providers(id);
UPDATE provisioning SET provider_id=(SELECT provider_id FROM agents WHERE agents.id=provisioning.id);
