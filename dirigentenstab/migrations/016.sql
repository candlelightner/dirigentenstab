ALTER TABLE agents ADD COLUMN owner_ssh_key_enabled INTEGER NOT NULL DEFAULT 1 CHECK(owner_ssh_key_enabled IN (0,1));
