ALTER TABLE agents ADD COLUMN thinking TEXT NOT NULL DEFAULT 'default'
 CHECK(length(thinking) BETWEEN 1 AND 32);
