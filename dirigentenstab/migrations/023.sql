CREATE TABLE secrets (
 name TEXT PRIMARY KEY CHECK(length(name) BETWEEN 1 AND 64),
 value BLOB NOT NULL, updated REAL NOT NULL
);
ALTER TABLE agents ADD COLUMN enabled_secrets TEXT;
