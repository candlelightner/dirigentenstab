ALTER TABLE managed_templates ADD COLUMN guest_admin INTEGER NOT NULL DEFAULT 0 CHECK(guest_admin IN (0,1));
CREATE TABLE platform_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE template_creations (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), volume_id TEXT NOT NULL,
 name TEXT NOT NULL UNIQUE, params BLOB NOT NULL, template_id TEXT, phase TEXT NOT NULL,
 guest_admin INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL
);
