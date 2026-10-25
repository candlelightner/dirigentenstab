CREATE TABLE providers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, protocol TEXT NOT NULL CHECK(protocol IN ('chat','responses')),
 base_url TEXT NOT NULL, api_key BLOB NOT NULL, default_model TEXT NOT NULL DEFAULT ''
);
CREATE TABLE agents (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, domain_id TEXT NOT NULL UNIQUE,
 account_id TEXT NOT NULL, user_id TEXT NOT NULL,
 runtime BLOB NOT NULL, provisioning BLOB NOT NULL,
 provider_id TEXT REFERENCES providers(id), model TEXT NOT NULL DEFAULT '',
 instructions TEXT NOT NULL DEFAULT '', can_provision INTEGER NOT NULL DEFAULT 0,
 enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, identity BLOB NOT NULL, expires REAL NOT NULL
);
CREATE TABLE login_attempts (bucket TEXT NOT NULL, created REAL NOT NULL);
CREATE INDEX login_attempts_time ON login_attempts(created);
CREATE TABLE conversations (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
 human_id TEXT NOT NULL, title TEXT NOT NULL, created REAL NOT NULL, messages BLOB NOT NULL
);
CREATE TABLE provisioning (
 id TEXT PRIMARY KEY, parent_id TEXT REFERENCES agents(id), name TEXT NOT NULL,
 model TEXT NOT NULL, instructions TEXT NOT NULL, phase TEXT NOT NULL DEFAULT 'pending',
 domain_id TEXT, account_id TEXT, user_id TEXT, credentials BLOB, error TEXT,
 updated REAL NOT NULL, UNIQUE(parent_id,name)
);
CREATE TABLE vm_access (
 vm_id TEXT PRIMARY KEY, owner_agent TEXT NOT NULL REFERENCES agents(id),
 username TEXT NOT NULL CHECK(username <> 'root'), private_key BLOB NOT NULL,
 host_key TEXT, port INTEGER NOT NULL DEFAULT 22
);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY, created REAL NOT NULL, actor TEXT NOT NULL,
 operation TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL
);
