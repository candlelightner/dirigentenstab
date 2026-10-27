CREATE TABLE IF NOT EXISTS user_ssh_keys (
    user_id TEXT PRIMARY KEY,
    private_key BLOB NOT NULL,
    passphrase BLOB,
    public_key TEXT NOT NULL,
    created REAL NOT NULL,
    updated REAL NOT NULL
);
