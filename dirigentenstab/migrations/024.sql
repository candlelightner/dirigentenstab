CREATE TABLE conversation_seen (
 human_id TEXT NOT NULL, conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
 seen REAL NOT NULL, PRIMARY KEY(human_id, conversation_id)
);
INSERT INTO conversation_seen SELECT human_id, id, CAST(strftime('%s','now') AS REAL) FROM conversations;
