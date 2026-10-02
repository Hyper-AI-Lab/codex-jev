CREATE TABLE IF NOT EXISTS invocation_schema(version INTEGER PRIMARY KEY CHECK(version=1));
INSERT OR IGNORE INTO invocation_schema VALUES(1);
CREATE TABLE IF NOT EXISTS invocations(
  id TEXT PRIMARY KEY,
  workspace_hash TEXT NOT NULL,
  operation TEXT NOT NULL,
  arguments_hash TEXT NOT NULL,
  revision TEXT NOT NULL,
  origin TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  completed_at INTEGER,
  result_status TEXT NOT NULL,
  metrics TEXT NOT NULL,
  session_hash TEXT,
  turn_hash TEXT,
  call_hash TEXT
);
CREATE TABLE IF NOT EXISTS invocation_receipts(
  call_hash TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL,
  turn_hash TEXT NOT NULL,
  workspace_hash TEXT NOT NULL,
  operation TEXT NOT NULL,
  arguments_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  invocation_id TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS invocation_task ON invocations(session_hash, started_at);
