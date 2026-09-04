CREATE TABLE IF NOT EXISTS pii_vault (
  token TEXT PRIMARY KEY,
  original TEXT NOT NULL,
  type TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pii_vault_hash ON pii_vault(hash);
CREATE INDEX IF NOT EXISTS idx_pii_vault_created_at ON pii_vault(created_at);
