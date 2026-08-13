-- Emergency access contacts. Keep in sync with src/services/storage-schema.ts.

CREATE TABLE IF NOT EXISTS emergency_access (
  id TEXT PRIMARY KEY,
  grantor_id TEXT NOT NULL,
  grantee_id TEXT,
  email TEXT,
  key_encrypted TEXT,
  type INTEGER NOT NULL,
  status INTEGER NOT NULL,
  wait_time_days INTEGER NOT NULL,
  recovery_initiated_at TEXT,
  last_notification_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (grantor_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (grantee_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_emergency_access_grantor ON emergency_access(grantor_id, status);
CREATE INDEX IF NOT EXISTS idx_emergency_access_grantee ON emergency_access(grantee_id, status);
CREATE INDEX IF NOT EXISTS idx_emergency_access_email ON emergency_access(email);
