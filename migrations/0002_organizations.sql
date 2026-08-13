-- Organizations, collections, roles, SSO, SCIM, Secrets Manager.
-- Keep in sync with src/services/storage-schema.ts.

CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  billing_email TEXT NOT NULL,
  identifier TEXT,
  private_key TEXT,
  public_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_identifier
  ON organizations(identifier) WHERE identifier IS NOT NULL;

CREATE TABLE IF NOT EXISTS organization_memberships (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  org_id TEXT NOT NULL,
  email TEXT,
  invited_by_email TEXT,
  access_all INTEGER NOT NULL DEFAULT 0,
  key TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL,
  type INTEGER NOT NULL,
  permissions TEXT,
  reset_password_key TEXT,
  external_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_memberships_user_org
  ON organization_memberships(user_id, org_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_org_memberships_org_status
  ON organization_memberships(org_id, status);
CREATE INDEX IF NOT EXISTS idx_org_memberships_external
  ON organization_memberships(org_id, external_id);

CREATE TABLE IF NOT EXISTS collections (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  external_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(org_id);

CREATE TABLE IF NOT EXISTS collection_users (
  user_id TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  read_only INTEGER NOT NULL DEFAULT 0,
  hide_passwords INTEGER NOT NULL DEFAULT 0,
  manage INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, collection_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cipher_collections (
  cipher_id TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  PRIMARY KEY (cipher_id, collection_id),
  FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cipher_collections_collection
  ON cipher_collections(collection_id);

CREATE TABLE IF NOT EXISTS org_groups (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  access_all INTEGER NOT NULL DEFAULT 0,
  external_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_org_groups_org ON org_groups(org_id);

CREATE TABLE IF NOT EXISTS org_group_members (
  group_id TEXT NOT NULL,
  membership_id TEXT NOT NULL,
  PRIMARY KEY (group_id, membership_id),
  FOREIGN KEY (group_id) REFERENCES org_groups(id) ON DELETE CASCADE,
  FOREIGN KEY (membership_id) REFERENCES organization_memberships(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collection_groups (
  collection_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  read_only INTEGER NOT NULL DEFAULT 0,
  hide_passwords INTEGER NOT NULL DEFAULT 0,
  manage INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (collection_id, group_id),
  FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
  FOREIGN KEY (group_id) REFERENCES org_groups(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS org_policies (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  type INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  UNIQUE (org_id, type),
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS organization_api_keys (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  type INTEGER NOT NULL DEFAULT 0,
  api_key TEXT NOT NULL,
  revision_date TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS organization_scim_tokens (
  org_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sso_auth (
  state TEXT PRIMARY KEY,
  code_challenge TEXT,
  redirect_uri TEXT NOT NULL,
  client_id TEXT NOT NULL,
  binding_hash TEXT,
  identifier TEXT,
  code_response TEXT,
  code_response_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sso_users (
  user_id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sm_projects (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sm_projects_org ON sm_projects(org_id);

CREATE TABLE IF NOT EXISTS sm_secrets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sm_secrets_org_updated ON sm_secrets(org_id, updated_at);

CREATE TABLE IF NOT EXISTS sm_secret_projects (
  secret_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  PRIMARY KEY (secret_id, project_id),
  FOREIGN KEY (secret_id) REFERENCES sm_secrets(id) ON DELETE CASCADE,
  FOREIGN KEY (project_id) REFERENCES sm_projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sm_service_accounts (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sm_service_account_projects (
  service_account_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  read_access INTEGER NOT NULL DEFAULT 1,
  write_access INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (service_account_id, project_id),
  FOREIGN KEY (service_account_id) REFERENCES sm_service_accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (project_id) REFERENCES sm_projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sm_access_tokens (
  id TEXT PRIMARY KEY,
  service_account_id TEXT NOT NULL,
  name TEXT NOT NULL,
  client_secret_hash TEXT NOT NULL,
  wrapped_org_key TEXT,
  expire_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (service_account_id) REFERENCES sm_service_accounts(id) ON DELETE CASCADE
);

ALTER TABLE ciphers ADD COLUMN organization_id TEXT;
CREATE INDEX IF NOT EXISTS idx_ciphers_organization ON ciphers(organization_id);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_personal
  ON ciphers(user_id, organization_id, updated_at);
