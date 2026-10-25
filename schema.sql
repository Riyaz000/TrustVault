-- TrustVault logical schema reference. The running application creates tables via SQLAlchemy.
-- Adapt types/identity syntax to your database before using this as a migration.
CREATE TABLE user (
  id INTEGER PRIMARY KEY,
  full_name VARCHAR(120) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'viewer',
  is_active_account BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE document (
  id INTEGER PRIMARY KEY,
  owner_id INTEGER NOT NULL REFERENCES user(id),
  title VARCHAR(255) NOT NULL,
  category VARCHAR(80) NOT NULL DEFAULT 'General',
  original_filename VARCHAR(255) NOT NULL,
  storage_key VARCHAR(80) NOT NULL UNIQUE,
  mime_type VARCHAR(120) NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256_hash VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP NULL
);
CREATE INDEX ix_document_owner_id ON document(owner_id);

CREATE TABLE permission (
  id INTEGER PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES document(id),
  user_id INTEGER NOT NULL REFERENCES user(id),
  level VARCHAR(10) NOT NULL CHECK (level IN ('read','edit')),
  granted_by INTEGER NOT NULL REFERENCES user(id),
  created_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL
);
CREATE INDEX ix_permission_document_id ON permission(document_id);
CREATE INDEX ix_permission_user_id ON permission(user_id);
-- Partial unique index: only one active grant for each user/document pair.
CREATE UNIQUE INDEX uq_active_permission_document_user
  ON permission(document_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  actor_id INTEGER NULL REFERENCES user(id),
  document_id INTEGER NULL,
  action VARCHAR(40) NOT NULL,
  outcome VARCHAR(20) NOT NULL,
  details VARCHAR(500) NOT NULL DEFAULT '',
  request_id VARCHAR(64) NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  previous_hash VARCHAR(64) NOT NULL,
  event_hash VARCHAR(64) NOT NULL
);
CREATE INDEX ix_audit_log_document_id ON audit_log(document_id);
CREATE INDEX ix_audit_log_action ON audit_log(action);
CREATE INDEX ix_audit_log_timestamp ON audit_log(timestamp);
