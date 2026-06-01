-- ============================================================================
-- Watcher MK1 — PostgreSQL Schema
-- Run this once to create all tables.
-- ============================================================================

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Connectors
CREATE TABLE IF NOT EXISTS connectors (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  account_id TEXT NOT NULL,
  role_arn TEXT NOT NULL,
  regions TEXT[] NOT NULL DEFAULT '{}',
  data_sources TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  last_poll_at TIMESTAMPTZ,
  error_message TEXT,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  account_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 50,
  threat_type TEXT,
  description TEXT,
  explanation TEXT,
  mitre_techniques JSONB DEFAULT '[]',
  affected_assets JSONB DEFAULT '[]',
  attack_surface TEXT,
  kill_chain_stage TEXT,
  predictions JSONB,
  status TEXT NOT NULL DEFAULT 'OPEN',
  reasoning_response_id TEXT,
  action_plan_id TEXT,
  detection_timestamp TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(tenant_id, severity);

-- Actions (approval queue + executed actions)
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  action_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
  severity_level TEXT,
  approver_id TEXT,
  rejection_reason TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  execution_timestamp TIMESTAMPTZ,
  outcome TEXT,
  affected_asset JSONB,
  blast_radius TEXT,
  rollback_spec JSONB,
  ai_reasoning TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_actions_tenant ON actions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON actions(incident_id);

-- Timeline events
CREATE TABLE IF NOT EXISTS timeline_events (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  tenant_id TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  actor TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_timeline_incident ON timeline_events(incident_id);

-- Trust levels
CREATE TABLE IF NOT EXISTS trust_levels (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  trust_level INTEGER NOT NULL DEFAULT 1,
  approval_rate_30d REAL NOT NULL DEFAULT 100,
  total_actions_30d INTEGER NOT NULL DEFAULT 0,
  approved_actions_30d INTEGER NOT NULL DEFAULT 0,
  last_level_change TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_level_change_reason TEXT,
  manually_overridden BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Reasoning memory
CREATE TABLE IF NOT EXISTS reasoning_memory (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  incident_id TEXT NOT NULL,
  threat_type TEXT,
  threat_description TEXT,
  affected_asset_types TEXT[] DEFAULT '{}',
  mitre_technique_ids TEXT[] DEFAULT '{}',
  actions_taken TEXT[] DEFAULT '{}',
  outcome TEXT,
  analyst_feedback JSONB,
  embedding_text TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_tenant ON reasoning_memory(tenant_id);

-- Audit log (append-only)
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  affected_resource TEXT,
  action_taken TEXT NOT NULL,
  outcome TEXT NOT NULL,
  reasoning_trace TEXT,
  ai_explanation TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type, timestamp DESC);

-- Rollback registry
CREATE TABLE IF NOT EXISTS rollbacks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  execution_record_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  action_description TEXT,
  blast_radius TEXT,
  rollback_spec JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'AVAILABLE',
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  executed_at TIMESTAMPTZ,
  executed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_rollbacks_tenant ON rollbacks(tenant_id, status);

-- Users (for authentication)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'ANALYST',
  name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
