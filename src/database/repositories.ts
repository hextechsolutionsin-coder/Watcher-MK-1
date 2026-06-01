/**
 * Database Repositories
 *
 * PostgreSQL implementations of all data access operations.
 * Each repository handles one table/domain.
 * These replace the in-memory stores when DB_ENABLED=true.
 */

import { query } from './connection.js';

// ============================================================================
// Incidents Repository
// ============================================================================

export const incidentsRepo = {
  async create(incident: Record<string, unknown>): Promise<void> {
    await query(
      `INSERT INTO incidents (id, tenant_id, account_id, severity, confidence, threat_type,
        description, explanation, mitre_techniques, affected_assets, attack_surface,
        kill_chain_stage, predictions, status, reasoning_response_id, action_plan_id,
        detection_timestamp, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
       ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status, updated_at = EXCLUDED.updated_at`,
      [
        incident['id'], incident['tenant_id'], incident['account_id'],
        incident['severity'] ?? incident['severity_level'], incident['confidence'] ?? incident['confidence_score'],
        incident['threat_type'], incident['description'], incident['explanation'],
        JSON.stringify(incident['mitre_techniques'] ?? incident['mitre_technique_ids'] ?? []),
        JSON.stringify(incident['affected_assets'] ?? []),
        incident['attack_surface'], incident['kill_chain_stage'],
        JSON.stringify(incident['predictions'] ?? null),
        incident['status'] ?? 'OPEN', incident['reasoning_response_id'],
        incident['action_plan_id'], incident['detection_timestamp'] ?? new Date().toISOString(),
        incident['created_at'] ?? new Date().toISOString(),
        incident['updated_at'] ?? new Date().toISOString(),
      ]
    );
  },

  async getByTenant(tenantId: string, filters?: { severity?: string; status?: string }): Promise<unknown[]> {
    let sql = 'SELECT * FROM incidents WHERE tenant_id = $1';
    const params: unknown[] = [tenantId];

    if (filters?.severity) {
      params.push(filters.severity);
      sql += ` AND severity = $${params.length}`;
    }
    if (filters?.status) {
      params.push(filters.status);
      sql += ` AND status = $${params.length}`;
    }

    sql += ' ORDER BY created_at DESC LIMIT 100';
    const result = await query(sql, params);
    return result.rows;
  },

  async getById(id: string): Promise<unknown | null> {
    const result = await query('SELECT * FROM incidents WHERE id = $1', [id]);
    return result.rows[0] ?? null;
  },

  async updateStatus(id: string, status: string): Promise<void> {
    await query('UPDATE incidents SET status = $1, updated_at = NOW() WHERE id = $2', [status, id]);
  },
};

// ============================================================================
// Actions Repository
// ============================================================================

export const actionsRepo = {
  async create(action: Record<string, unknown>): Promise<void> {
    await query(
      `INSERT INTO actions (id, incident_id, tenant_id, action_type, status, severity_level,
        approver_id, rejection_reason, retry_count, execution_timestamp, outcome,
        affected_asset, blast_radius, rollback_spec, ai_reasoning, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status, approver_id = EXCLUDED.approver_id,
        rejection_reason = EXCLUDED.rejection_reason, updated_at = EXCLUDED.updated_at`,
      [
        action['id'], action['incident_id'], action['tenant_id'],
        action['action_type'], action['status'] ?? 'PENDING_APPROVAL',
        action['severity_level'], action['approver_id'], action['rejection_reason'],
        action['retry_count'] ?? 0, action['execution_timestamp'],
        action['outcome'], JSON.stringify(action['affected_asset'] ?? null),
        action['blast_radius'], JSON.stringify(action['rollback_spec'] ?? null),
        action['ai_reasoning'],
        action['created_at'] ?? new Date().toISOString(),
        action['updated_at'] ?? new Date().toISOString(),
      ]
    );
  },

  async getByTenant(tenantId: string, filters?: { type?: string; outcome?: string }): Promise<unknown[]> {
    let sql = 'SELECT * FROM actions WHERE tenant_id = $1';
    const params: unknown[] = [tenantId];

    if (filters?.type) {
      params.push(filters.type);
      sql += ` AND action_type = $${params.length}`;
    }
    if (filters?.outcome) {
      params.push(filters.outcome);
      sql += ` AND outcome = $${params.length}`;
    }

    sql += ' ORDER BY created_at DESC LIMIT 100';
    const result = await query(sql, params);
    return result.rows;
  },

  async getPending(tenantId: string): Promise<unknown[]> {
    const result = await query(
      "SELECT * FROM actions WHERE tenant_id = $1 AND status = 'PENDING_APPROVAL' ORDER BY created_at ASC",
      [tenantId]
    );
    return result.rows;
  },

  async getById(id: string): Promise<unknown | null> {
    const result = await query('SELECT * FROM actions WHERE id = $1', [id]);
    return result.rows[0] ?? null;
  },

  async update(id: string, updates: Record<string, unknown>): Promise<unknown | null> {
    const fields = Object.keys(updates).filter((k) => k !== 'id');
    if (fields.length === 0) return null;

    const setClauses = fields.map((f, i) => `${f} = $${i + 2}`);
    setClauses.push(`updated_at = NOW()`);

    const result = await query(
      `UPDATE actions SET ${setClauses.join(', ')} WHERE id = $1 RETURNING *`,
      [id, ...fields.map((f) => updates[f])]
    );
    return result.rows[0] ?? null;
  },
};

// ============================================================================
// Connectors Repository
// ============================================================================

export const connectorsRepo = {
  async create(connector: Record<string, unknown>): Promise<void> {
    await query(
      `INSERT INTO connectors (id, tenant_id, account_id, role_arn, regions, data_sources, status, registered_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        connector['id'], connector['tenant_id'], connector['account_id'],
        connector['role_arn'], connector['regions'], connector['data_sources'],
        connector['status'] ?? 'ACTIVE', connector['registered_at'] ?? new Date().toISOString(),
      ]
    );
  },

  async getAll(): Promise<unknown[]> {
    const result = await query('SELECT * FROM connectors ORDER BY registered_at DESC');
    return result.rows;
  },

  async getById(id: string): Promise<unknown | null> {
    const result = await query('SELECT * FROM connectors WHERE id = $1', [id]);
    return result.rows[0] ?? null;
  },

  async updateStatus(id: string, status: string, errorMessage?: string): Promise<void> {
    await query(
      'UPDATE connectors SET status = $1, error_message = $2, last_poll_at = NOW() WHERE id = $3',
      [status, errorMessage ?? null, id]
    );
  },
};

// ============================================================================
// Trust Level Repository
// ============================================================================

export const trustRepo = {
  async get(tenantId: string): Promise<unknown | null> {
    const result = await query('SELECT * FROM trust_levels WHERE tenant_id = $1', [tenantId]);
    return result.rows[0] ?? null;
  },

  async upsert(record: Record<string, unknown>): Promise<void> {
    await query(
      `INSERT INTO trust_levels (tenant_id, trust_level, approval_rate_30d, total_actions_30d,
        approved_actions_30d, last_level_change, last_level_change_reason, manually_overridden, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
       ON CONFLICT (tenant_id) DO UPDATE SET
        trust_level = EXCLUDED.trust_level, approval_rate_30d = EXCLUDED.approval_rate_30d,
        total_actions_30d = EXCLUDED.total_actions_30d, approved_actions_30d = EXCLUDED.approved_actions_30d,
        last_level_change = EXCLUDED.last_level_change, last_level_change_reason = EXCLUDED.last_level_change_reason,
        manually_overridden = EXCLUDED.manually_overridden, updated_at = NOW()`,
      [
        record['tenant_id'], record['trust_level'] ?? 1, record['approval_rate_30d'] ?? 100,
        record['total_actions_30d'] ?? 0, record['approved_actions_30d'] ?? 0,
        record['last_level_change'] ?? new Date().toISOString(),
        record['last_level_change_reason'] ?? 'Initial', record['manually_overridden'] ?? false,
      ]
    );
  },
};

// ============================================================================
// Audit Log Repository
// ============================================================================

export const auditRepo = {
  async append(entry: Record<string, unknown>): Promise<void> {
    await query(
      `INSERT INTO audit_log (tenant_id, event_type, timestamp, actor_type, actor_id,
        affected_resource, action_taken, outcome, reasoning_trace, ai_explanation, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        entry['tenant_id'], entry['event_type'], entry['timestamp'] ?? new Date().toISOString(),
        (entry['actor'] as Record<string, unknown>)?.['type'] ?? 'SYSTEM',
        (entry['actor'] as Record<string, unknown>)?.['id'] ?? 'system',
        entry['affected_resource'], entry['action_taken'],
        entry['outcome'] ?? 'SUCCESS', entry['reasoning_trace'],
        entry['ai_explanation'], JSON.stringify(entry['metadata'] ?? {}),
      ]
    );
  },

  async getByTenant(tenantId: string, limit = 100): Promise<unknown[]> {
    const result = await query(
      'SELECT * FROM audit_log WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2',
      [tenantId, limit]
    );
    return result.rows;
  },
};

// ============================================================================
// Timeline Events Repository
// ============================================================================

export const timelineRepo = {
  async create(event: Record<string, unknown>): Promise<void> {
    await query(
      `INSERT INTO timeline_events (id, incident_id, tenant_id, timestamp, type, title, description, actor)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        event['id'], event['incident_id'], event['tenant_id'] ?? 'default',
        event['timestamp'], event['type'], event['title'],
        event['description'], event['actor'],
      ]
    );
  },

  async getByIncident(incidentId: string): Promise<unknown[]> {
    const result = await query(
      'SELECT * FROM timeline_events WHERE incident_id = $1 ORDER BY timestamp ASC',
      [incidentId]
    );
    return result.rows;
  },
};

// ============================================================================
// Users Repository (for auth)
// ============================================================================

export const usersRepo = {
  async create(user: { id: string; tenant_id: string; email: string; password_hash: string; role: string; name?: string }): Promise<void> {
    await query(
      'INSERT INTO users (id, tenant_id, email, password_hash, role, name) VALUES ($1,$2,$3,$4,$5,$6)',
      [user.id, user.tenant_id, user.email, user.password_hash, user.role, user.name ?? null]
    );
  },

  async getByEmail(email: string): Promise<{ id: string; tenant_id: string; email: string; password_hash: string; role: string; name: string | null } | null> {
    const result = await query('SELECT * FROM users WHERE email = $1', [email]);
    return (result.rows[0] as any) ?? null;
  },

  async getById(id: string): Promise<unknown | null> {
    const result = await query('SELECT id, tenant_id, email, role, name, created_at FROM users WHERE id = $1', [id]);
    return result.rows[0] ?? null;
  },

  async updateLastLogin(id: string): Promise<void> {
    await query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [id]);
  },
};

// ============================================================================
// Tenants Repository
// ============================================================================

export const tenantsRepo = {
  async create(id: string, name: string): Promise<void> {
    await query(
      'INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING',
      [id, name]
    );
  },

  async getById(id: string): Promise<unknown | null> {
    const result = await query('SELECT * FROM tenants WHERE id = $1', [id]);
    return result.rows[0] ?? null;
  },
};
