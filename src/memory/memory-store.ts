import { Incident, ReasoningMemoryEntry, AnalystFeedback } from '../types/index.js';

/**
 * Abstract database interface — swap for real PG client or in-memory mock.
 */
export interface DatabaseClient {
  insert(table: string, record: Record<string, unknown>): Promise<void>;
  findById(table: string, id: string, tenantId: string): Promise<Record<string, unknown> | null>;
  findByTenantId(table: string, tenantId: string, options?: { limit?: number; offset?: number }): Promise<Record<string, unknown>[]>;
  update(table: string, id: string, tenantId: string, updates: Record<string, unknown>): Promise<void>;
  deleteByTenantId(table: string, tenantId: string): Promise<number>;
}

const TABLES = {
  INCIDENTS: 'incidents',
  REASONING_MEMORY: 'reasoning_memory',
  ANALYST_FEEDBACK: 'analyst_feedback',
} as const;

/**
 * Reasoning Memory persistence layer.
 * Stores incidents, reasoning memory entries, and analyst feedback per tenant.
 * This is what makes the AI smarter over time — it retrieves past incidents
 * and feedback when reasoning about new events.
 */
export class MemoryStore {
  private readonly db: DatabaseClient;

  constructor(db: DatabaseClient) {
    this.db = db;
  }

  // ── Incidents ──────────────────────────────────────────────────────────────

  async saveIncident(incident: Incident): Promise<void> {
    await this.db.insert(TABLES.INCIDENTS, incident as unknown as Record<string, unknown>);
  }

  async getIncident(id: string, tenantId: string): Promise<Incident | null> {
    const record = await this.db.findById(TABLES.INCIDENTS, id, tenantId);
    return record ? (record as unknown as Incident) : null;
  }

  async getIncidentsByTenant(tenantId: string, options?: { limit?: number; offset?: number }): Promise<Incident[]> {
    const records = await this.db.findByTenantId(TABLES.INCIDENTS, tenantId, options);
    return records as unknown as Incident[];
  }

  async updateIncident(id: string, tenantId: string, updates: Partial<Incident>): Promise<void> {
    await this.db.update(TABLES.INCIDENTS, id, tenantId, updates as Record<string, unknown>);
  }

  // ── Reasoning Memory ───────────────────────────────────────────────────────

  async saveMemoryEntry(entry: ReasoningMemoryEntry): Promise<void> {
    await this.db.insert(TABLES.REASONING_MEMORY, entry as unknown as Record<string, unknown>);
  }

  async getMemoryEntry(id: string, tenantId: string): Promise<ReasoningMemoryEntry | null> {
    const record = await this.db.findById(TABLES.REASONING_MEMORY, id, tenantId);
    return record ? (record as unknown as ReasoningMemoryEntry) : null;
  }

  async getMemoryEntriesByTenant(tenantId: string, options?: { limit?: number; offset?: number }): Promise<ReasoningMemoryEntry[]> {
    const records = await this.db.findByTenantId(TABLES.REASONING_MEMORY, tenantId, options);
    return records as unknown as ReasoningMemoryEntry[];
  }

  // ── Analyst Feedback ───────────────────────────────────────────────────────

  async saveAnalystFeedback(incidentId: string, tenantId: string, feedback: AnalystFeedback): Promise<void> {
    const record: Record<string, unknown> = { id: incidentId, tenant_id: tenantId, ...feedback };
    await this.db.insert(TABLES.ANALYST_FEEDBACK, record);
  }

  async getAnalystFeedback(incidentId: string, tenantId: string): Promise<AnalystFeedback | null> {
    const record = await this.db.findById(TABLES.ANALYST_FEEDBACK, incidentId, tenantId);
    if (!record) return null;
    const { id: _id, tenant_id: _tenantId, ...feedback } = record;
    return feedback as unknown as AnalystFeedback;
  }

  // ── Tenant Data Deletion ───────────────────────────────────────────────────

  async deleteAllTenantData(tenantId: string): Promise<{ deletedCounts: Record<string, number> }> {
    const deletedCounts: Record<string, number> = {};
    for (const table of Object.values(TABLES)) {
      deletedCounts[table] = await this.db.deleteByTenantId(table, tenantId);
    }
    return { deletedCounts };
  }
}
