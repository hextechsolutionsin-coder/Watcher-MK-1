import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryStore, DatabaseClient } from './memory-store.js';
import {
  Incident,
  ReasoningMemoryEntry,
  AnalystFeedback,
  IncidentSeverity,
  IncidentStatus,
  AttackSurface,
  MitreTechnique,
  ThreatPrediction,
} from '../types/index.js';

// ── Mock DB ──────────────────────────────────────────────────────────────────

function createMockDb(): DatabaseClient & { tables: Map<string, Map<string, Record<string, unknown>>> } {
  const tables = new Map<string, Map<string, Record<string, unknown>>>();

  const getTable = (t: string) => {
    if (!tables.has(t)) tables.set(t, new Map());
    return tables.get(t)!;
  };
  const key = (id: string, tid: string) => `${tid}:${id}`;

  return {
    tables,
    async insert(table, record) { getTable(table).set(key(record.id as string, record.tenant_id as string), { ...record }); },
    async findById(table, id, tenantId) { return getTable(table).get(key(id, tenantId)) ?? null; },
    async findByTenantId(table, tenantId, opts) {
      let results = [...getTable(table).values()].filter(r => r.tenant_id === tenantId);
      const offset = opts?.offset ?? 0;
      const limit = opts?.limit ?? results.length;
      return results.slice(offset, offset + limit);
    },
    async update(table, id, tenantId, updates) {
      const k = key(id, tenantId);
      const existing = getTable(table).get(k);
      if (existing) getTable(table).set(k, { ...existing, ...updates });
    },
    async deleteByTenantId(table, tenantId) {
      const t = getTable(table);
      let count = 0;
      for (const [k, r] of t.entries()) {
        if (r.tenant_id === tenantId) { t.delete(k); count++; }
      }
      return count;
    },
  };
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

function makeIncident(overrides?: Partial<Incident>): Incident {
  return {
    id: 'inc-001',
    tenant_id: 'tenant-1',
    account_id: '123456789',
    severity: IncidentSeverity.HIGH,
    confidence: 85,
    threat_type: 'Credential Compromise',
    description: 'IAM key used from anomalous location',
    explanation: 'A compromised IAM key was used from Russia.',
    mitre_techniques: [{ technique_id: 'T1078.004', technique_name: 'Valid Accounts: Cloud Accounts', tactic: 'Initial Access' }],
    affected_assets: ['arn:aws:iam::123456789:user/svc-account'],
    attack_surface: AttackSurface.CLOUD_IAM,
    kill_chain_stage: 'Initial Access',
    predictions: { next_likely_action: 'Data exfiltration', probability: 72, recommended_preemption: 'Audit S3 access' },
    status: IncidentStatus.OPEN,
    reasoning_response_id: 'rr-001',
    detection_timestamp: '2024-01-15T10:30:00Z',
    created_at: '2024-01-15T10:30:00Z',
    updated_at: '2024-01-15T10:30:00Z',
    ...overrides,
  };
}

function makeMemoryEntry(overrides?: Partial<ReasoningMemoryEntry>): ReasoningMemoryEntry {
  return {
    id: 'mem-001',
    tenant_id: 'tenant-1',
    incident_id: 'inc-001',
    threat_type: 'Credential Compromise',
    threat_description: 'IAM key used from anomalous location',
    affected_asset_types: ['AWS::IAM::AccessKey'],
    mitre_technique_ids: ['T1078.004'],
    actions_taken: ['Revoke IAM access key'],
    outcome: 'RESOLVED',
    embedding_text: 'Credential compromise IAM key anomalous location T1078.004',
    created_at: '2024-01-15T11:00:00Z',
    ...overrides,
  };
}

function makeFeedback(overrides?: Partial<AnalystFeedback>): AnalystFeedback {
  return {
    verdict: 'CORRECT',
    notes: 'Confirmed malicious activity',
    submitted_by: 'analyst-jane',
    submitted_at: '2024-01-15T11:00:00Z',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('MemoryStore', () => {
  let db: ReturnType<typeof createMockDb>;
  let store: MemoryStore;

  beforeEach(() => {
    db = createMockDb();
    store = new MemoryStore(db);
  });

  describe('saveIncident / getIncident', () => {
    it('persists and retrieves an incident with all fields intact', async () => {
      const incident = makeIncident();
      await store.saveIncident(incident);
      const retrieved = await store.getIncident('inc-001', 'tenant-1');
      expect(retrieved).toEqual(incident);
    });

    it('returns null for non-existent incident', async () => {
      expect(await store.getIncident('nope', 'tenant-1')).toBeNull();
    });

    it('enforces tenant isolation', async () => {
      await store.saveIncident(makeIncident());
      expect(await store.getIncident('inc-001', 'other-tenant')).toBeNull();
    });
  });

  describe('getIncidentsByTenant', () => {
    it('returns all incidents for a tenant', async () => {
      await store.saveIncident(makeIncident({ id: 'inc-1' }));
      await store.saveIncident(makeIncident({ id: 'inc-2' }));
      await store.saveIncident(makeIncident({ id: 'inc-3', tenant_id: 'tenant-2' }));

      const results = await store.getIncidentsByTenant('tenant-1');
      expect(results).toHaveLength(2);
    });

    it('supports pagination', async () => {
      for (let i = 0; i < 5; i++) await store.saveIncident(makeIncident({ id: `inc-${i}` }));
      const page1 = await store.getIncidentsByTenant('tenant-1', { limit: 2, offset: 0 });
      const page2 = await store.getIncidentsByTenant('tenant-1', { limit: 2, offset: 2 });
      expect(page1).toHaveLength(2);
      expect(page2).toHaveLength(2);
    });
  });

  describe('saveMemoryEntry / getMemoryEntry', () => {
    it('persists and retrieves a reasoning memory entry', async () => {
      const entry = makeMemoryEntry();
      await store.saveMemoryEntry(entry);
      const retrieved = await store.getMemoryEntry('mem-001', 'tenant-1');
      expect(retrieved).toEqual(entry);
    });

    it('returns null for non-existent entry', async () => {
      expect(await store.getMemoryEntry('nope', 'tenant-1')).toBeNull();
    });
  });

  describe('saveAnalystFeedback / getAnalystFeedback', () => {
    it('persists and retrieves analyst feedback', async () => {
      const feedback = makeFeedback();
      await store.saveAnalystFeedback('inc-001', 'tenant-1', feedback);
      const retrieved = await store.getAnalystFeedback('inc-001', 'tenant-1');
      expect(retrieved).toEqual(feedback);
    });

    it('returns null for non-existent feedback', async () => {
      expect(await store.getAnalystFeedback('nope', 'tenant-1')).toBeNull();
    });

    it('handles all verdict types', async () => {
      const verdicts: AnalystFeedback['verdict'][] = ['CORRECT', 'INCORRECT', 'FALSE_POSITIVE', 'SEVERITY_WRONG', 'ACTION_WRONG'];
      for (const verdict of verdicts) {
        await store.saveAnalystFeedback(`inc-${verdict}`, 'tenant-1', makeFeedback({ verdict }));
        const r = await store.getAnalystFeedback(`inc-${verdict}`, 'tenant-1');
        expect(r!.verdict).toBe(verdict);
      }
    });
  });

  describe('deleteAllTenantData', () => {
    it('deletes all data for a tenant across all tables', async () => {
      await store.saveIncident(makeIncident());
      await store.saveMemoryEntry(makeMemoryEntry());
      await store.saveAnalystFeedback('inc-001', 'tenant-1', makeFeedback());

      const result = await store.deleteAllTenantData('tenant-1');

      expect(result.deletedCounts['incidents']).toBe(1);
      expect(result.deletedCounts['reasoning_memory']).toBe(1);
      expect(result.deletedCounts['analyst_feedback']).toBe(1);
    });

    it('does not affect other tenants', async () => {
      await store.saveIncident(makeIncident({ id: 'inc-t1', tenant_id: 'tenant-1' }));
      await store.saveIncident(makeIncident({ id: 'inc-t2', tenant_id: 'tenant-2' }));

      await store.deleteAllTenantData('tenant-1');

      expect(await store.getIncidentsByTenant('tenant-1')).toHaveLength(0);
      expect(await store.getIncidentsByTenant('tenant-2')).toHaveLength(1);
    });
  });
});
