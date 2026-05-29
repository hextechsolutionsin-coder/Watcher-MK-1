import { describe, it, expect, beforeEach, vi } from 'vitest';
import { RollbackRegistry, RollbackStore, RollbackEntry, RollbackStatus } from './rollback-registry.js';
import { PlannedAction, BlastRadius, ActionUrgency } from '../types/index.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeAction(overrides?: Partial<PlannedAction>): PlannedAction {
  return {
    id: 'action-001',
    sequence: 1,
    description: 'Disable IAM access key',
    reasoning: 'Key compromised',
    connector_id: 'conn-001',
    tool_action_id: 'aws:iam:disable-access-key',
    aws_service: 'iam',
    aws_api_call: 'UpdateAccessKey',
    api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Inactive' },
    blast_radius: BlastRadius.LOW,
    urgency: ActionUrgency.IMMEDIATE,
    confidence: 85,
    rollback_spec: {
      aws_service: 'iam',
      aws_api_call: 'UpdateAccessKey',
      api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Active' },
      description: 'Re-enable the access key',
    },
    ...overrides,
  };
}

function createMockStore(): RollbackStore & { entries: Map<string, RollbackEntry> } {
  const entries = new Map<string, RollbackEntry>();
  const byExecId = new Map<string, RollbackEntry>();

  return {
    entries,
    async save(entry) {
      entries.set(`${entry.tenant_id}:${entry.id}`, entry);
      byExecId.set(`${entry.tenant_id}:${entry.execution_record_id}`, entry);
    },
    async getById(id, tenantId) { return entries.get(`${tenantId}:${id}`) ?? null; },
    async getByExecutionRecordId(execId, tenantId) { return byExecId.get(`${tenantId}:${execId}`) ?? null; },
    async getAvailableByTenant(tenantId) {
      return [...entries.values()].filter(e => e.tenant_id === tenantId && e.status === 'AVAILABLE');
    },
    async updateStatus(id, tenantId, status, executedAt, executedBy) {
      const key = `${tenantId}:${id}`;
      const entry = entries.get(key);
      if (entry) {
        const updated = { ...entry, status, ...(executedAt && { executed_at: executedAt }), ...(executedBy && { executed_by: executedBy }) };
        entries.set(key, updated);
        byExecId.set(`${tenantId}:${entry.execution_record_id}`, updated);
      }
    },
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('RollbackRegistry', () => {
  let store: ReturnType<typeof createMockStore>;
  let registry: RollbackRegistry;

  beforeEach(() => {
    store = createMockStore();
    registry = new RollbackRegistry(store);
  });

  describe('register', () => {
    it('registers a rollback entry with AVAILABLE status', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);

      expect(entry.status).toBe('AVAILABLE');
      expect(entry.tenant_id).toBe('tenant-abc');
      expect(entry.execution_record_id).toBe('exec-001');
      expect(entry.action_id).toBe('action-001');
      expect(entry.rollback_spec).toEqual(action.rollback_spec);
      expect(entry.id).toBeDefined();
      expect(entry.registered_at).toBeDefined();
      expect(entry.expires_at).toBeDefined();
    });

    it('sets expiry to 24 hours for LOW blast radius', async () => {
      const action = makeAction({ blast_radius: BlastRadius.LOW });
      const before = Date.now();
      const entry = await registry.register('tenant-abc', 'exec-001', action);
      const after = Date.now();

      const expiresAt = new Date(entry.expires_at).getTime();
      const expectedMin = before + 23 * 60 * 60 * 1000;
      const expectedMax = after + 25 * 60 * 60 * 1000;

      expect(expiresAt).toBeGreaterThan(expectedMin);
      expect(expiresAt).toBeLessThan(expectedMax);
    });

    it('sets expiry to 4 hours for HIGH blast radius', async () => {
      const action = makeAction({
        blast_radius: BlastRadius.HIGH,
        rollback_spec: { aws_service: 'ec2', aws_api_call: 'StartInstances', api_params: {}, description: 'restart' },
      });
      const before = Date.now();
      const entry = await registry.register('tenant-abc', 'exec-001', action);

      const expiresAt = new Date(entry.expires_at).getTime();
      const expectedMax = before + 5 * 60 * 60 * 1000;

      expect(expiresAt).toBeLessThan(expectedMax);
    });

    it('throws when action has no rollback_spec', async () => {
      const action = makeAction({ rollback_spec: undefined });
      await expect(registry.register('tenant-abc', 'exec-001', action))
        .rejects.toThrow('no rollback_spec');
    });

    it('persists the entry to the store', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);

      const stored = await store.getById(entry.id, 'tenant-abc');
      expect(stored).not.toBeNull();
      expect(stored!.id).toBe(entry.id);
    });
  });

  describe('markExecuted', () => {
    it('marks a rollback as EXECUTED', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);

      await registry.markExecuted(entry.id, 'tenant-abc', 'analyst:alice');

      const updated = await store.getById(entry.id, 'tenant-abc');
      expect(updated!.status).toBe('EXECUTED');
      expect(updated!.executed_by).toBe('analyst:alice');
      expect(updated!.executed_at).toBeDefined();
    });

    it('throws when rollback entry not found', async () => {
      await expect(registry.markExecuted('nonexistent', 'tenant-abc', 'analyst:alice'))
        .rejects.toThrow('not found');
    });

    it('throws when rollback is already executed', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);
      await registry.markExecuted(entry.id, 'tenant-abc', 'analyst:alice');

      await expect(registry.markExecuted(entry.id, 'tenant-abc', 'analyst:bob'))
        .rejects.toThrow('not available');
    });
  });

  describe('getAvailable', () => {
    it('returns only AVAILABLE entries that have not expired', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);

      const available = await registry.getAvailable('tenant-abc');
      expect(available).toHaveLength(1);
      expect(available[0]!.id).toBe(entry.id);
    });

    it('excludes executed entries', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);
      await registry.markExecuted(entry.id, 'tenant-abc', 'analyst:alice');

      const available = await registry.getAvailable('tenant-abc');
      expect(available).toHaveLength(0);
    });

    it('excludes entries from other tenants', async () => {
      await registry.register('tenant-abc', 'exec-001', makeAction());
      await registry.register('tenant-xyz', 'exec-002', makeAction({ id: 'action-002' }));

      const available = await registry.getAvailable('tenant-abc');
      expect(available).toHaveLength(1);
    });
  });

  describe('expireStale', () => {
    it('marks expired entries as EXPIRED', async () => {
      const action = makeAction();
      const entry = await registry.register('tenant-abc', 'exec-001', action);

      // Manually set expires_at to the past
      const stored = await store.getById(entry.id, 'tenant-abc');
      store.entries.set(`tenant-abc:${entry.id}`, {
        ...stored!,
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });

      const count = await registry.expireStale('tenant-abc');
      expect(count).toBe(1);

      const updated = await store.getById(entry.id, 'tenant-abc');
      expect(updated!.status).toBe('EXPIRED');
    });

    it('does not expire entries that are still valid', async () => {
      await registry.register('tenant-abc', 'exec-001', makeAction());

      const count = await registry.expireStale('tenant-abc');
      expect(count).toBe(0);
    });
  });

  describe('isAvailable', () => {
    it('returns true for a valid available entry', async () => {
      const entry = await registry.register('tenant-abc', 'exec-001', makeAction());
      expect(await registry.isAvailable(entry.id, 'tenant-abc')).toBe(true);
    });

    it('returns false for a non-existent entry', async () => {
      expect(await registry.isAvailable('nonexistent', 'tenant-abc')).toBe(false);
    });

    it('returns false for an executed entry', async () => {
      const entry = await registry.register('tenant-abc', 'exec-001', makeAction());
      await registry.markExecuted(entry.id, 'tenant-abc', 'analyst:alice');
      expect(await registry.isAvailable(entry.id, 'tenant-abc')).toBe(false);
    });
  });
});
