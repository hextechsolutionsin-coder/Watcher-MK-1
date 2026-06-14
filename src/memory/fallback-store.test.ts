import { describe, it, expect, beforeEach } from 'vitest';
import { InMemoryFallbackStore } from './fallback-store.js';
import { ReasoningMemoryEntry } from '../types/index.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

function makeEntry(overrides?: Partial<ReasoningMemoryEntry>): ReasoningMemoryEntry {
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
    embedding_text: 'Credential compromise IAM key anomalous location',
    created_at: '2024-01-15T11:00:00Z',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('InMemoryFallbackStore', () => {
  let store: InMemoryFallbackStore;

  beforeEach(() => {
    store = new InMemoryFallbackStore();
  });

  describe('addEntry / getEntriesByTenant', () => {
    it('stores and retrieves entries for a tenant', () => {
      const entry = makeEntry();
      store.addEntry('tenant-1', entry);

      const entries = store.getEntriesByTenant('tenant-1');
      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual(entry);
    });

    it('returns empty array for unknown tenant', () => {
      expect(store.getEntriesByTenant('unknown')).toEqual([]);
    });

    it('stores multiple entries for the same tenant', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      store.addEntry('tenant-1', makeEntry({ id: 'mem-002' }));
      store.addEntry('tenant-1', makeEntry({ id: 'mem-003' }));

      expect(store.getEntriesByTenant('tenant-1')).toHaveLength(3);
    });

    it('isolates entries between tenants', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001', tenant_id: 'tenant-1' }));
      store.addEntry('tenant-2', makeEntry({ id: 'mem-002', tenant_id: 'tenant-2' }));

      expect(store.getEntriesByTenant('tenant-1')).toHaveLength(1);
      expect(store.getEntriesByTenant('tenant-2')).toHaveLength(1);
      expect(store.getEntriesByTenant('tenant-1')[0].id).toBe('mem-001');
      expect(store.getEntriesByTenant('tenant-2')[0].id).toBe('mem-002');
    });

    it('respects the limit option', () => {
      for (let i = 0; i < 10; i++) {
        store.addEntry('tenant-1', makeEntry({ id: `mem-${i}` }));
      }

      const limited = store.getEntriesByTenant('tenant-1', { limit: 3 });
      expect(limited).toHaveLength(3);
    });

    it('returns all entries when limit exceeds count', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      store.addEntry('tenant-1', makeEntry({ id: 'mem-002' }));

      const entries = store.getEntriesByTenant('tenant-1', { limit: 100 });
      expect(entries).toHaveLength(2);
    });

    it('returns a copy so mutations do not affect store', () => {
      store.addEntry('tenant-1', makeEntry());
      const entries = store.getEntriesByTenant('tenant-1');
      entries.pop();

      expect(store.getEntriesByTenant('tenant-1')).toHaveLength(1);
    });
  });

  describe('findById', () => {
    it('finds an entry by id within a tenant', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      store.addEntry('tenant-1', makeEntry({ id: 'mem-002' }));

      const found = store.findById('tenant-1', 'mem-002');
      expect(found).not.toBeNull();
      expect(found!.id).toBe('mem-002');
    });

    it('returns null when id does not exist', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      expect(store.findById('tenant-1', 'nonexistent')).toBeNull();
    });

    it('returns null when tenant has no entries', () => {
      expect(store.findById('unknown-tenant', 'mem-001')).toBeNull();
    });

    it('does not find entries belonging to a different tenant', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      expect(store.findById('tenant-2', 'mem-001')).toBeNull();
    });
  });

  describe('update', () => {
    it('updates an existing entry and returns true', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001', outcome: 'ONGOING' }));

      const result = store.update('tenant-1', 'mem-001', { outcome: 'RESOLVED' });
      expect(result).toBe(true);

      const updated = store.findById('tenant-1', 'mem-001');
      expect(updated!.outcome).toBe('RESOLVED');
    });

    it('returns false when entry does not exist', () => {
      expect(store.update('tenant-1', 'nonexistent', { outcome: 'RESOLVED' })).toBe(false);
    });

    it('returns false when tenant has no entries', () => {
      expect(store.update('unknown', 'mem-001', { outcome: 'RESOLVED' })).toBe(false);
    });

    it('merges partial updates without removing existing fields', () => {
      const entry = makeEntry({ id: 'mem-001' });
      store.addEntry('tenant-1', entry);

      store.update('tenant-1', 'mem-001', { threat_type: 'Lateral Movement' });

      const updated = store.findById('tenant-1', 'mem-001');
      expect(updated!.threat_type).toBe('Lateral Movement');
      expect(updated!.threat_description).toBe(entry.threat_description);
      expect(updated!.outcome).toBe(entry.outcome);
    });
  });

  describe('clear', () => {
    it('removes all entries for a tenant', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      store.addEntry('tenant-1', makeEntry({ id: 'mem-002' }));

      store.clear('tenant-1');
      expect(store.getEntriesByTenant('tenant-1')).toEqual([]);
    });

    it('does not affect other tenants', () => {
      store.addEntry('tenant-1', makeEntry({ id: 'mem-001' }));
      store.addEntry('tenant-2', makeEntry({ id: 'mem-002' }));

      store.clear('tenant-1');

      expect(store.getEntriesByTenant('tenant-1')).toEqual([]);
      expect(store.getEntriesByTenant('tenant-2')).toHaveLength(1);
    });

    it('is safe to call on a tenant with no entries', () => {
      expect(() => store.clear('nonexistent')).not.toThrow();
    });
  });
});
