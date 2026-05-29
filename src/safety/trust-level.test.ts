import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  TrustLevelService,
  TrustLevelStore,
  canActAutonomously,
  maxAutonomousBlastRadius,
  evaluateTrustPromotion,
  evaluateTrustDemotion,
} from './trust-level.js';
import { TrustLevel, BlastRadius, TenantTrustRecord } from '../types/index.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeRecord(overrides?: Partial<TenantTrustRecord>): TenantTrustRecord {
  return {
    tenant_id: 'tenant-abc',
    trust_level: TrustLevel.ONE,
    approval_rate_30d: 100,
    total_actions_30d: 0,
    approved_actions_30d: 0,
    last_level_change: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString(), // 35 days ago
    last_level_change_reason: 'Initial',
    manually_overridden: false,
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

function createMockStore(initial?: TenantTrustRecord): TrustLevelStore & { stored: TenantTrustRecord | null } {
  let stored: TenantTrustRecord | null = initial ?? null;
  return {
    get stored() { return stored; },
    getRecord: vi.fn(async () => stored),
    upsertRecord: vi.fn(async (r) => { stored = r; }),
  };
}

// ── canActAutonomously ────────────────────────────────────────────────────────

describe('canActAutonomously', () => {
  it('Level 1: only NONE blast radius is autonomous', () => {
    expect(canActAutonomously(TrustLevel.ONE, BlastRadius.NONE)).toBe(true);
    expect(canActAutonomously(TrustLevel.ONE, BlastRadius.LOW)).toBe(false);
    expect(canActAutonomously(TrustLevel.ONE, BlastRadius.MEDIUM)).toBe(false);
    expect(canActAutonomously(TrustLevel.ONE, BlastRadius.HIGH)).toBe(false);
  });

  it('Level 2: NONE and LOW are autonomous', () => {
    expect(canActAutonomously(TrustLevel.TWO, BlastRadius.NONE)).toBe(true);
    expect(canActAutonomously(TrustLevel.TWO, BlastRadius.LOW)).toBe(true);
    expect(canActAutonomously(TrustLevel.TWO, BlastRadius.MEDIUM)).toBe(false);
    expect(canActAutonomously(TrustLevel.TWO, BlastRadius.HIGH)).toBe(false);
  });

  it('Level 3: NONE, LOW, and MEDIUM are autonomous', () => {
    expect(canActAutonomously(TrustLevel.THREE, BlastRadius.NONE)).toBe(true);
    expect(canActAutonomously(TrustLevel.THREE, BlastRadius.LOW)).toBe(true);
    expect(canActAutonomously(TrustLevel.THREE, BlastRadius.MEDIUM)).toBe(true);
    expect(canActAutonomously(TrustLevel.THREE, BlastRadius.HIGH)).toBe(false);
  });

  it('HIGH blast radius is NEVER autonomous regardless of trust level', () => {
    expect(canActAutonomously(TrustLevel.ONE, BlastRadius.HIGH)).toBe(false);
    expect(canActAutonomously(TrustLevel.TWO, BlastRadius.HIGH)).toBe(false);
    expect(canActAutonomously(TrustLevel.THREE, BlastRadius.HIGH)).toBe(false);
  });
});

// ── maxAutonomousBlastRadius ──────────────────────────────────────────────────

describe('maxAutonomousBlastRadius', () => {
  it('returns correct max blast radius per trust level', () => {
    expect(maxAutonomousBlastRadius(TrustLevel.ONE)).toBe(BlastRadius.NONE);
    expect(maxAutonomousBlastRadius(TrustLevel.TWO)).toBe(BlastRadius.LOW);
    expect(maxAutonomousBlastRadius(TrustLevel.THREE)).toBe(BlastRadius.MEDIUM);
  });
});

// ── evaluateTrustPromotion ────────────────────────────────────────────────────

describe('evaluateTrustPromotion', () => {
  it('promotes Level 1 → 2 after 30 days with >90% approval rate', () => {
    const record = makeRecord({
      trust_level: TrustLevel.ONE,
      approval_rate_30d: 95,
      total_actions_30d: 20,
      last_level_change: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.TWO);
    expect(result.reason).toContain('Promoted');
  });

  it('does NOT promote Level 1 → 2 if fewer than 30 days elapsed', () => {
    const record = makeRecord({
      trust_level: TrustLevel.ONE,
      approval_rate_30d: 95,
      total_actions_30d: 20,
      last_level_change: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(), // only 10 days
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.ONE);
    expect(result.reason).toContain('10/30 days');
  });

  it('does NOT promote Level 1 → 2 if approval rate < 90%', () => {
    const record = makeRecord({
      trust_level: TrustLevel.ONE,
      approval_rate_30d: 85,
      total_actions_30d: 20,
      last_level_change: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.ONE);
  });

  it('promotes Level 2 → 3 after 90 days with >95% approval rate', () => {
    const record = makeRecord({
      trust_level: TrustLevel.TWO,
      approval_rate_30d: 97,
      total_actions_30d: 50,
      last_level_change: new Date(Date.now() - 95 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.THREE);
    expect(result.reason).toContain('Promoted');
  });

  it('does NOT promote Level 2 → 3 if fewer than 90 days elapsed', () => {
    const record = makeRecord({
      trust_level: TrustLevel.TWO,
      approval_rate_30d: 97,
      total_actions_30d: 50,
      last_level_change: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.TWO);
  });

  it('does NOT promote Level 3 (already max)', () => {
    const record = makeRecord({
      trust_level: TrustLevel.THREE,
      approval_rate_30d: 100,
      total_actions_30d: 100,
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.THREE);
  });

  it('does NOT promote with fewer than 5 actions', () => {
    const record = makeRecord({
      trust_level: TrustLevel.ONE,
      approval_rate_30d: 100,
      total_actions_30d: 3,
      last_level_change: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString(),
    });

    const result = evaluateTrustPromotion(record);
    expect(result.newLevel).toBe(TrustLevel.ONE);
    expect(result.reason).toContain('Insufficient');
  });
});

// ── evaluateTrustDemotion ─────────────────────────────────────────────────────

describe('evaluateTrustDemotion', () => {
  it('demotes Level 2 → 1 when approval rate drops below 80%', () => {
    const record = makeRecord({
      trust_level: TrustLevel.TWO,
      approval_rate_30d: 75,
      total_actions_30d: 20,
    });

    const result = evaluateTrustDemotion(record);
    expect(result.newLevel).toBe(TrustLevel.ONE);
    expect(result.reason).toContain('Demoted');
    expect(result.reason).toContain('75.0%');
  });

  it('demotes Level 3 → 2 when approval rate drops below 80%', () => {
    const record = makeRecord({
      trust_level: TrustLevel.THREE,
      approval_rate_30d: 70,
      total_actions_30d: 20,
    });

    const result = evaluateTrustDemotion(record);
    expect(result.newLevel).toBe(TrustLevel.TWO);
  });

  it('does NOT demote Level 1 (already minimum)', () => {
    const record = makeRecord({
      trust_level: TrustLevel.ONE,
      approval_rate_30d: 50,
      total_actions_30d: 20,
    });

    const result = evaluateTrustDemotion(record);
    expect(result.newLevel).toBe(TrustLevel.ONE);
  });

  it('does NOT demote when approval rate is >= 80%', () => {
    const record = makeRecord({
      trust_level: TrustLevel.TWO,
      approval_rate_30d: 82,
      total_actions_30d: 20,
    });

    const result = evaluateTrustDemotion(record);
    expect(result.newLevel).toBe(TrustLevel.TWO);
  });
});

// ── TrustLevelService ─────────────────────────────────────────────────────────

describe('TrustLevelService', () => {
  let store: ReturnType<typeof createMockStore>;
  let service: TrustLevelService;

  beforeEach(() => {
    store = createMockStore();
    service = new TrustLevelService(store);
  });

  describe('getOrCreate', () => {
    it('creates a new Level 1 record for a new tenant', async () => {
      const record = await service.getOrCreate('new-tenant');

      expect(record.tenant_id).toBe('new-tenant');
      expect(record.trust_level).toBe(TrustLevel.ONE);
      expect(record.total_actions_30d).toBe(0);
      expect(record.manually_overridden).toBe(false);
      expect(store.upsertRecord).toHaveBeenCalledOnce();
    });

    it('returns existing record without creating a new one', async () => {
      const existing = makeRecord({ tenant_id: 'existing-tenant', trust_level: TrustLevel.TWO });
      store = createMockStore(existing);
      service = new TrustLevelService(store);

      const record = await service.getOrCreate('existing-tenant');

      expect(record.trust_level).toBe(TrustLevel.TWO);
      expect(store.upsertRecord).not.toHaveBeenCalled();
    });
  });

  describe('recordDecision', () => {
    it('increments total_actions_30d on each decision', async () => {
      store = createMockStore(makeRecord());
      service = new TrustLevelService(store);

      await service.recordDecision('tenant-abc', true);
      await service.recordDecision('tenant-abc', true);

      expect(store.stored!.total_actions_30d).toBe(2);
    });

    it('increments approved_actions_30d only on approval', async () => {
      store = createMockStore(makeRecord());
      service = new TrustLevelService(store);

      await service.recordDecision('tenant-abc', true);
      await service.recordDecision('tenant-abc', false);
      await service.recordDecision('tenant-abc', true);

      expect(store.stored!.approved_actions_30d).toBe(2);
      expect(store.stored!.total_actions_30d).toBe(3);
    });

    it('calculates approval_rate_30d correctly', async () => {
      store = createMockStore(makeRecord());
      service = new TrustLevelService(store);

      // 3 approvals, 1 rejection = 75%
      await service.recordDecision('tenant-abc', true);
      await service.recordDecision('tenant-abc', true);
      await service.recordDecision('tenant-abc', true);
      await service.recordDecision('tenant-abc', false);

      expect(store.stored!.approval_rate_30d).toBeCloseTo(75, 1);
    });

    it('promotes trust level when criteria are met', async () => {
      const record = makeRecord({
        trust_level: TrustLevel.ONE,
        approval_rate_30d: 94,
        total_actions_30d: 19,
        approved_actions_30d: 18,
        last_level_change: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString(),
      });
      store = createMockStore(record);
      service = new TrustLevelService(store);

      // One more approval pushes rate to 95% (19/20)
      const result = await service.recordDecision('tenant-abc', true);

      expect(result.changed).toBe(true);
      expect(result.newLevel).toBe(TrustLevel.TWO);
      expect(store.stored!.trust_level).toBe(TrustLevel.TWO);
    });

    it('demotes trust level when approval rate drops below 80%', async () => {
      const record = makeRecord({
        trust_level: TrustLevel.TWO,
        approval_rate_30d: 80,
        total_actions_30d: 20,
        approved_actions_30d: 16, // 16/20 = 80%
      });
      store = createMockStore(record);
      service = new TrustLevelService(store);

      // Rejection drops rate to 16/21 = 76.2% → below 80%
      const result = await service.recordDecision('tenant-abc', false);

      expect(result.changed).toBe(true);
      expect(result.newLevel).toBe(TrustLevel.ONE);
    });

    it('skips auto-evaluation when manually overridden', async () => {
      const record = makeRecord({
        trust_level: TrustLevel.ONE,
        approval_rate_30d: 99,
        total_actions_30d: 19,
        approved_actions_30d: 19,
        manually_overridden: true,
        last_level_change: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString(),
      });
      store = createMockStore(record);
      service = new TrustLevelService(store);

      const result = await service.recordDecision('tenant-abc', true);

      expect(result.changed).toBe(false);
      expect(result.reason).toContain('Manual override');
      expect(store.stored!.trust_level).toBe(TrustLevel.ONE);
    });
  });

  describe('setTrustLevel', () => {
    it('sets trust level and marks as manually overridden', async () => {
      store = createMockStore(makeRecord());
      service = new TrustLevelService(store);

      await service.setTrustLevel('tenant-abc', TrustLevel.THREE, 'Admin escalation for incident response');

      expect(store.stored!.trust_level).toBe(TrustLevel.THREE);
      expect(store.stored!.manually_overridden).toBe(true);
      expect(store.stored!.last_level_change_reason).toContain('Admin escalation');
    });
  });

  describe('clearManualOverride', () => {
    it('clears the manual override flag', async () => {
      store = createMockStore(makeRecord({ manually_overridden: true, trust_level: TrustLevel.THREE }));
      service = new TrustLevelService(store);

      await service.clearManualOverride('tenant-abc');

      expect(store.stored!.manually_overridden).toBe(false);
      expect(store.stored!.trust_level).toBe(TrustLevel.THREE); // level unchanged
    });
  });

  describe('resetRollingWindow', () => {
    it('resets counters to zero', async () => {
      store = createMockStore(makeRecord({
        total_actions_30d: 50,
        approved_actions_30d: 45,
        approval_rate_30d: 90,
      }));
      service = new TrustLevelService(store);

      await service.resetRollingWindow('tenant-abc');

      expect(store.stored!.total_actions_30d).toBe(0);
      expect(store.stored!.approved_actions_30d).toBe(0);
      expect(store.stored!.approval_rate_30d).toBe(100);
    });
  });
});
