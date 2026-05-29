/**
 * Trust Level Management
 *
 * Tracks how much autonomy the AI has earned with each tenant.
 * New tenants start at level 1 (human approves everything).
 * Trust increases as the AI demonstrates correct decisions.
 * Trust decreases if the approval rate drops.
 *
 * Trust Level → Max autonomous blast radius:
 *   Level 1: NONE only (read-only queries auto-approved, everything else → human)
 *   Level 2: NONE + LOW (single-resource writes auto-approved after 30 days >90%)
 *   Level 3: NONE + LOW + MEDIUM (multi-resource writes auto-approved after 90 days >95%)
 *   HIGH blast radius: ALWAYS requires human approval regardless of trust level
 */

import { TrustLevel, TenantTrustRecord, BlastRadius } from '../types/index.js';

// ============================================================================
// Trust Level Store Interface
// ============================================================================

export interface TrustLevelStore {
  getRecord(tenantId: string): Promise<TenantTrustRecord | null>;
  upsertRecord(record: TenantTrustRecord): Promise<void>;
}

// ============================================================================
// Trust Level Rules
// ============================================================================

/**
 * Returns the maximum blast radius the AI can execute autonomously
 * at a given trust level.
 */
export function maxAutonomousBlastRadius(trustLevel: TrustLevel): BlastRadius {
  switch (trustLevel) {
    case TrustLevel.ONE:   return BlastRadius.NONE;
    case TrustLevel.TWO:   return BlastRadius.LOW;
    case TrustLevel.THREE: return BlastRadius.MEDIUM;
    default:               return BlastRadius.NONE;
  }
}

/**
 * Returns true if the AI can execute an action autonomously
 * at the given trust level and blast radius.
 *
 * HIGH blast radius is NEVER autonomous regardless of trust level.
 */
export function canActAutonomously(
  trustLevel: TrustLevel,
  blastRadius: BlastRadius
): boolean {
  if (blastRadius === BlastRadius.HIGH) return false;

  const maxRadius = maxAutonomousBlastRadius(trustLevel);

  const order: BlastRadius[] = [
    BlastRadius.NONE,
    BlastRadius.LOW,
    BlastRadius.MEDIUM,
    BlastRadius.HIGH,
  ];

  return order.indexOf(blastRadius) <= order.indexOf(maxRadius);
}

/**
 * Determines if a trust level promotion is warranted.
 * Returns the new trust level (may be unchanged).
 */
export function evaluateTrustPromotion(
  current: TenantTrustRecord,
  now: Date = new Date()
): { newLevel: TrustLevel; reason: string } {
  const { trust_level, approval_rate_30d, total_actions_30d } = current;

  // Need minimum actions before evaluating
  if (total_actions_30d < 5) {
    return { newLevel: trust_level, reason: 'Insufficient action history (< 5 actions)' };
  }

  // Level 1 → 2: 30+ days, >90% approval rate
  if (trust_level === TrustLevel.ONE && approval_rate_30d >= 90) {
    const daysSinceCreation = Math.floor(
      (now.getTime() - new Date(current.last_level_change).getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSinceCreation >= 30) {
      return {
        newLevel: TrustLevel.TWO,
        reason: `Promoted: ${approval_rate_30d.toFixed(1)}% approval rate over ${daysSinceCreation} days`,
      };
    }
    return {
      newLevel: trust_level,
      reason: `Good approval rate (${approval_rate_30d.toFixed(1)}%) but only ${daysSinceCreation}/30 days elapsed`,
    };
  }

  // Level 2 → 3: 90+ days at level 2, >95% approval rate
  if (trust_level === TrustLevel.TWO && approval_rate_30d >= 95) {
    const daysSincePromotion = Math.floor(
      (now.getTime() - new Date(current.last_level_change).getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSincePromotion >= 90) {
      return {
        newLevel: TrustLevel.THREE,
        reason: `Promoted: ${approval_rate_30d.toFixed(1)}% approval rate over ${daysSincePromotion} days`,
      };
    }
    return {
      newLevel: trust_level,
      reason: `Excellent approval rate (${approval_rate_30d.toFixed(1)}%) but only ${daysSincePromotion}/90 days elapsed`,
    };
  }

  return { newLevel: trust_level, reason: 'No promotion criteria met' };
}

/**
 * Determines if a trust level demotion is warranted.
 * Returns the new trust level (may be unchanged).
 */
export function evaluateTrustDemotion(
  current: TenantTrustRecord
): { newLevel: TrustLevel; reason: string } {
  const { trust_level, approval_rate_30d, total_actions_30d } = current;

  // Need minimum actions before evaluating demotion
  if (total_actions_30d < 5) {
    return { newLevel: trust_level, reason: 'Insufficient action history' };
  }

  // Demote if approval rate drops below 80%
  if (approval_rate_30d < 80 && trust_level > TrustLevel.ONE) {
    const newLevel = (trust_level - 1) as TrustLevel;
    return {
      newLevel,
      reason: `Demoted: approval rate dropped to ${approval_rate_30d.toFixed(1)}% (threshold: 80%)`,
    };
  }

  return { newLevel: trust_level, reason: 'No demotion criteria met' };
}

// ============================================================================
// Trust Level Service
// ============================================================================

/**
 * Manages trust level records for all tenants.
 * Called after every approval/rejection decision to update the rolling metrics.
 */
export class TrustLevelService {
  private readonly store: TrustLevelStore;

  constructor(store: TrustLevelStore) {
    this.store = store;
  }

  /**
   * Gets or creates a trust record for a tenant.
   * New tenants start at level 1.
   */
  async getOrCreate(tenantId: string): Promise<TenantTrustRecord> {
    const existing = await this.store.getRecord(tenantId);
    if (existing) return existing;

    const now = new Date().toISOString();
    const record: TenantTrustRecord = {
      tenant_id: tenantId,
      trust_level: TrustLevel.ONE,
      approval_rate_30d: 100, // start optimistic
      total_actions_30d: 0,
      approved_actions_30d: 0,
      last_level_change: now,
      last_level_change_reason: 'Initial trust level for new tenant',
      manually_overridden: false,
      updated_at: now,
    };
    await this.store.upsertRecord(record);
    return record;
  }

  /**
   * Records an approval decision and updates the rolling 30-day metrics.
   * Then evaluates whether the trust level should change.
   */
  async recordDecision(
    tenantId: string,
    approved: boolean
  ): Promise<TrustLevelChangeResult> {
    const record = await this.getOrCreate(tenantId);
    const now = new Date();

    const newTotal = record.total_actions_30d + 1;
    const newApproved = record.approved_actions_30d + (approved ? 1 : 0);
    const newRate = (newApproved / newTotal) * 100;

    const updated: TenantTrustRecord = {
      ...record,
      total_actions_30d: newTotal,
      approved_actions_30d: newApproved,
      approval_rate_30d: newRate,
      updated_at: now.toISOString(),
    };

    // Skip auto-evaluation if manually overridden
    if (record.manually_overridden) {
      await this.store.upsertRecord(updated);
      return { previousLevel: record.trust_level, newLevel: record.trust_level, changed: false, reason: 'Manual override active' };
    }

    // Check for promotion first, then demotion
    const promotion = evaluateTrustPromotion(updated, now);
    const demotion = evaluateTrustDemotion(updated);

    let finalLevel = record.trust_level;
    let changeReason = 'No change';

    if (promotion.newLevel !== record.trust_level) {
      finalLevel = promotion.newLevel;
      changeReason = promotion.reason;
    } else if (demotion.newLevel !== record.trust_level) {
      finalLevel = demotion.newLevel;
      changeReason = demotion.reason;
    }

    const final: TenantTrustRecord = {
      ...updated,
      trust_level: finalLevel,
      last_level_change: finalLevel !== record.trust_level ? now.toISOString() : record.last_level_change,
      last_level_change_reason: finalLevel !== record.trust_level ? changeReason : record.last_level_change_reason,
    };

    await this.store.upsertRecord(final);

    return {
      previousLevel: record.trust_level,
      newLevel: finalLevel,
      changed: finalLevel !== record.trust_level,
      reason: changeReason,
    };
  }

  /**
   * Manually sets the trust level for a tenant (admin override).
   */
  async setTrustLevel(
    tenantId: string,
    level: TrustLevel,
    reason: string
  ): Promise<void> {
    const record = await this.getOrCreate(tenantId);
    const now = new Date().toISOString();

    await this.store.upsertRecord({
      ...record,
      trust_level: level,
      manually_overridden: true,
      last_level_change: now,
      last_level_change_reason: `Manual override: ${reason}`,
      updated_at: now,
    });
  }

  /**
   * Removes the manual override, allowing automatic trust evaluation to resume.
   */
  async clearManualOverride(tenantId: string): Promise<void> {
    const record = await this.getOrCreate(tenantId);
    await this.store.upsertRecord({
      ...record,
      manually_overridden: false,
      updated_at: new Date().toISOString(),
    });
  }

  /**
   * Resets the 30-day rolling window counters.
   * Called by a scheduled job at the start of each new 30-day window.
   */
  async resetRollingWindow(tenantId: string): Promise<void> {
    const record = await this.getOrCreate(tenantId);
    await this.store.upsertRecord({
      ...record,
      total_actions_30d: 0,
      approved_actions_30d: 0,
      approval_rate_30d: 100,
      updated_at: new Date().toISOString(),
    });
  }
}

export interface TrustLevelChangeResult {
  previousLevel: TrustLevel;
  newLevel: TrustLevel;
  changed: boolean;
  reason: string;
}
