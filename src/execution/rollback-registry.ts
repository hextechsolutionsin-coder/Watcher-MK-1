/**
 * Rollback Registry
 *
 * Stores the rollback specification for every action the AI executes.
 * Every write action must register a rollback before being considered complete.
 *
 * Design principle: If the AI makes a mistake, any analyst can undo it
 * with one click. The registry is the source of truth for what can be undone.
 */

import { PlannedAction, RollbackSpec, BlastRadius } from '../types/index.js';

// ============================================================================
// Types
// ============================================================================

export type RollbackStatus = 'AVAILABLE' | 'EXECUTED' | 'EXPIRED' | 'UNAVAILABLE';

export interface RollbackEntry {
  id: string;
  tenant_id: string;
  execution_record_id: string;
  action_id: string;
  action_description: string;
  blast_radius: BlastRadius;
  rollback_spec: RollbackSpec;
  status: RollbackStatus;
  registered_at: string;
  expires_at: string;
  executed_at?: string;
  executed_by?: string;  // 'analyst:user-id' or 'ai:auto'
}

// ============================================================================
// Store Interface
// ============================================================================

export interface RollbackStore {
  save(entry: RollbackEntry): Promise<void>;
  getById(id: string, tenantId: string): Promise<RollbackEntry | null>;
  getByExecutionRecordId(executionRecordId: string, tenantId: string): Promise<RollbackEntry | null>;
  getAvailableByTenant(tenantId: string): Promise<RollbackEntry[]>;
  updateStatus(id: string, tenantId: string, status: RollbackStatus, executedAt?: string, executedBy?: string): Promise<void>;
}

// ============================================================================
// Rollback Registry
// ============================================================================

/** Default rollback window — 24 hours for most actions. */
const DEFAULT_ROLLBACK_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Shorter window for high-blast actions — 4 hours. */
const HIGH_BLAST_ROLLBACK_WINDOW_MS = 4 * 60 * 60 * 1000;

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

export class RollbackRegistry {
  private readonly store: RollbackStore;

  constructor(store: RollbackStore) {
    this.store = store;
  }

  /**
   * Registers a rollback for an executed action.
   * Called immediately after successful execution.
   * Returns the rollback entry ID.
   */
  async register(
    tenantId: string,
    executionRecordId: string,
    action: PlannedAction
  ): Promise<RollbackEntry> {
    if (!action.rollback_spec) {
      throw new Error(
        `Cannot register rollback for action '${action.tool_action_id}' — no rollback_spec provided`
      );
    }

    const now = new Date();
    const windowMs = action.blast_radius === BlastRadius.HIGH
      ? HIGH_BLAST_ROLLBACK_WINDOW_MS
      : DEFAULT_ROLLBACK_WINDOW_MS;

    const entry: RollbackEntry = {
      id: generateId(),
      tenant_id: tenantId,
      execution_record_id: executionRecordId,
      action_id: action.id,
      action_description: action.description,
      blast_radius: action.blast_radius,
      rollback_spec: action.rollback_spec,
      status: 'AVAILABLE',
      registered_at: now.toISOString(),
      expires_at: new Date(now.getTime() + windowMs).toISOString(),
    };

    await this.store.save(entry);
    return entry;
  }

  /**
   * Marks a rollback as executed.
   * Called after the rollback action completes successfully.
   */
  async markExecuted(
    rollbackId: string,
    tenantId: string,
    executedBy: string
  ): Promise<void> {
    const entry = await this.store.getById(rollbackId, tenantId);
    if (!entry) throw new Error(`Rollback entry '${rollbackId}' not found`);
    if (entry.status !== 'AVAILABLE') {
      throw new Error(`Rollback '${rollbackId}' is not available (status: ${entry.status})`);
    }

    await this.store.updateStatus(
      rollbackId,
      tenantId,
      'EXECUTED',
      new Date().toISOString(),
      executedBy
    );
  }

  /**
   * Expires rollback entries that are past their window.
   * Called by a scheduled job periodically.
   */
  async expireStale(tenantId: string): Promise<number> {
    const available = await this.store.getAvailableByTenant(tenantId);
    const now = new Date();
    let expired = 0;

    for (const entry of available) {
      if (new Date(entry.expires_at) < now) {
        await this.store.updateStatus(entry.id, tenantId, 'EXPIRED');
        expired++;
      }
    }

    return expired;
  }

  /**
   * Returns all available rollbacks for a tenant.
   * Used by the UI to show the "undo" buttons.
   */
  async getAvailable(tenantId: string): Promise<RollbackEntry[]> {
    const all = await this.store.getAvailableByTenant(tenantId);
    const now = new Date();
    // Filter out expired ones (in case expireStale hasn't run yet)
    return all.filter((e) => new Date(e.expires_at) >= now);
  }

  /**
   * Returns the rollback entry for a specific execution record.
   */
  async getForExecution(
    executionRecordId: string,
    tenantId: string
  ): Promise<RollbackEntry | null> {
    return this.store.getByExecutionRecordId(executionRecordId, tenantId);
  }

  /**
   * Checks if a rollback is still available (not expired, not already executed).
   */
  async isAvailable(rollbackId: string, tenantId: string): Promise<boolean> {
    const entry = await this.store.getById(rollbackId, tenantId);
    if (!entry) return false;
    if (entry.status !== 'AVAILABLE') return false;
    return new Date(entry.expires_at) >= new Date();
  }
}
