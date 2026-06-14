/**
 * InMemoryFallbackStore — Degraded-mode storage for when Supermemory is unavailable.
 *
 * Provides tenant-scoped in-memory storage that mimics the existing keyword-based
 * behavior. Used by the MemoryLayer when the circuit breaker is open (Fallback_Mode).
 * All operations are synchronous — no async needed here.
 */

import { ReasoningMemoryEntry } from '../types/index.js';

export class InMemoryFallbackStore {
  private entries: Map<string, ReasoningMemoryEntry[]>;

  constructor() {
    this.entries = new Map();
  }

  /**
   * Retrieve all memory entries for a given tenant, optionally limited.
   * Returns entries in insertion order (newest last).
   */
  getEntriesByTenant(tenantId: string, options?: { limit?: number }): ReasoningMemoryEntry[] {
    const tenantEntries = this.entries.get(tenantId) ?? [];
    if (options?.limit !== undefined && options.limit >= 0) {
      return tenantEntries.slice(0, options.limit);
    }
    return [...tenantEntries];
  }

  /**
   * Add a new memory entry for a tenant.
   */
  addEntry(tenantId: string, entry: ReasoningMemoryEntry): void {
    const tenantEntries = this.entries.get(tenantId);
    if (tenantEntries) {
      tenantEntries.push(entry);
    } else {
      this.entries.set(tenantId, [entry]);
    }
  }

  /**
   * Find a specific memory entry by ID within a tenant's entries.
   * Returns null if not found.
   */
  findById(tenantId: string, id: string): ReasoningMemoryEntry | null {
    const tenantEntries = this.entries.get(tenantId) ?? [];
    return tenantEntries.find((entry) => entry.id === id) ?? null;
  }

  /**
   * Update a memory entry by ID within a tenant's entries.
   * Merges the provided partial updates into the existing entry.
   * Returns true if the entry was found and updated, false otherwise.
   */
  update(tenantId: string, id: string, updates: Partial<ReasoningMemoryEntry>): boolean {
    const tenantEntries = this.entries.get(tenantId);
    if (!tenantEntries) {
      return false;
    }
    const index = tenantEntries.findIndex((entry) => entry.id === id);
    if (index === -1) {
      return false;
    }
    tenantEntries[index] = { ...tenantEntries[index], ...updates };
    return true;
  }

  /**
   * Clear all stored entries for a given tenant.
   */
  clear(tenantId: string): void {
    this.entries.delete(tenantId);
  }
}
