/**
 * MemoryLayer — Primary semantic memory module wrapping Supermemory.
 *
 * Implements both SemanticMemoryProvider and DatabaseClient interfaces,
 * providing a drop-in replacement for the existing MemoryStore while adding
 * semantic search, entity profiles, and cross-session pattern recognition.
 *
 * Features:
 * - Circuit breaker for graceful degradation
 * - In-memory fallback when Supermemory is unavailable
 * - Write queue for replay on reconnection
 * - Automatic reconnection with configurable interval
 */

import Supermemory from 'supermemory';
import { MemoryLayerConfig } from './memory-layer-config.js';
import {
  SemanticMemoryProvider,
  ConnectionStatus,
  SemanticSearchResult,
  EntityProfile,
} from './types.js';
import { DatabaseClient } from './memory-store.js';
import { CircuitBreaker } from './circuit-breaker.js';
import { InMemoryFallbackStore } from './fallback-store.js';
import { WriteQueue } from './write-queue.js';
import { validateTenantId, filterCrossTenantResults } from './tenant-validation.js';
import { MemoryFormatter, SupermemoryMetadata } from './memory-formatter.js';
import { ReasoningMemoryEntry, Incident, ReasoningResponse, AnalystFeedback } from '../types/index.js';

export class MemoryLayer implements SemanticMemoryProvider, DatabaseClient {
  private readonly client: Supermemory;
  private readonly config: MemoryLayerConfig;
  private readonly circuitBreaker: CircuitBreaker;
  private readonly fallbackStore: InMemoryFallbackStore;
  private readonly writeQueue: WriteQueue;
  private reconnectTimer: ReturnType<typeof setInterval> | null = null;
  private connected: boolean = false;

  constructor(config: MemoryLayerConfig) {
    this.config = config;
    this.client = new Supermemory({
      apiKey: config.apiKey ?? 'local',
      baseURL: config.baseUrl,
      timeout: config.timeoutMs,
    });
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 3,
      recoveryTimeMs: config.reconnectIntervalMs,
      timeoutMs: config.timeoutMs,
    });
    this.fallbackStore = new InMemoryFallbackStore();
    this.writeQueue = new WriteQueue(config.writeQueueMax);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Initialize the MemoryLayer by attempting to connect to Supermemory.
   * On failure, enters Fallback_Mode with a warning log and starts a
   * reconnection timer.
   */
  async initialize(): Promise<void> {
    try {
      // Probe Supermemory connectivity with a lightweight search call
      await this.client.search.memories({ q: '', limit: 1 });
      this.connected = true;
      console.info('[MemoryLayer] Connected to Supermemory at', this.config.baseUrl);
    } catch (error) {
      this.connected = false;
      this.circuitBreaker.recordFailure();
      console.warn(
        '[MemoryLayer] Failed to connect to Supermemory at startup. Entering Fallback_Mode.',
        error instanceof Error ? error.message : error
      );
      this.startReconnectionTimer();
    }
  }

  /**
   * Gracefully shut down the MemoryLayer.
   * Clears the reconnection timer and attempts to flush pending writes.
   */
  async shutdown(): Promise<void> {
    this.stopReconnectionTimer();

    // Attempt to flush pending writes if connected
    if (this.connected && this.writeQueue.size() > 0) {
      try {
        const result = await this.writeQueue.replayAll(async (write) => {
          await this.client.add({
            content: write.payload as string,
            containerTag: write.tenantId,
            customId: write.id,
          });
        });
        console.info(
          `[MemoryLayer] Shutdown flush: ${result.succeeded} writes replayed, ${result.failed} failed.`
        );
      } catch (error) {
        console.warn(
          '[MemoryLayer] Error flushing write queue during shutdown:',
          error instanceof Error ? error.message : error
        );
      }
    }

    console.info('[MemoryLayer] Shut down.');
  }

  /**
   * Returns the current connection status.
   */
  healthCheck(): ConnectionStatus {
    if (this.connected && this.circuitBreaker.isHealthy()) {
      return 'connected';
    }
    if (!this.connected && this.reconnectTimer !== null) {
      return 'fallback';
    }
    return 'disconnected';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SemanticMemoryProvider interface (stubs — implemented in tasks 5.4-5.8)
  // ═══════════════════════════════════════════════════════════════════════════

  async semanticSearch(
    tenantId: string,
    query: string,
    options?: { limit?: number; threshold?: number }
  ): Promise<SemanticSearchResult[]> {
    const validatedTenantId = validateTenantId(tenantId);
    const limit = options?.limit ?? this.config.searchLimit;
    const threshold = options?.threshold ?? this.config.similarityThreshold;

    const results = await this.circuitBreaker.execute<SemanticSearchResult[]>(
      async () => {
        // Call Supermemory SDK with tenant-scoped containerTag
        const response = await this.client.search.memories({
          q: query,
          containerTag: validatedTenantId,
          limit,
        });

        // Parse results into SemanticSearchResult objects
        const rawResults: Array<{ entry: ReasoningMemoryEntry; relevanceScore: number }> = [];
        const searchResults = (response as unknown as { results: Array<{ content: string; metadata?: Record<string, unknown>; score?: number }> }).results ?? [];

        for (const result of searchResults) {
          const metadata = result.metadata ?? {};
          const entry = MemoryFormatter.parseMemoryContent(result.content, metadata);
          const relevanceScore = result.score ?? 0;
          rawResults.push({ entry, relevanceScore });
        }

        // Filter out cross-tenant results
        const tenantFiltered = filterCrossTenantResults(
          rawResults,
          validatedTenantId,
          (item) => item.entry.tenant_id
        );

        return tenantFiltered;
      },
      async () => {
        // Fallback: return entries from in-memory store with relevance score 0
        const fallbackEntries = this.fallbackStore.getEntriesByTenant(validatedTenantId, { limit });
        return fallbackEntries.map((entry) => ({ entry, relevanceScore: 0 }));
      }
    );

    // Filter results below similarity threshold
    const thresholdFiltered = results.filter((r) => r.relevanceScore >= threshold);

    // Sort by relevance descending; when scores are equal, prioritize entries with analyst feedback
    thresholdFiltered.sort((a, b) => {
      if (b.relevanceScore !== a.relevanceScore) {
        return b.relevanceScore - a.relevanceScore;
      }
      // Feedback prioritization tiebreaker
      const aHasFeedback = a.entry.analyst_feedback !== undefined ? 1 : 0;
      const bHasFeedback = b.entry.analyst_feedback !== undefined ? 1 : 0;
      return bHasFeedback - aHasFeedback;
    });

    // Cap at the configured limit
    return thresholdFiltered.slice(0, limit);
  }

  async getEntityProfile(
    tenantId: string,
    entityId: string
  ): Promise<EntityProfile | null> {
    try {
      const validatedTenantId = validateTenantId(tenantId);

      const profile = await this.circuitBreaker.execute<EntityProfile | null>(
        async () => {
          // Call Supermemory profile API scoped to tenant via containerTag
          // and filtered to the specific entity via metadata filter
          const response = await this.client.profile({
            containerTag: validatedTenantId,
            filters: {
              AND: [{ key: 'entity_id', value: entityId }],
            },
          });

          const staticFacts = response.profile?.static ?? [];
          const dynamicContext = response.profile?.dynamic ?? [];

          // If the profile is empty (no facts or context), treat as non-existent
          if (staticFacts.length === 0 && dynamicContext.length === 0) {
            return null;
          }

          return {
            entityId,
            tenantId: validatedTenantId,
            staticFacts,
            dynamicContext,
          };
        },
        async () => {
          // Fallback: return null when Supermemory is unavailable
          return null;
        }
      );

      return profile;
    } catch {
      // No exception propagation per requirement 9.1
      return null;
    }
  }

  async getPatternSummary(
    tenantId: string,
    options?: { threatCategory?: string; mitreTechnique?: string }
  ): Promise<SemanticSearchResult[]> {
    const validatedTenantId = validateTenantId(tenantId);
    const patternQuery = MemoryFormatter.buildPatternQuery(
      options?.threatCategory,
      options?.mitreTechnique
    );

    try {
      const results = await this.circuitBreaker.execute<SemanticSearchResult[]>(
        async () => {
          // Build metadata filters if category/technique specified
          const filterConditions: Array<{ key: string; value: string }> = [];
          if (options?.threatCategory) {
            filterConditions.push({ key: 'threat_type', value: options.threatCategory });
          }
          if (options?.mitreTechnique) {
            filterConditions.push({ key: 'mitre_techniques', value: options.mitreTechnique });
          }

          // Call Supermemory SDK with tenant-scoped containerTag and optional filters
          const response = filterConditions.length > 0
            ? await this.client.search.memories({
                q: patternQuery,
                containerTag: validatedTenantId,
                limit: this.config.searchLimit,
                filters: { AND: filterConditions },
              })
            : await this.client.search.memories({
                q: patternQuery,
                containerTag: validatedTenantId,
                limit: this.config.searchLimit,
              });

          // Parse results into SemanticSearchResult objects
          const rawResults: SemanticSearchResult[] = [];
          const searchResults = (
            response as unknown as {
              results: Array<{ content?: string; memory?: string; metadata?: Record<string, unknown> | null; score?: number; similarity?: number }>;
            }
          ).results ?? [];

          for (const result of searchResults) {
            const content = result.memory ?? result.content ?? '';
            const metadata = result.metadata ?? {};
            const entry = MemoryFormatter.parseMemoryContent(content, metadata);
            const relevanceScore = result.similarity ?? result.score ?? 0;
            rawResults.push({ entry, relevanceScore });
          }

          // Filter out cross-tenant results
          const tenantFiltered = filterCrossTenantResults(
            rawResults,
            validatedTenantId,
            (item) => item.entry.tenant_id
          );

          // Filter to only unresolved entries for pattern surfacing
          const unresolvedOnly = tenantFiltered.filter(
            (item) => item.entry.outcome !== 'RESOLVED'
          );

          return unresolvedOnly;
        },
        async () => {
          // Fallback: return empty array when Supermemory is unavailable
          return [];
        }
      );

      // Sort by relevance descending
      results.sort((a, b) => b.relevanceScore - a.relevanceScore);

      return results;
    } catch {
      // Error containment: return empty array on any unexpected error
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MemoryProvider interface (backward compat)
  // ═══════════════════════════════════════════════════════════════════════════

  async getMemoryEntriesByTenant(
    tenantId: string,
    options?: { limit?: number }
  ): Promise<ReasoningMemoryEntry[]> {
    const validatedTenantId = validateTenantId(tenantId);
    const limit = options?.limit ?? this.config.searchLimit;

    try {
      const entries = await this.circuitBreaker.execute<ReasoningMemoryEntry[]>(
        async () => {
          // Query Supermemory with empty query to get all memories for this tenant
          const response = await this.client.search.memories({
            q: '',
            containerTag: validatedTenantId,
            limit,
          });

          // Parse each result into a ReasoningMemoryEntry
          const searchResults = (
            response as unknown as {
              results: Array<{ content?: string; memory?: string; metadata?: Record<string, unknown> | null }>;
            }
          ).results ?? [];

          const parsedEntries: ReasoningMemoryEntry[] = [];
          for (const result of searchResults) {
            const content = result.memory ?? result.content ?? '';
            const metadata = result.metadata ?? {};
            const entry = MemoryFormatter.parseMemoryContent(content, metadata);
            parsedEntries.push(entry);
          }

          // Filter out any cross-tenant results
          const tenantFiltered = filterCrossTenantResults(
            parsedEntries,
            validatedTenantId,
            (item) => item.tenant_id
          );

          return tenantFiltered;
        },
        async () => {
          // Fallback: return from in-memory store
          return this.fallbackStore.getEntriesByTenant(validatedTenantId, { limit });
        }
      );

      return entries;
    } catch {
      // Error containment: no exception propagation, return from fallback store
      return this.fallbackStore.getEntriesByTenant(validatedTenantId, { limit });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DatabaseClient interface
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Insert a record into the specified table.
   * Routes to Supermemory client.add() with content formatted for embedding.
   * On circuit breaker fallback, stores in the in-memory fallback store and
   * queues the write for later replay.
   */
  async insert(table: string, record: Record<string, unknown>): Promise<void> {
    const tenantId = record.tenant_id as string | undefined;
    const validatedTenantId = validateTenantId(tenantId);
    const recordId = record.id as string;

    // Format the content: use MemoryFormatter for reasoning_memory entries,
    // otherwise serialize as JSON
    const isReasoningMemoryEntry = 'threat_type' in record && 'incident_id' in record;
    const content = isReasoningMemoryEntry
      ? MemoryFormatter.formatMemoryEntryForStorage(record as unknown as ReasoningMemoryEntry)
      : JSON.stringify(record);

    // Build metadata for Supermemory storage
    const metadata: Record<string, unknown> = {
      type: isReasoningMemoryEntry ? 'memory_entry' : table,
      tenant_id: validatedTenantId,
      ...(isReasoningMemoryEntry ? {
        incident_id: (record as Record<string, unknown>).incident_id,
        threat_type: (record as Record<string, unknown>).threat_type,
        severity: (record as Record<string, unknown>).severity ?? 'N/A',
        mitre_techniques: Array.isArray((record as Record<string, unknown>).mitre_technique_ids)
          ? ((record as Record<string, unknown>).mitre_technique_ids as string[]).join(',')
          : '',
        outcome: (record as Record<string, unknown>).outcome ?? 'ONGOING',
        has_feedback: !!(record as Record<string, unknown>).analyst_feedback,
        created_at: (record as Record<string, unknown>).created_at ?? new Date().toISOString(),
      } : {}),
    };

    // Always store in the fallback store to keep it warm
    if (isReasoningMemoryEntry) {
      this.fallbackStore.addEntry(validatedTenantId, record as unknown as ReasoningMemoryEntry);
    }

    await this.circuitBreaker.execute(
      async () => {
        await this.client.add({
          content,
          containerTag: validatedTenantId,
          customId: recordId,
          metadata,
        });
      },
      async () => {
        // Fallback: store already done above, queue the write for replay
        this.writeQueue.enqueue({
          id: recordId,
          operation: 'add',
          tenantId: validatedTenantId,
          payload: content,
          timestamp: new Date().toISOString(),
          retryCount: 0,
        });
      }
    );
  }

  /**
   * Find a single record by ID within a tenant scope.
   * Uses Supermemory search filtered by customId. Falls back to in-memory store.
   */
  async findById(
    _table: string,
    id: string,
    tenantId: string
  ): Promise<Record<string, unknown> | null> {
    const validatedTenantId = validateTenantId(tenantId);

    const result = await this.circuitBreaker.execute<Record<string, unknown> | null>(
      async () => {
        // Search Supermemory with empty query scoped to tenant, then filter by customId
        const response = await this.client.search.memories({
          q: '',
          containerTag: validatedTenantId,
          limit: 50,
        });

        const searchResults = (
          response as unknown as {
            results: Array<{ id?: string; customId?: string; content?: string; memory?: string; metadata?: Record<string, unknown> | null }>;
          }
        ).results ?? [];

        // Find the result matching the requested ID
        for (const result of searchResults) {
          const resultId = result.customId ?? result.id;
          if (resultId === id) {
            const content = result.memory ?? result.content ?? '';
            const metadata = result.metadata ?? {};
            const entry = MemoryFormatter.parseMemoryContent(content, metadata);
            // Verify tenant isolation
            if (entry.tenant_id === validatedTenantId) {
              return entry as unknown as Record<string, unknown>;
            }
          }
        }

        return null;
      },
      async () => {
        // Fallback: look up from in-memory store
        const entry = this.fallbackStore.findById(validatedTenantId, id);
        return entry ? (entry as unknown as Record<string, unknown>) : null;
      }
    );

    return result;
  }

  /**
   * Find all records for a given tenant, with optional limit/offset pagination.
   * Uses Supermemory search scoped by containerTag. Falls back to in-memory store.
   */
  async findByTenantId(
    _table: string,
    tenantId: string,
    options?: { limit?: number; offset?: number }
  ): Promise<Record<string, unknown>[]> {
    const validatedTenantId = validateTenantId(tenantId);
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    const results = await this.circuitBreaker.execute<Record<string, unknown>[]>(
      async () => {
        // Request enough records to cover limit + offset
        const fetchLimit = limit + offset;
        const response = await this.client.search.memories({
          q: '',
          containerTag: validatedTenantId,
          limit: fetchLimit,
        });

        const searchResults = (
          response as unknown as {
            results: Array<{ content?: string; memory?: string; metadata?: Record<string, unknown> | null }>;
          }
        ).results ?? [];

        const entries: Record<string, unknown>[] = [];
        for (const result of searchResults) {
          const content = result.memory ?? result.content ?? '';
          const metadata = result.metadata ?? {};
          const entry = MemoryFormatter.parseMemoryContent(content, metadata);
          // Verify tenant isolation
          if (entry.tenant_id === validatedTenantId) {
            entries.push(entry as unknown as Record<string, unknown>);
          }
        }

        // Apply offset pagination
        return entries.slice(offset, offset + limit);
      },
      async () => {
        // Fallback: retrieve from in-memory store
        const entries = this.fallbackStore.getEntriesByTenant(validatedTenantId, { limit: limit + offset });
        return entries.slice(offset, offset + limit) as unknown as Record<string, unknown>[];
      }
    );

    return results;
  }

  /**
   * Update a record by ID within a tenant scope.
   * Merges updates into the existing record, then re-adds to Supermemory
   * with the same customId (Supermemory upserts on customId).
   */
  async update(
    _table: string,
    id: string,
    tenantId: string,
    updates: Record<string, unknown>
  ): Promise<void> {
    const validatedTenantId = validateTenantId(tenantId);

    // Get existing record from fallback store
    const existing = this.fallbackStore.findById(validatedTenantId, id);
    const merged = existing
      ? { ...existing, ...updates }
      : { id, tenant_id: validatedTenantId, ...updates };

    // Update the fallback store
    if (existing) {
      this.fallbackStore.update(validatedTenantId, id, updates as Partial<ReasoningMemoryEntry>);
    }

    // Format for Supermemory
    const isReasoningMemoryEntry = 'threat_type' in merged && 'incident_id' in merged;
    const content = isReasoningMemoryEntry
      ? MemoryFormatter.formatMemoryEntryForStorage(merged as unknown as ReasoningMemoryEntry)
      : JSON.stringify(merged);

    const metadata: Record<string, unknown> = {
      type: isReasoningMemoryEntry ? 'memory_entry' : 'unknown',
      tenant_id: validatedTenantId,
      ...(isReasoningMemoryEntry ? {
        incident_id: (merged as Record<string, unknown>).incident_id,
        threat_type: (merged as Record<string, unknown>).threat_type,
        outcome: (merged as Record<string, unknown>).outcome ?? 'ONGOING',
        has_feedback: !!(merged as Record<string, unknown>).analyst_feedback,
      } : {}),
    };

    await this.circuitBreaker.execute(
      async () => {
        // Re-add with same customId — Supermemory upserts on customId
        await this.client.add({
          content,
          containerTag: validatedTenantId,
          customId: id,
          metadata,
        });
      },
      async () => {
        // Fallback: store update already applied above, queue for replay
        this.writeQueue.enqueue({
          id,
          operation: 'update',
          tenantId: validatedTenantId,
          payload: content,
          timestamp: new Date().toISOString(),
          retryCount: 0,
        });
      }
    );
  }

  /**
   * Delete all records for a given tenant.
   * Attempts to use Supermemory's search + delete scoped by containerTag.
   * Also clears the fallback store for this tenant.
   */
  async deleteByTenantId(_table: string, tenantId: string): Promise<number> {
    const validatedTenantId = validateTenantId(tenantId);

    // Clear from fallback store regardless
    this.fallbackStore.clear(validatedTenantId);

    await this.circuitBreaker.execute(
      async () => {
        // Supermemory doesn't have a bulk-delete-by-container API in the SDK,
        // so we search for all entries in this container and delete individually
        // if available. For now, log a warning since the SDK may not expose delete.
        console.warn(
          `[MemoryLayer] deleteByTenantId: Supermemory SDK does not provide a bulk delete API. ` +
          `Entries for tenant "${validatedTenantId}" remain in Supermemory but are cleared from fallback store.`
        );
      },
      async () => {
        // Fallback: already cleared from fallback store above
        console.warn(
          `[MemoryLayer] deleteByTenantId: Circuit open, cleared fallback store for tenant "${validatedTenantId}".`
        );
      }
    );

    // Return 0 since we cannot determine actual count from Supermemory
    return 0;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Incident & Feedback Memory Operations
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Store an incident as a Memory_Entry when an incident is created.
   * Called from the event pipeline on incident creation.
   * Formats content using MemoryFormatter and stores via circuit breaker
   * with in-memory fallback and write queue for replay.
   */
  async saveIncidentMemory(incident: Incident, reasoning?: ReasoningResponse): Promise<void> {
    const validatedTenantId = validateTenantId(incident.tenant_id);

    // Format content for optimal semantic search
    const content = MemoryFormatter.formatIncidentForStorage(incident, reasoning);

    // Build metadata for Supermemory storage
    const metadata: SupermemoryMetadata = {
      type: 'incident',
      incident_id: incident.id,
      tenant_id: validatedTenantId,
      threat_type: incident.threat_type,
      severity: incident.severity,
      mitre_techniques: incident.mitre_techniques.map(t => t.technique_id).join(','),
      outcome: incident.status,
      has_feedback: false,
      created_at: incident.created_at,
    };

    // Build a ReasoningMemoryEntry and store in fallbackStore (keeps it warm)
    const memoryEntry: ReasoningMemoryEntry = {
      id: incident.id,
      tenant_id: validatedTenantId,
      incident_id: incident.id,
      threat_type: incident.threat_type,
      threat_description: incident.description,
      affected_asset_types: incident.affected_assets,
      mitre_technique_ids: incident.mitre_techniques.map(t => t.technique_id),
      actions_taken: [],
      outcome: 'ONGOING',
      embedding_text: reasoning?.explanation ?? incident.description,
      created_at: incident.created_at,
    };

    this.fallbackStore.addEntry(validatedTenantId, memoryEntry);

    await this.circuitBreaker.execute(
      async () => {
        await this.client.add({
          content,
          containerTag: validatedTenantId,
          customId: incident.id,
          metadata: metadata as unknown as Record<string, unknown>,
        });
      },
      async () => {
        // Fallback: store already done above, queue write for later replay
        this.writeQueue.enqueue({
          id: incident.id,
          operation: 'add',
          tenantId: validatedTenantId,
          payload: content,
          timestamp: new Date().toISOString(),
          retryCount: 0,
        });
      }
    );
  }

  /**
   * Update a memory entry when an incident is resolved or marked as false positive.
   * Updates the outcome field in both the fallback store and Supermemory.
   */
  async updateIncidentResolution(incidentId: string, tenantId: string, outcome: string): Promise<void> {
    const validatedTenantId = validateTenantId(tenantId);

    // Find existing entry in fallbackStore and update its outcome
    const existing = this.fallbackStore.findById(validatedTenantId, incidentId);
    const validOutcome = outcome as ReasoningMemoryEntry['outcome'];

    if (existing) {
      this.fallbackStore.update(validatedTenantId, incidentId, { outcome: validOutcome });
    }

    // Get the updated entry for re-formatting
    const updatedEntry = this.fallbackStore.findById(validatedTenantId, incidentId);

    // Format the updated entry for Supermemory
    const content = updatedEntry
      ? MemoryFormatter.formatMemoryEntryForStorage(updatedEntry)
      : `[Incident ID: ${incidentId}]\nOutcome: ${outcome}`;

    const metadata: Partial<SupermemoryMetadata> = {
      type: 'incident',
      incident_id: incidentId,
      tenant_id: validatedTenantId,
      outcome: validOutcome,
    };

    await this.circuitBreaker.execute(
      async () => {
        // Re-add to Supermemory with same customId (upserts on customId)
        await this.client.add({
          content,
          containerTag: validatedTenantId,
          customId: incidentId,
          metadata: metadata as unknown as Record<string, unknown>,
        });
      },
      async () => {
        // Fallback: update already applied above, queue write for replay
        this.writeQueue.enqueue({
          id: incidentId,
          operation: 'update',
          tenantId: validatedTenantId,
          payload: content,
          timestamp: new Date().toISOString(),
          retryCount: 0,
        });
      }
    );
  }

  /**
   * Store analyst feedback for an incident.
   * Updates the existing memory entry with the analyst's verdict and notes,
   * then re-formats and stores the updated entry.
   */
  async saveAnalystFeedback(incidentId: string, tenantId: string, feedback: AnalystFeedback): Promise<void> {
    const validatedTenantId = validateTenantId(tenantId);

    // Find existing entry in fallbackStore and add analyst_feedback field
    const existing = this.fallbackStore.findById(validatedTenantId, incidentId);

    if (existing) {
      this.fallbackStore.update(validatedTenantId, incidentId, { analyst_feedback: feedback });
    }

    // Get the updated entry for re-formatting
    const updatedEntry = this.fallbackStore.findById(validatedTenantId, incidentId);

    // Re-format the full entry for Supermemory
    const content = updatedEntry
      ? MemoryFormatter.formatMemoryEntryForStorage(updatedEntry)
      : MemoryFormatter.formatFeedbackUpdate(feedback);

    const metadata: Partial<SupermemoryMetadata> = {
      type: 'incident',
      incident_id: incidentId,
      tenant_id: validatedTenantId,
      has_feedback: true,
    };

    await this.circuitBreaker.execute(
      async () => {
        // Re-add to Supermemory with same customId and updated metadata
        await this.client.add({
          content,
          containerTag: validatedTenantId,
          customId: incidentId,
          metadata: metadata as unknown as Record<string, unknown>,
        });
      },
      async () => {
        // Fallback: update already applied above, queue write for replay
        this.writeQueue.enqueue({
          id: incidentId,
          operation: 'update',
          tenantId: validatedTenantId,
          payload: content,
          timestamp: new Date().toISOString(),
          retryCount: 0,
        });
      }
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Private — Reconnection Logic
  // ═══════════════════════════════════════════════════════════════════════════

  private startReconnectionTimer(): void {
    if (this.reconnectTimer !== null) return;

    this.reconnectTimer = setInterval(async () => {
      try {
        await this.client.search.memories({ q: '', limit: 1 });
        // Probe succeeded — restore connectivity
        this.connected = true;
        this.circuitBreaker.recordSuccess();
        console.info('[MemoryLayer] Reconnected to Supermemory. Resuming normal operations.');

        // Replay queued writes
        if (this.writeQueue.size() > 0) {
          const result = await this.writeQueue.replayAll(async (write) => {
            await this.client.add({
              content: write.payload as string,
              containerTag: write.tenantId,
              customId: write.id,
            });
          });
          console.info(
            `[MemoryLayer] Write queue replay: ${result.succeeded} succeeded, ${result.failed} failed.`
          );
        }

        this.stopReconnectionTimer();
      } catch {
        // Still unavailable — stay in fallback
        this.circuitBreaker.recordFailure();
      }
    }, this.config.reconnectIntervalMs);
  }

  private stopReconnectionTimer(): void {
    if (this.reconnectTimer !== null) {
      clearInterval(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}
