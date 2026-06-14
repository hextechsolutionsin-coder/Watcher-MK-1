/**
 * Semantic Memory Layer — Type Definitions
 *
 * Defines interfaces and types for the Supermemory-powered semantic memory system.
 * The SemanticMemoryProvider extends the existing MemoryProvider interface to add
 * semantic search, entity profiles, and pattern summary capabilities.
 */

import { ReasoningMemoryEntry } from '../types/index.js';
import { MemoryProvider } from '../ai/context-assembler.js';

// ============================================================================
// Search Results
// ============================================================================

/** A semantic search result with relevance scoring. */
export interface SemanticSearchResult {
  entry: ReasoningMemoryEntry;
  relevanceScore: number;
}

// ============================================================================
// Entity Profiles
// ============================================================================

/** An entity profile aggregated from stored memories by Supermemory. */
export interface EntityProfile {
  entityId: string;
  tenantId: string;
  /** Long-term behavioral patterns (e.g., "This IAM user typically accesses S3 in us-east-1") */
  staticFacts: string[];
  /** Recent activity summary (e.g., "Recently involved in 2 credential rotation incidents") */
  dynamicContext: string[];
}

// ============================================================================
// Connection & Circuit State
// ============================================================================

/** Connection status reported by the Memory Layer health check. */
export type ConnectionStatus = 'connected' | 'fallback' | 'disconnected';

/** Circuit breaker state for managing Supermemory connectivity. */
export type CircuitState = 'closed' | 'open' | 'half-open';

// ============================================================================
// Write Queue
// ============================================================================

/** A queued write operation for replay when Supermemory connectivity is restored. */
export interface QueuedWrite {
  id: string;
  operation: 'add' | 'update' | 'forget';
  tenantId: string;
  payload: unknown;
  timestamp: string;
  retryCount: number;
}

// ============================================================================
// Semantic Memory Provider
// ============================================================================

/**
 * Extended memory provider with semantic search capabilities.
 *
 * Extends the existing MemoryProvider interface to add Supermemory-powered
 * semantic search, entity profiles, and pattern summary methods. The
 * ContextAssembler uses duck-typing to detect whether the injected
 * MemoryProvider also implements this interface.
 */
export interface SemanticMemoryProvider extends MemoryProvider {
  /**
   * Perform a semantic search against stored memories using vector similarity.
   * Results are ranked by relevance score and capped at the configured limit.
   */
  semanticSearch(
    tenantId: string,
    query: string,
    options?: { limit?: number; threshold?: number }
  ): Promise<SemanticSearchResult[]>;

  /**
   * Retrieve the entity profile for a given actor or resource.
   * Returns null if no profile exists or if Supermemory is unavailable.
   */
  getEntityProfile(
    tenantId: string,
    entityId: string
  ): Promise<EntityProfile | null>;

  /**
   * Retrieve a pattern summary filtered by threat category or MITRE technique.
   * Used in PROACTIVE mode to surface unresolved patterns and repeated vulnerabilities.
   */
  getPatternSummary(
    tenantId: string,
    options?: { threatCategory?: string; mitreTechnique?: string }
  ): Promise<SemanticSearchResult[]>;
}
