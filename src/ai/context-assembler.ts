/**
 * Context Assembler
 *
 * Assembles the full ReasoningRequest before each AI reasoning call.
 * Pulls from: environment model, reasoning memory, tool capabilities,
 * recent events, and tenant config.
 *
 * This is what makes the AI's reasoning contextual — it doesn't just
 * see the raw event, it sees the event in the context of the entire
 * environment, past incidents, and available tools.
 */

import {
  ReasoningRequest,
  ReasoningMode,
  NormalizedEvent,
  EnvironmentContext,
  ReasoningMemoryEntry,
  ToolCapabilityProfile,
  TenantConfig,
  TrustLevel,
} from '../types/index.js';

// ============================================================================
// Interfaces
// ============================================================================

export interface EnvironmentContextProvider {
  assembleContext(tenantId: string, accountId: string, relevantResourceIds?: string[]): Promise<EnvironmentContext>;
}

export interface MemoryProvider {
  getMemoryEntriesByTenant(tenantId: string, options?: { limit?: number }): Promise<ReasoningMemoryEntry[]>;
}

export interface ToolCapabilityProvider {
  getCapabilitiesForTenant(tenantId: string): Promise<ToolCapabilityProfile[]>;
}

export interface TenantConfigProvider {
  getConfig(tenantId: string): Promise<TenantConfig>;
}

export interface RecentEventsProvider {
  getRecentEvents(tenantId: string, limit: number): Promise<NormalizedEvent[]>;
}

// ============================================================================
// Default Tenant Config
// ============================================================================

export function defaultTenantConfig(tenantId: string): TenantConfig {
  return {
    tenant_id: tenantId,
    trust_level: TrustLevel.ONE,
    confidence_threshold_low: 70,
    confidence_threshold_medium: 85,
    approval_timeout_hours: 4,
    approval_channels: [],
    reasoning_sensitivity: 'MEDIUM',
    cross_tenant_opt_in: false,
    gdpr_mode: false,
    data_retention_days: 365,
    aws_accounts: [],
  };
}

// ============================================================================
// Context Assembler
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

/**
 * Assembles a complete ReasoningRequest for the AI Reasoning Engine.
 *
 * For REACTIVE mode: pulls context relevant to the triggering event.
 * For PROACTIVE/PREDICTIVE/INVESTIGATIVE: pulls broader environment context.
 */
export class ContextAssembler {
  private readonly envProvider: EnvironmentContextProvider;
  private readonly memoryProvider: MemoryProvider;
  private readonly toolProvider: ToolCapabilityProvider;
  private readonly configProvider: TenantConfigProvider;
  private readonly eventsProvider: RecentEventsProvider;

  /** Max memory entries to include in context. */
  private static readonly MAX_MEMORY_ENTRIES = 10;

  /** Max recent events to include in context. */
  private static readonly MAX_RECENT_EVENTS = 30;

  constructor(
    envProvider: EnvironmentContextProvider,
    memoryProvider: MemoryProvider,
    toolProvider: ToolCapabilityProvider,
    configProvider: TenantConfigProvider,
    eventsProvider: RecentEventsProvider
  ) {
    this.envProvider = envProvider;
    this.memoryProvider = memoryProvider;
    this.toolProvider = toolProvider;
    this.configProvider = configProvider;
    this.eventsProvider = eventsProvider;
  }

  /**
   * Assembles context for a REACTIVE reasoning request (triggered by an event).
   */
  async assembleReactive(
    tenantId: string,
    accountId: string,
    event: NormalizedEvent
  ): Promise<ReasoningRequest> {
    // Relevant resource IDs: the event's target + actor
    const relevantIds = [
      event.target.resource_id,
      event.actor.identifier,
    ].filter((id) => id && id !== 'unknown');

    const [envContext, memory, tools, config, recentEvents] = await Promise.all([
      this.envProvider.assembleContext(tenantId, accountId, relevantIds),
      this.memoryProvider.getMemoryEntriesByTenant(tenantId, { limit: ContextAssembler.MAX_MEMORY_ENTRIES }),
      this.toolProvider.getCapabilitiesForTenant(tenantId),
      this.configProvider.getConfig(tenantId),
      this.eventsProvider.getRecentEvents(tenantId, ContextAssembler.MAX_RECENT_EVENTS),
    ]);

    // Filter memory to entries relevant to this event type or affected assets
    const relevantMemory = this.filterRelevantMemory(memory, event);

    return {
      id: generateId(),
      tenant_id: tenantId,
      mode: ReasoningMode.REACTIVE,
      trigger_event: event,
      environment_context: envContext,
      recent_events: recentEvents.filter((e) => e.id !== event.id),
      relevant_memory: relevantMemory,
      tool_capabilities: tools,
      tenant_config: config,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Assembles context for a PROACTIVE reasoning request (threat hunting).
   */
  async assembleProactive(
    tenantId: string,
    accountId: string
  ): Promise<ReasoningRequest> {
    const [envContext, memory, tools, config, recentEvents] = await Promise.all([
      this.envProvider.assembleContext(tenantId, accountId),
      this.memoryProvider.getMemoryEntriesByTenant(tenantId, { limit: ContextAssembler.MAX_MEMORY_ENTRIES }),
      this.toolProvider.getCapabilitiesForTenant(tenantId),
      this.configProvider.getConfig(tenantId),
      this.eventsProvider.getRecentEvents(tenantId, ContextAssembler.MAX_RECENT_EVENTS),
    ]);

    return {
      id: generateId(),
      tenant_id: tenantId,
      mode: ReasoningMode.PROACTIVE,
      trigger_description: 'Autonomous threat hunting cycle — review environment for hidden threats',
      environment_context: envContext,
      recent_events: recentEvents,
      relevant_memory: memory,
      tool_capabilities: tools,
      tenant_config: config,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Assembles context for a PREDICTIVE reasoning request (forecasting).
   */
  async assemblePredictive(
    tenantId: string,
    accountId: string,
    triggerDescription: string
  ): Promise<ReasoningRequest> {
    const [envContext, tools, config] = await Promise.all([
      this.envProvider.assembleContext(tenantId, accountId),
      this.toolProvider.getCapabilitiesForTenant(tenantId),
      this.configProvider.getConfig(tenantId),
    ]);

    return {
      id: generateId(),
      tenant_id: tenantId,
      mode: ReasoningMode.PREDICTIVE,
      trigger_description: triggerDescription,
      environment_context: envContext,
      recent_events: [],
      relevant_memory: [],
      tool_capabilities: tools,
      tenant_config: config,
      created_at: new Date().toISOString(),
    };
  }

  /**
   * Assembles context for an INVESTIGATIVE reasoning request (analyst-requested).
   */
  async assembleInvestigative(
    tenantId: string,
    accountId: string,
    description: string,
    relevantResourceIds?: string[]
  ): Promise<ReasoningRequest> {
    const [envContext, memory, tools, config, recentEvents] = await Promise.all([
      this.envProvider.assembleContext(tenantId, accountId, relevantResourceIds),
      this.memoryProvider.getMemoryEntriesByTenant(tenantId, { limit: ContextAssembler.MAX_MEMORY_ENTRIES }),
      this.toolProvider.getCapabilitiesForTenant(tenantId),
      this.configProvider.getConfig(tenantId),
      this.eventsProvider.getRecentEvents(tenantId, ContextAssembler.MAX_RECENT_EVENTS),
    ]);

    return {
      id: generateId(),
      tenant_id: tenantId,
      mode: ReasoningMode.INVESTIGATIVE,
      trigger_description: description,
      environment_context: envContext,
      recent_events: recentEvents,
      relevant_memory: memory,
      tool_capabilities: tools,
      tenant_config: config,
      created_at: new Date().toISOString(),
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Filters memory entries to those most relevant to the current event.
   * Prioritizes: same threat type, same affected assets, same MITRE techniques.
   */
  private filterRelevantMemory(
    memory: ReasoningMemoryEntry[],
    event: NormalizedEvent
  ): ReasoningMemoryEntry[] {
    if (memory.length === 0) return [];

    const eventSurface = event.attack_surface;
    const actorId = event.actor.identifier;
    const targetId = event.target.resource_id;

    // Score each memory entry by relevance
    const scored = memory.map((entry) => {
      let score = 0;

      // Same affected asset type
      if (entry.affected_asset_types.some((t) => t.includes(event.target.resource_type))) {
        score += 3;
      }

      // Same actor
      if (entry.threat_description.includes(actorId)) score += 2;

      // Same target
      if (entry.threat_description.includes(targetId)) score += 2;

      // Same attack surface
      if (entry.threat_description.toLowerCase().includes(eventSurface.toLowerCase())) {
        score += 1;
      }

      // False positives are especially relevant — avoid repeating them
      if (entry.analyst_feedback?.verdict === 'FALSE_POSITIVE') score += 2;

      return { entry, score };
    });

    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, ContextAssembler.MAX_MEMORY_ENTRIES)
      .map((s) => s.entry);
  }
}
