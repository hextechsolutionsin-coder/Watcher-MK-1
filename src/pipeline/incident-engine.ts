/**
 * Incident Engine (Task 12)
 *
 * Creates and manages Incident records from AI reasoning responses.
 * The AI reasons about threats — this engine persists those findings
 * as structured Incident records that the UI and API expose.
 */

import {
  Incident,
  IncidentStatus,
  NormalizedEvent,
  ReasoningResponse,
} from '../types/index.js';

// ============================================================================
// Store Interface
// ============================================================================

export interface IncidentStore {
  createFromReasoning(
    tenantId: string,
    accountId: string,
    event: NormalizedEvent,
    response: ReasoningResponse
  ): Promise<Incident>;

  getById(id: string, tenantId: string): Promise<Incident | null>;
  getByTenant(tenantId: string, options?: { limit?: number; status?: IncidentStatus }): Promise<Incident[]>;
  update(id: string, tenantId: string, updates: Partial<Incident>): Promise<void>;
}

// ============================================================================
// In-Memory Incident Store (prototype)
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

export class InMemoryIncidentStore implements IncidentStore {
  private readonly incidents = new Map<string, Incident>();

  async createFromReasoning(
    tenantId: string,
    accountId: string,
    event: NormalizedEvent,
    response: ReasoningResponse
  ): Promise<Incident> {
    const now = new Date().toISOString();
    const assessment = response.assessment!;

    const incident: Incident = {
      id: generateId(),
      tenant_id: tenantId,
      account_id: accountId,
      severity: assessment.severity,
      confidence: assessment.confidence,
      threat_type: assessment.threat_type,
      description: assessment.threat_description,
      explanation: response.explanation,
      mitre_techniques: assessment.mitre_techniques,
      affected_assets: assessment.affected_assets.length > 0
        ? assessment.affected_assets
        : [event.target.resource_id],
      attack_surface: event.attack_surface,
      kill_chain_stage: assessment.kill_chain_stage,
      predictions: assessment.predictions,
      status: IncidentStatus.OPEN,
      reasoning_response_id: response.id,
      action_plan_id: response.action_plan?.id,
      detection_timestamp: event.ingestion_timestamp,
      created_at: now,
      updated_at: now,
    };

    this.incidents.set(`${tenantId}:${incident.id}`, incident);
    return incident;
  }

  async getById(id: string, tenantId: string): Promise<Incident | null> {
    return this.incidents.get(`${tenantId}:${id}`) ?? null;
  }

  async getByTenant(
    tenantId: string,
    options?: { limit?: number; status?: IncidentStatus }
  ): Promise<Incident[]> {
    let results = [...this.incidents.values()].filter((i) => i.tenant_id === tenantId);

    if (options?.status) {
      results = results.filter((i) => i.status === options.status);
    }

    results.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    if (options?.limit) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  async update(id: string, tenantId: string, updates: Partial<Incident>): Promise<void> {
    const key = `${tenantId}:${id}`;
    const existing = this.incidents.get(key);
    if (existing) {
      this.incidents.set(key, { ...existing, ...updates, updated_at: new Date().toISOString() });
    }
  }
}
