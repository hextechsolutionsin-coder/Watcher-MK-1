/**
 * In-memory data store for the prototype API server.
 *
 * When DB_ENABLED=true, write operations are mirrored to PostgreSQL.
 * Read operations use the in-memory store for speed (cache-first).
 * On startup with DB_ENABLED=true, the in-memory store is hydrated from the DB.
 *
 * Performance notes:
 * - incidentIndex / actionIndex: O(1) lookups by ID instead of O(n) array scan
 * - polled_events uses push (O(1)) not unshift (O(n)); newest-first sort on read
 */

import type { PolledEventStatus } from './store.js';

export interface StoreIncident {
  id: string;
  tenant_id: string;
  severity_level: string;
  confidence_score: number;
  review_required: boolean;
  status: string;
  affected_assets: any[];
  attack_surface: string;
  detection_timestamp: string;
  evidence: any[];
  mitre_technique_ids: string[];
  recommended_actions: string[];
  created_at: string;
  updated_at: string;
}

export interface StoreAction {
  id: string;
  incident_id: string;
  tenant_id: string;
  action_type: string;
  status: string;
  severity_level: string;
  approver_id?: string;
  rejection_reason?: string;
  retry_count: number;
  execution_timestamp?: string;
  outcome?: string;
  affected_asset: any;
  ai_reasoning?: string;
  ai_params?: Record<string, unknown>;
  blast_radius?: string;
  rollback_description?: string;
  created_at: string;
  updated_at: string;
}

export interface StoreTimelineEvent {
  id: string;
  incident_id: string;
  timestamp: string;
  type: string;
  title: string;
  description: string;
  actor?: string;
}

export type PolledEventStatus = 'PROCESSED' | 'CORRELATED' | 'SKIPPED';

export interface StorePolledEvent {
  id: string;
  event_name: string;
  event_time: string;
  received_at: string;
  source: string;
  account_id: string;
  region: string;
  actor_arn: string;
  actor_type: string;
  actor_short: string;
  source_ip: string | null;
  status: PolledEventStatus;
  reason: string;
  incident_id: string | null;
  error_code: string | null;
  raw_payload: Record<string, unknown>;
}

export interface Store {
  incidents: StoreIncident[];
  actions: StoreAction[];
  timeline_events: StoreTimelineEvent[];
  polled_events: StorePolledEvent[];
}

export const store: Store = {
  incidents: [],
  actions: [],
  timeline_events: [],
  polled_events: [],
};

// =========================================================================
// O(1) index maps — kept in sync with the arrays above
// =========================================================================

/** incident.id → array index — O(1) lookup instead of O(n) find */
const incidentIndex = new Map<string, StoreIncident>();
/** action.id → StoreAction — O(1) lookup */
const actionIndex = new Map<string, StoreAction>();

// =========================================================================
// DB flag
// =========================================================================

function dbEnabled(): boolean {
  return process.env['DB_ENABLED'] === 'true';
}

// =========================================================================
// Incidents
// =========================================================================

export function getIncidents(params?: { severity?: string; status?: string }): StoreIncident[] {
  let results = store.incidents;
  if (params?.severity) results = results.filter((i) => i.severity_level === params.severity!.toUpperCase());
  if (params?.status) results = results.filter((i) => i.status === params.status!.toUpperCase());
  return results;
}

export function getIncidentById(id: string): StoreIncident | undefined {
  return incidentIndex.get(id);
}

export function addIncident(incident: StoreIncident): void {
  // Prevent duplicates
  if (incidentIndex.has(incident.id)) return;
  store.incidents.push(incident);
  incidentIndex.set(incident.id, incident);

  if (dbEnabled()) {
    import('../database/repositories.js').then(({ incidentsRepo }) => {
      incidentsRepo.create(incident as unknown as Record<string, unknown>).catch((err) =>
        console.error('[DB] Failed to persist incident:', err.message)
      );
    });
  }
}

// =========================================================================
// Actions
// =========================================================================

export function getActions(params?: { type?: string; outcome?: string }): StoreAction[] {
  let results = store.actions;
  if (params?.type) results = results.filter((a) => a.action_type === params.type!.toUpperCase());
  if (params?.outcome) results = results.filter((a) => a.outcome === params.outcome!.toUpperCase());
  return results;
}

export function addAction(action: StoreAction): void {
  if (actionIndex.has(action.id)) return;
  store.actions.push(action);
  actionIndex.set(action.id, action);

  if (dbEnabled()) {
    import('../database/repositories.js').then(({ actionsRepo }) => {
      actionsRepo.create(action as unknown as Record<string, unknown>).catch((err) =>
        console.error('[DB] Failed to persist action:', err.message)
      );
    });
  }
}

export function getPendingApprovals(): StoreAction[] {
  return store.actions.filter((a) => a.status === 'PENDING_APPROVAL');
}

export function getActionById(id: string): StoreAction | undefined {
  return actionIndex.get(id);
}

export function updateAction(id: string, updates: Partial<StoreAction>): StoreAction | undefined {
  const action = actionIndex.get(id);
  if (!action) return undefined;

  // Update in-place on the object (index and array share the same reference)
  Object.assign(action, updates);

  if (dbEnabled()) {
    import('../database/repositories.js').then(({ actionsRepo }) => {
      actionsRepo.update(id, updates as Record<string, unknown>).catch((err) =>
        console.error('[DB] Failed to update action:', err.message)
      );
    });
  }

  return action;
}

// =========================================================================
// Timeline Events
// =========================================================================

export function getTimelineForIncident(incidentId: string): StoreTimelineEvent[] {
  return store.timeline_events
    .filter((e) => e.incident_id === incidentId)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

export function addTimelineEvent(event: StoreTimelineEvent): void {
  if (store.timeline_events.some((e) => e.id === event.id)) return;
  store.timeline_events.push(event);

  if (dbEnabled()) {
    import('../database/repositories.js').then(({ timelineRepo }) => {
      timelineRepo.create(event as unknown as Record<string, unknown>).catch((err) =>
        console.error('[DB] Failed to persist timeline event:', err.message)
      );
    });
  }
}

// =========================================================================
// Polled Events
// =========================================================================

const MAX_POLLED_EVENTS = 2000;

export function addPolledEvent(event: StorePolledEvent): void {
  // push is O(1) — unshift was O(n) shifting every element
  store.polled_events.push(event);
  if (store.polled_events.length > MAX_POLLED_EVENTS) {
    // Remove oldest (front of array) — O(1) amortized with splice(0,1)
    store.polled_events.splice(0, store.polled_events.length - MAX_POLLED_EVENTS);
  }
}

export function getPolledEvents(params?: {
  status?: PolledEventStatus;
  source?: string;
  incident_id?: string;
  event_id?: string;
  limit?: number;
}): StorePolledEvent[] {
  let results = store.polled_events;
  if (params?.status) results = results.filter((e) => e.status === params.status);
  if (params?.source) results = results.filter((e) => e.source === params.source!.toUpperCase());
  if (params?.incident_id) results = results.filter((e) => e.incident_id === params.incident_id);
  if (params?.event_id) results = results.filter((e) => e.id === params.event_id);
  // Return newest first — reverse slice is O(k) where k = limit, not O(n)
  const limited = results.slice(-(params?.limit ?? 500));
  return limited.reverse();
}

export function getPolledEventById(id: string): StorePolledEvent | undefined {
  return store.polled_events.find((e) => e.id === id);
}

// =========================================================================
// DB Hydration — load existing data from PostgreSQL on startup
// =========================================================================

/**
 * Hydrates the in-memory store from PostgreSQL.
 * Called once on startup when DB_ENABLED=true.
 * This ensures the UI shows existing data after a server restart.
 */
export async function hydrateFromDatabase(tenantId = 'tenant-001'): Promise<void> {
  if (!dbEnabled()) return;

  try {
    const { incidentsRepo, actionsRepo, timelineRepo, connectorsRepo } = await import('../database/repositories.js');

    // Load incidents
    const incidents = await incidentsRepo.getByTenant(tenantId) as any[];
    for (const inc of incidents) {
      if (!incidentIndex.has(inc.id)) {
        const incident: StoreIncident = {
          id: inc.id,
          tenant_id: inc.tenant_id,
          severity_level: inc.severity ?? 'MEDIUM',
          confidence_score: inc.confidence ?? 50,
          review_required: inc.severity === 'CRITICAL' || inc.severity === 'HIGH',
          status: inc.status ?? 'OPEN',
          affected_assets: typeof inc.affected_assets === 'string' ? JSON.parse(inc.affected_assets) : (inc.affected_assets ?? []),
          attack_surface: inc.attack_surface ?? 'CLOUD_IAM',
          detection_timestamp: inc.detection_timestamp,
          evidence: [],
          mitre_technique_ids: typeof inc.mitre_techniques === 'string' ? JSON.parse(inc.mitre_techniques) : (inc.mitre_techniques ?? []),
          recommended_actions: [],
          created_at: inc.created_at,
          updated_at: inc.updated_at,
        };
        store.incidents.push(incident);
        incidentIndex.set(incident.id, incident);
      }
    }

    // Load actions
    const actions = await actionsRepo.getByTenant(tenantId) as any[];
    for (const act of actions) {
      if (!actionIndex.has(act.id)) {
        const action: StoreAction = {
          id: act.id,
          incident_id: act.incident_id,
          tenant_id: act.tenant_id,
          action_type: act.action_type,
          status: act.status,
          severity_level: act.severity_level ?? 'MEDIUM',
          approver_id: act.approver_id,
          rejection_reason: act.rejection_reason,
          retry_count: act.retry_count ?? 0,
          execution_timestamp: act.execution_timestamp,
          outcome: act.outcome,
          affected_asset: typeof act.affected_asset === 'string' ? JSON.parse(act.affected_asset) : act.affected_asset,
          ai_reasoning: act.ai_reasoning,
          blast_radius: act.blast_radius,
          rollback_description: act.rollback_spec?.description,
          created_at: act.created_at,
          updated_at: act.updated_at,
        };
        store.actions.push(action);
        actionIndex.set(action.id, action);
      }
    }

    // Load timeline events for all loaded incidents
    for (const inc of store.incidents) {
      const events = await timelineRepo.getByIncident(inc.id) as any[];
      for (const ev of events) {
        if (!store.timeline_events.some((e) => e.id === ev.id)) {
          store.timeline_events.push({
            id: ev.id,
            incident_id: ev.incident_id,
            timestamp: ev.timestamp,
            type: ev.type,
            title: ev.title,
            description: ev.description,
            actor: ev.actor,
          });
        }
      }
    }

    // Load connectors and re-register them in the polling loop
    const connectors = await connectorsRepo.getAll() as any[];
    if (connectors.length > 0) {
      const { registerConnector } = await import('../pipeline/polling-loop.js');
      const { AwsDataSource } = await import('../types/index.js');
      for (const c of connectors) {
        if (c.status === 'ACTIVE') {
          registerConnector({
            id: c.id,
            tenant_id: c.tenant_id,
            account_id: c.account_id,
            role_arn: c.role_arn,
            regions: c.regions ?? ['us-east-1'],
            data_sources: (c.data_sources ?? ['CLOUDTRAIL']) as any[],
            registered_at: c.registered_at,
            last_poll_at: c.last_poll_at,
            status: 'ACTIVE',
          });
        }
      }
      console.log(`[DB] Restored ${connectors.length} connector(s) from database`);
    }

    console.log(`[DB] Hydrated: ${store.incidents.length} incidents, ${store.actions.length} actions, ${store.timeline_events.length} timeline events`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[DB] Hydration failed: ${message}`);
  }
}
