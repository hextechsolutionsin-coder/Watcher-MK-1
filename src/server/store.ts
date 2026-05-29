/**
 * In-memory data store for the prototype API server.
 * Stores incidents, actions, and timeline events as simple arrays.
 */

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

export interface Store {
  incidents: StoreIncident[];
  actions: StoreAction[];
  timeline_events: StoreTimelineEvent[];
}

export const store: Store = {
  incidents: [],
  actions: [],
  timeline_events: [],
};

// =========================================================================
// Query functions
// =========================================================================

export function getIncidents(params?: { severity?: string; status?: string }): StoreIncident[] {
  let results = store.incidents;
  if (params?.severity) {
    results = results.filter((i) => i.severity_level === params.severity!.toUpperCase());
  }
  if (params?.status) {
    results = results.filter((i) => i.status === params.status!.toUpperCase());
  }
  return results;
}

export function getIncidentById(id: string): StoreIncident | undefined {
  return store.incidents.find((i) => i.id === id);
}

export function addIncident(incident: StoreIncident): void {
  store.incidents.push(incident);
}

export function getTimelineForIncident(incidentId: string): StoreTimelineEvent[] {
  return store.timeline_events
    .filter((e) => e.incident_id === incidentId)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

export function getActions(params?: { type?: string; outcome?: string }): StoreAction[] {
  let results = store.actions;
  if (params?.type) {
    results = results.filter((a) => a.action_type === params.type!.toUpperCase());
  }
  if (params?.outcome) {
    results = results.filter((a) => a.outcome === params.outcome!.toUpperCase());
  }
  return results;
}

export function addAction(action: StoreAction): void {
  store.actions.push(action);
}

export function getPendingApprovals(): StoreAction[] {
  return store.actions.filter((a) => a.status === 'PENDING_APPROVAL');
}

export function getActionById(id: string): StoreAction | undefined {
  return store.actions.find((a) => a.id === id);
}

export function updateAction(id: string, updates: Partial<StoreAction>): StoreAction | undefined {
  const idx = store.actions.findIndex((a) => a.id === id);
  if (idx === -1) return undefined;
  store.actions[idx] = { ...store.actions[idx], ...updates };
  return store.actions[idx];
}

export function addTimelineEvent(event: StoreTimelineEvent): void {
  store.timeline_events.push(event);
}
