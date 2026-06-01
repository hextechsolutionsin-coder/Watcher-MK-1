const API_BASE = '/api/v1';

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(`API error ${res.status}: ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export function fetchIncidents(params?: { severity?: string; status?: string }) {
  const url = new URL(`${API_BASE}/incidents`, window.location.origin);
  if (params?.severity) url.searchParams.set('severity', params.severity);
  if (params?.status) url.searchParams.set('status', params.status);
  return apiFetch<unknown[]>(url.toString());
}

export function fetchIncidentById(id: string) {
  return apiFetch<unknown>(`${API_BASE}/incidents/${id}`);
}

export function fetchIncidentTimeline(id: string) {
  return apiFetch<unknown[]>(`${API_BASE}/incidents/${id}/timeline`);
}

// ── Approvals ─────────────────────────────────────────────────────────────────

export function fetchApprovals() {
  return apiFetch<unknown[]>(`${API_BASE}/approvals`);
}

export function approveAction(actionId: string, approverId: string) {
  return apiFetch<unknown>(`${API_BASE}/approvals/${actionId}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approver_id: approverId }),
  });
}

export function rejectAction(actionId: string, approverId: string, reason: string) {
  return apiFetch<unknown>(`${API_BASE}/approvals/${actionId}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approver_id: approverId, reason }),
  });
}

export function retryAction(actionId: string) {
  return apiFetch<unknown>(`${API_BASE}/approvals/${actionId}/retry`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Actions ───────────────────────────────────────────────────────────────────

export function fetchActions(params?: { type?: string; outcome?: string }) {
  const url = new URL(`${API_BASE}/actions`, window.location.origin);
  if (params?.type) url.searchParams.set('type', params.type);
  if (params?.outcome) url.searchParams.set('outcome', params.outcome);
  return apiFetch<unknown[]>(url.toString());
}

// ── Metrics ───────────────────────────────────────────────────────────────────

export function fetchRiskScore() {
  return apiFetch<{ score: number }>(`${API_BASE}/metrics/risk-score`);
}

export function fetchKpis() {
  return apiFetch<unknown>(`${API_BASE}/metrics/kpis`);
}

export function fetchTrends() {
  return apiFetch<unknown>(`${API_BASE}/metrics/trends`);
}

// ── Connectors ────────────────────────────────────────────────────────────────

export function fetchConnectors() {
  return apiFetch<unknown[]>(`${API_BASE}/connectors`);
}

export function registerConnector(body: {
  tenant_id: string;
  role_arn: string;
  account_id: string;
  regions: string[];
  data_sources: string[];
}) {
  return apiFetch<unknown>(`${API_BASE}/connectors`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export function pauseConnector(connectorId: string) {
  return apiFetch<unknown>(`${API_BASE}/connectors/${connectorId}`, { method: 'DELETE' });
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

export function fetchPipelineStatus() {
  return apiFetch<unknown>(`${API_BASE}/pipeline/status`);
}

export function fetchTrustLevel() {
  return apiFetch<unknown>(`${API_BASE}/pipeline/trust`);
}

export function fetchRollbacks() {
  return apiFetch<unknown[]>(`${API_BASE}/pipeline/rollbacks`);
}

// ── Known IPs ─────────────────────────────────────────────────────────────────

export function fetchKnownIps() {
  return apiFetch<unknown[]>(`${API_BASE}/pipeline/known-ips`);
}

export function addKnownIp(body: { ip: string; label: string; owner: string; notes?: string }) {
  return apiFetch<unknown>(`${API_BASE}/pipeline/known-ips`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export function deleteKnownIp(id: string) {
  return apiFetch<unknown>(`${API_BASE}/pipeline/known-ips/${id}`, { method: 'DELETE' });
}

// ── Environment Facts ─────────────────────────────────────────────────────────

export function fetchEnvironmentFacts() {
  return apiFetch<unknown[]>(`${API_BASE}/pipeline/facts`);
}

export function addEnvironmentFact(fact: string) {
  return apiFetch<unknown>(`${API_BASE}/pipeline/facts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fact }),
  });
}

export function deleteEnvironmentFact(index: number) {
  return apiFetch<unknown>(`${API_BASE}/pipeline/facts/${index}`, { method: 'DELETE' });
}

// ── Polled Events ─────────────────────────────────────────────────────────────

export function fetchPolledEvents(params?: {
  status?: string;
  source?: string;
  incident_id?: string;
  event_id?: string;
  limit?: number;
}) {
  const url = new URL(`${API_BASE}/events`, window.location.origin);
  if (params?.status) url.searchParams.set('status', params.status);
  if (params?.source) url.searchParams.set('source', params.source);
  if (params?.incident_id) url.searchParams.set('incident_id', params.incident_id);
  if (params?.event_id) url.searchParams.set('event_id', params.event_id);
  if (params?.limit) url.searchParams.set('limit', String(params.limit));
  return apiFetch<unknown[]>(url.toString());
}

export function fetchPolledEventStats() {
  return apiFetch<unknown>(`${API_BASE}/events/stats`);
}

export function fetchPolledEventById(eventId: string) {
  return apiFetch<unknown>(`${API_BASE}/events/${eventId}`);
}

export function fetchSuppressions() {
  return apiFetch<unknown[]>(`${API_BASE}/suppressions`);
}

export function createSuppression(body: {
  type: string;
  value: string;
  reason: string;
  created_by?: string;
}) {
  return apiFetch<unknown>(`${API_BASE}/suppressions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export function deleteSuppression(id: string) {
  return apiFetch<unknown>(`${API_BASE}/suppressions/${id}`, { method: 'DELETE' });
}

// ── Feedback ──────────────────────────────────────────────────────────────────

export function submitFeedback(incidentId: string, body: {
  verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'SEVERITY_WRONG';
  correct_severity?: string;
  notes?: string;
  analyst_id?: string;
}) {
  return apiFetch<unknown>(`${API_BASE}/incidents/${incidentId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
