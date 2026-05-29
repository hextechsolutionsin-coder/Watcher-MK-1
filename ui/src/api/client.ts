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
