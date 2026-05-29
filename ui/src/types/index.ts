// ============================================================================
// Frontend Type Definitions — AI-first architecture
// ============================================================================

export enum AttackSurface {
  CLOUD_IAM = 'CLOUD_IAM',
  CLOUD_COMPUTE = 'CLOUD_COMPUTE',
  CLOUD_STORAGE = 'CLOUD_STORAGE',
  CLOUD_NETWORK = 'CLOUD_NETWORK',
  CLOUD_SERVERLESS = 'CLOUD_SERVERLESS',
  CLOUD_DATABASE = 'CLOUD_DATABASE',
  CLOUD_CONTAINER = 'CLOUD_CONTAINER',
  CLOUD_CICD = 'CLOUD_CICD',
  // Legacy values for seed data compatibility
  CLOUD = 'CLOUD',
  ENDPOINT = 'ENDPOINT',
  NETWORK = 'NETWORK',
  SAAS = 'SAAS',
  IAM = 'IAM',
  CICD = 'CICD',
}

export enum SeverityLevel {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFORMATIONAL = 'INFORMATIONAL',
}

export enum IncidentStatus {
  OPEN = 'OPEN',
  IN_PROGRESS = 'IN_PROGRESS',
  RESOLVED = 'RESOLVED',
  SUPPRESSED = 'SUPPRESSED',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
}

export enum RemediationStatus {
  PENDING_APPROVAL = 'PENDING_APPROVAL',
  APPROVED = 'APPROVED',
  EXECUTING = 'EXECUTING',
  COMPLETED = 'COMPLETED',
  REJECTED = 'REJECTED',
  FAILED = 'FAILED',
  RETRYING = 'RETRYING',
  FAILED_FINAL = 'FAILED_FINAL',
  ESCALATED = 'ESCALATED',
}

export enum BlastRadius {
  NONE = 'NONE',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
}

// ── Incident ──────────────────────────────────────────────────────────────────

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface ThreatPrediction {
  next_likely_action: string;
  probability: number;
  recommended_preemption: string;
}

export interface Asset {
  id: string;
  class: string;
  identifier: string;
  criticality: number;
}

export interface Evidence {
  connector_id: string;
  attack_surface: string;
  raw_event_id: string;
  description: string;
  timestamp: string;
}

/** Unified Incident — supports both legacy seed data and new AI-generated incidents */
export interface Incident {
  id: string;
  tenant_id: string;
  // New AI fields
  severity?: SeverityLevel;
  confidence?: number;
  threat_type?: string;
  description?: string;
  explanation?: string;
  mitre_techniques?: MitreTechnique[];
  affected_assets?: string[];
  attack_surface?: string;
  kill_chain_stage?: string;
  predictions?: ThreatPrediction;
  status: IncidentStatus;
  reasoning_response_id?: string;
  action_plan_id?: string;
  detection_timestamp?: string;
  // Legacy seed data fields
  severity_level?: SeverityLevel;
  confidence_score?: number;
  review_required?: boolean;
  affected_assets_legacy?: Asset[];
  evidence?: Evidence[];
  mitre_technique_ids?: string[];
  recommended_actions?: string[];
  created_at: string;
  updated_at: string;
}

// ── Actions ───────────────────────────────────────────────────────────────────

export interface PlannedAction {
  id: string;
  sequence: number;
  description: string;
  reasoning: string;
  tool_action_id: string;
  aws_service: string;
  aws_api_call: string;
  api_params: Record<string, unknown>;
  blast_radius: BlastRadius;
  urgency: string;
  confidence: number;
  rollback_spec?: {
    aws_service: string;
    aws_api_call: string;
    description: string;
  };
}

export interface RemediationAction {
  id: string;
  incident_id: string;
  tenant_id: string;
  action_type: string;
  status: RemediationStatus;
  severity_level: SeverityLevel;
  approver_id?: string;
  rejection_reason?: string;
  retry_count: number;
  execution_timestamp?: string;
  outcome?: string;
  affected_asset: Asset;
  created_at: string;
  updated_at: string;
}

// ── Approval ──────────────────────────────────────────────────────────────────

export interface ApprovalRequest {
  id: string;
  tenant_id: string;
  incident_id: string;
  action_plan_id: string;
  actions: PlannedAction[];
  ai_explanation: string;
  ai_reasoning_trace: string;
  threat_assessment: {
    threat_type: string;
    severity: SeverityLevel;
    confidence: number;
    mitre_techniques: MitreTechnique[];
    affected_assets: string[];
    predictions: ThreatPrediction;
  };
  status: string;
  decision_by?: string;
  rejection_reason?: string;
  created_at: string;
  expires_at: string;
  decided_at?: string;
}

// ── Rollback ──────────────────────────────────────────────────────────────────

export interface RollbackEntry {
  id: string;
  action_description: string;
  blast_radius: BlastRadius;
  status: 'AVAILABLE' | 'EXECUTED' | 'EXPIRED';
  registered_at: string;
  expires_at: string;
  rollback_description: string;
}

// ── Trust Level ───────────────────────────────────────────────────────────────

export interface TrustLevelInfo {
  tenant_id: string;
  trust_level: 1 | 2 | 3;
  trust_level_description: string;
  approval_rate_30d: number;
  total_actions_30d: number;
  approved_actions_30d: number;
  path_to_level_2?: {
    required_approval_rate: number;
    required_days: number;
    current_days: number;
    days_remaining: number;
  };
  manually_overridden: boolean;
  last_level_change: string;
  last_level_change_reason: string;
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

export interface PipelineStatus {
  status: string;
  components: Record<string, string>;
  ai_model: string;
  bedrock_region: string;
  bedrock_connected: boolean;
  timestamp: string;
}

// ── Timeline ──────────────────────────────────────────────────────────────────

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'detection' | 'correlation' | 'enrichment' | 'approval' | 'remediation' | 'escalation';
  title: string;
  description: string;
  actor?: string;
}

// ── Metrics ───────────────────────────────────────────────────────────────────

export interface KpiMetric {
  label: string;
  value: number;
  unit: string;
  trend: 'up' | 'down' | 'stable';
  trendValue: number;
}

export interface ChartDataPoint {
  date: string;
  value: number;
}

export interface ExecutiveMetrics {
  riskScore: number;
  mttd: KpiMetric;
  mttr: KpiMetric;
  falsePositiveRate: KpiMetric;
  autonomousResolutionRate: KpiMetric;
  trendData: {
    mttd: ChartDataPoint[];
    mttr: ChartDataPoint[];
    falsePositiveRate: ChartDataPoint[];
    autonomousResolution: ChartDataPoint[];
  };
  topThreats: {
    techniqueId: string;
    techniqueName: string;
    count: number;
    severity: SeverityLevel;
  }[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Gets the effective severity from either new or legacy incident format */
export function getIncidentSeverity(incident: Incident): SeverityLevel {
  return incident.severity ?? incident.severity_level ?? SeverityLevel.MEDIUM;
}

/** Gets the effective confidence from either new or legacy incident format */
export function getIncidentConfidence(incident: Incident): number {
  return incident.confidence ?? incident.confidence_score ?? 50;
}

/** Gets the effective description from either new or legacy incident format */
export function getIncidentDescription(incident: Incident): string {
  return incident.explanation ?? incident.description ?? incident.threat_type ?? 'Security incident detected';
}

/** Gets MITRE technique IDs from either new or legacy incident format */
export function getMitreTechniqueIds(incident: Incident): string[] {
  if (incident.mitre_techniques && incident.mitre_techniques.length > 0) {
    return incident.mitre_techniques.map(t => t.technique_id);
  }
  return incident.mitre_technique_ids ?? [];
}
