// ============================================================================
// WATCHER MK1 — Core Type Definitions
// AI-first autonomous cybersecurity reasoning agent
// ============================================================================

// ============================================================================
// Enums
// ============================================================================

/** AWS attack surfaces monitored by the platform. */
export enum AttackSurface {
  CLOUD_IAM = 'CLOUD_IAM',
  CLOUD_COMPUTE = 'CLOUD_COMPUTE',
  CLOUD_STORAGE = 'CLOUD_STORAGE',
  CLOUD_NETWORK = 'CLOUD_NETWORK',
  CLOUD_SERVERLESS = 'CLOUD_SERVERLESS',
  CLOUD_DATABASE = 'CLOUD_DATABASE',
  CLOUD_CONTAINER = 'CLOUD_CONTAINER',
  CLOUD_CICD = 'CLOUD_CICD',
}

/** AWS data source types for telemetry ingestion. */
export enum AwsDataSource {
  CLOUDTRAIL = 'CLOUDTRAIL',
  GUARDDUTY = 'GUARDDUTY',
  SECURITY_HUB = 'SECURITY_HUB',
  CONFIG = 'CONFIG',
  VPC_FLOW_LOGS = 'VPC_FLOW_LOGS',
  IAM_ACCESS_ANALYZER = 'IAM_ACCESS_ANALYZER',
  S3_ACCESS_LOGS = 'S3_ACCESS_LOGS',
  CLOUDWATCH = 'CLOUDWATCH',
}

/** Severity levels for incidents and threats. */
export enum IncidentSeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFORMATIONAL = 'INFORMATIONAL',
}

/** Lifecycle status of an incident. */
export enum IncidentStatus {
  OPEN = 'OPEN',
  IN_PROGRESS = 'IN_PROGRESS',
  RESOLVED = 'RESOLVED',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
}

/** Blast radius of an AI-planned action — how much damage if wrong. */
export enum BlastRadius {
  NONE = 'NONE',       // Read-only, no side effects
  LOW = 'LOW',         // Single resource write, easily reversible
  MEDIUM = 'MEDIUM',   // Multi-resource or service-affecting
  HIGH = 'HIGH',       // Environment-wide or potentially irreversible
}

/** Urgency level for AI-planned actions. */
export enum ActionUrgency {
  IMMEDIATE = 'IMMEDIATE', // Execute as fast as possible
  QUEUE = 'QUEUE',         // Execute within 60 seconds
  ADVISORY = 'ADVISORY',   // No execution — inform human only
}

/** AI reasoning mode. */
export enum ReasoningMode {
  REACTIVE = 'REACTIVE',         // Triggered by incoming event
  PROACTIVE = 'PROACTIVE',       // Scheduled threat hunting
  PREDICTIVE = 'PREDICTIVE',     // Forecasting future attack paths
  INVESTIGATIVE = 'INVESTIGATIVE', // Deep-dive on analyst request
}

/** Safety gate routing decision. */
export enum SafetyDecision {
  APPROVED = 'APPROVED',           // Auto-execute
  HUMAN_REVIEW = 'HUMAN_REVIEW',   // Route to approval queue
  REJECTED = 'REJECTED',           // Block — policy violation
}

/** Approval status for human-in-the-loop actions. */
export enum ApprovalStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  ESCALATED = 'ESCALATED',
  TIMEOUT = 'TIMEOUT',
}

/** Execution status of an action. */
export enum ExecutionStatus {
  PENDING = 'PENDING',
  EXECUTING = 'EXECUTING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  RETRYING = 'RETRYING',
  ROLLED_BACK = 'ROLLED_BACK',
}

/** Trust level — determines AI autonomy for a tenant. */
export enum TrustLevel {
  ONE = 1,   // New tenant — all writes require human approval
  TWO = 2,   // Low blast radius auto-approved
  THREE = 3, // Low + medium blast radius auto-approved
}

/** Audit event types. */
export enum AuditEventType {
  // AI reasoning
  AI_REASONING_COMPLETED = 'AI_REASONING_COMPLETED',
  AI_ACTION_PLANNED = 'AI_ACTION_PLANNED',
  AI_PROACTIVE_HUNT = 'AI_PROACTIVE_HUNT',
  AI_FORECAST_GENERATED = 'AI_FORECAST_GENERATED',
  // Safety gate
  SAFETY_GATE_APPROVED = 'SAFETY_GATE_APPROVED',
  SAFETY_GATE_HUMAN_REVIEW = 'SAFETY_GATE_HUMAN_REVIEW',
  SAFETY_GATE_REJECTED = 'SAFETY_GATE_REJECTED',
  // Approvals
  APPROVAL_REQUESTED = 'APPROVAL_REQUESTED',
  APPROVAL_GRANTED = 'APPROVAL_GRANTED',
  APPROVAL_REJECTED = 'APPROVAL_REJECTED',
  APPROVAL_TIMEOUT = 'APPROVAL_TIMEOUT',
  APPROVAL_ESCALATED = 'APPROVAL_ESCALATED',
  // Execution
  ACTION_EXECUTED = 'ACTION_EXECUTED',
  ACTION_FAILED = 'ACTION_FAILED',
  ACTION_ROLLED_BACK = 'ACTION_ROLLED_BACK',
  // Incidents
  INCIDENT_CREATED = 'INCIDENT_CREATED',
  INCIDENT_UPDATED = 'INCIDENT_UPDATED',
  INCIDENT_RESOLVED = 'INCIDENT_RESOLVED',
  // Connectors
  CONNECTOR_REGISTERED = 'CONNECTOR_REGISTERED',
  CONNECTOR_FAILED = 'CONNECTOR_FAILED',
  CONNECTOR_CREDENTIAL_EXPIRED = 'CONNECTOR_CREDENTIAL_EXPIRED',
  TELEMETRY_GAP_DETECTED = 'TELEMETRY_GAP_DETECTED',
  // Learning
  ANALYST_FEEDBACK_SUBMITTED = 'ANALYST_FEEDBACK_SUBMITTED',
  TRUST_LEVEL_CHANGED = 'TRUST_LEVEL_CHANGED',
  // Compliance
  AUDIT_MODIFICATION_ATTEMPTED = 'AUDIT_MODIFICATION_ATTEMPTED',
  DATA_DELETION_COMPLETED = 'DATA_DELETION_COMPLETED',
}

// ============================================================================
// Telemetry & Ingestion
// ============================================================================

/** Raw event received from an AWS data source before normalization. */
export interface RawAwsEvent {
  source: AwsDataSource;
  connector_id: string;
  tenant_id: string;
  account_id: string;
  region: string;
  raw_payload: Record<string, unknown>;
  received_at: string;
}

/** Normalized event — canonical schema after parsing raw AWS events. */
export interface NormalizedEvent {
  id: string;
  tenant_id: string;
  connector_id: string;
  account_id: string;
  region: string;
  source: AwsDataSource;
  attack_surface: AttackSurface;
  event_type: string;          // e.g. "ConsoleLogin", "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
  actor: EventActor;
  target: EventTarget;
  source_ip?: string;
  user_agent?: string;
  raw_payload: Record<string, unknown>;
  ingestion_timestamp: string;
}

/** Who performed the action in a normalized event. */
export interface EventActor {
  type: 'IAM_USER' | 'IAM_ROLE' | 'AWS_SERVICE' | 'FEDERATED_USER' | 'UNKNOWN';
  identifier: string;          // ARN, username, or service name
  account_id?: string;
  session_context?: string;
}

/** What resource was targeted in a normalized event. */
export interface EventTarget {
  resource_type: string;       // e.g. "AWS::IAM::AccessKey", "AWS::S3::Bucket"
  resource_id: string;         // ARN or resource identifier
  resource_name?: string;
  attack_surface: AttackSurface;
}

// ============================================================================
// Tool Discovery
// ============================================================================

/** Auto-discovered capability profile for a connected tool/connector. */
export interface ToolCapabilityProfile {
  connector_id: string;
  tenant_id: string;
  tool_type: 'AWS';
  account_id: string;
  region: string;
  readable_sources: AwsDataSource[];
  writable_actions: ToolAction[];
  discovered_at: string;
  last_updated: string;
}

/** A specific action the AI can take via a connected tool. */
export interface ToolAction {
  action_id: string;           // e.g. "aws:iam:disable-access-key"
  description: string;         // Human-readable: "Disable an IAM access key"
  aws_service: string;         // e.g. "iam", "ec2", "s3"
  aws_api_call: string;        // e.g. "UpdateAccessKey"
  required_params: string[];   // Parameter names required
  blast_radius: BlastRadius;
  reversible: boolean;
  rollback_api_call?: string;  // API call to undo this action
}

// ============================================================================
// Environment Model
// ============================================================================

/** A single asset in the customer's AWS environment. */
export interface EnvironmentAsset {
  id: string;                  // Internal ID
  tenant_id: string;
  account_id: string;
  region: string;
  resource_type: string;       // e.g. "AWS::IAM::User", "AWS::EC2::Instance"
  resource_id: string;         // ARN
  resource_name?: string;
  attack_surface: AttackSurface;
  criticality: number;         // 1–10, 10 = most critical
  tags: Record<string, string>;
  is_public_facing: boolean;
  known_vulnerabilities: string[]; // CVE IDs
  last_seen: string;
  created_at: string;
}

/** A relationship between two assets (permission, network, data flow). */
export interface AssetRelationship {
  id: string;
  tenant_id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: 'IAM_PERMISSION' | 'NETWORK_REACHABLE' | 'DATA_FLOW' | 'TRUST_RELATIONSHIP';
  description: string;         // e.g. "role can s3:GetObject on bucket"
  is_overprivileged: boolean;
  created_at: string;
}

/** Behavioral baseline for an asset or user. */
export interface BehavioralBaseline {
  entity_id: string;           // resource ARN or user identifier
  entity_type: 'ASSET' | 'USER';
  tenant_id: string;
  typical_api_calls: string[];
  typical_source_ips: string[];
  typical_regions: string[];
  typical_active_hours_utc: number[]; // 0–23
  typical_data_volume_mb_per_day: number;
  lookback_days: number;
  established: boolean;        // false = cold start (< 30 days data)
  last_updated: string;
}

/** Snapshot of the tenant's environment for AI context assembly. */
export interface EnvironmentContext {
  tenant_id: string;
  account_id: string;
  total_assets: number;
  critical_assets: EnvironmentAsset[];
  recent_config_changes: string[];
  active_incidents_count: number;
  assembled_at: string;
}

// ============================================================================
// AI Reasoning Engine
// ============================================================================

/** Full context assembled for an AI reasoning request. */
export interface ReasoningRequest {
  id: string;
  tenant_id: string;
  mode: ReasoningMode;
  // What triggered this reasoning
  trigger_event?: NormalizedEvent;
  trigger_description?: string;  // For proactive/predictive modes
  // Context fed to the AI
  environment_context: EnvironmentContext;
  recent_events: NormalizedEvent[];
  relevant_memory: ReasoningMemoryEntry[];
  tool_capabilities: ToolCapabilityProfile[];
  tenant_config: TenantConfig;
  created_at: string;
}

/** Full output from the AI Reasoning Engine. */
export interface ReasoningResponse {
  id: string;
  request_id: string;
  tenant_id: string;
  mode: ReasoningMode;
  // Threat assessment
  is_threat: boolean;
  assessment?: ThreatAssessment;
  // Action plan (only present if is_threat = true and actions are warranted)
  action_plan?: ActionPlan;
  // Natural language explanation for humans
  explanation: string;
  // Full reasoning trace for audit
  reasoning_trace: string;
  // Token usage for cost tracking
  tokens_used: number;
  model_id: string;
  created_at: string;
}

/** AI's assessment of a detected threat. */
export interface ThreatAssessment {
  threat_type: string;           // e.g. "Credential Compromise", "Lateral Movement"
  threat_description: string;
  severity: IncidentSeverity;
  confidence: number;            // 0–100
  mitre_techniques: MitreTechnique[];
  affected_assets: string[];     // Resource ARNs
  kill_chain_stage?: string;     // e.g. "Initial Access", "Privilege Escalation"
  related_incident_ids: string[];
  predictions: ThreatPrediction;
}

/** MITRE ATT&CK technique mapping. */
export interface MitreTechnique {
  technique_id: string;          // e.g. "T1078.004"
  technique_name: string;        // e.g. "Valid Accounts: Cloud Accounts"
  tactic: string;                // e.g. "Initial Access"
}

/** AI's prediction of what happens next. */
export interface ThreatPrediction {
  next_likely_action: string;
  probability: number;           // 0–100
  recommended_preemption: string;
}

/** A complete action plan generated by the AI. */
export interface ActionPlan {
  id: string;
  incident_id: string;
  actions: PlannedAction[];
  overall_reasoning: string;
  created_at: string;
}

/** A single action within an AI-generated plan. */
export interface PlannedAction {
  id: string;
  sequence: number;              // Order of execution
  description: string;           // Human-readable: "Revoke compromised IAM access key"
  reasoning: string;             // Why this action is necessary
  // Execution details
  connector_id: string;
  tool_action_id: string;        // References ToolAction.action_id
  aws_service: string;
  aws_api_call: string;
  api_params: Record<string, unknown>;
  // Safety metadata
  blast_radius: BlastRadius;
  urgency: ActionUrgency;
  confidence: number;            // AI's confidence this action is correct
  // Rollback
  rollback_spec?: RollbackSpec;
}

/** Specification for undoing an executed action. */
export interface RollbackSpec {
  aws_service: string;
  aws_api_call: string;
  api_params: Record<string, unknown>;
  description: string;           // "Re-enable IAM access key AKIA..."
  expires_at?: string;           // When rollback is no longer possible
}

// ============================================================================
// Safety Gate
// ============================================================================

/** Result of Safety Gate validation for a planned action. */
export interface SafetyGateResult {
  action_id: string;
  decision: SafetyDecision;
  blast_radius: BlastRadius;
  trust_level: TrustLevel;
  confidence: number;
  reasons: string[];             // Why this decision was made
  evaluated_at: string;
}

// ============================================================================
// Approval Workflow
// ============================================================================

/** An approval request sent to a human for review. */
export interface ApprovalRequest {
  id: string;
  tenant_id: string;
  incident_id: string;
  action_plan_id: string;
  actions: PlannedAction[];
  // AI context for the approver
  ai_explanation: string;
  ai_reasoning_trace: string;
  threat_assessment: ThreatAssessment;
  // Workflow state
  status: ApprovalStatus;
  assigned_to?: string;
  decision_by?: string;
  rejection_reason?: string;
  // Timing
  created_at: string;
  expires_at: string;
  decided_at?: string;
}

// ============================================================================
// Action Execution
// ============================================================================

/** Record of an executed action and its outcome. */
export interface ExecutionRecord {
  id: string;
  tenant_id: string;
  incident_id: string;
  action_plan_id: string;
  planned_action: PlannedAction;
  status: ExecutionStatus;
  // Execution details
  executed_at?: string;
  completed_at?: string;
  aws_request_id?: string;
  // Outcome
  success: boolean;
  outcome_description: string;
  verification_result?: string;  // Result of post-execution verification query
  error_message?: string;
  retry_count: number;
  // Rollback
  rollback_registered: boolean;
  rolled_back_at?: string;
  created_at: string;
}

// ============================================================================
// Incidents
// ============================================================================

/** An incident record created when the AI identifies a threat. */
export interface Incident {
  id: string;
  tenant_id: string;
  account_id: string;
  // AI assessment
  severity: IncidentSeverity;
  confidence: number;
  threat_type: string;
  description: string;
  explanation: string;           // Natural language for humans
  mitre_techniques: MitreTechnique[];
  affected_assets: string[];     // Resource ARNs
  attack_surface: AttackSurface;
  kill_chain_stage?: string;
  predictions: ThreatPrediction;
  // Lifecycle
  status: IncidentStatus;
  reasoning_response_id: string; // Links to the AI reasoning that created this
  action_plan_id?: string;
  // Timing
  detection_timestamp: string;
  created_at: string;
  updated_at: string;
}

// ============================================================================
// Reasoning Memory
// ============================================================================

/** A memory entry — past incident + outcome + feedback stored per tenant. */
export interface ReasoningMemoryEntry {
  id: string;
  tenant_id: string;
  incident_id: string;
  // What happened
  threat_type: string;
  threat_description: string;
  affected_asset_types: string[];
  mitre_technique_ids: string[];
  // What the AI did
  actions_taken: string[];
  outcome: 'RESOLVED' | 'ESCALATED' | 'FALSE_POSITIVE' | 'ONGOING';
  // What the analyst said
  analyst_feedback?: AnalystFeedback;
  // Embedding for similarity search
  embedding_text: string;        // Text used to generate vector embedding
  created_at: string;
}

/** Analyst feedback on an AI decision. */
export interface AnalystFeedback {
  verdict: 'CORRECT' | 'INCORRECT' | 'FALSE_POSITIVE' | 'SEVERITY_WRONG' | 'ACTION_WRONG';
  notes?: string;
  submitted_by: string;
  submitted_at: string;
}

// ============================================================================
// Trust Level
// ============================================================================

/** Per-tenant trust level record. */
export interface TenantTrustRecord {
  tenant_id: string;
  trust_level: TrustLevel;
  approval_rate_30d: number;     // 0–100 percentage
  total_actions_30d: number;
  approved_actions_30d: number;
  last_level_change: string;
  last_level_change_reason: string;
  manually_overridden: boolean;
  updated_at: string;
}

// ============================================================================
// Tenant Configuration
// ============================================================================

/** Per-tenant configuration. */
export interface TenantConfig {
  tenant_id: string;
  // Trust and autonomy
  trust_level: TrustLevel;
  confidence_threshold_low: number;    // Min confidence for auto-approve low blast
  confidence_threshold_medium: number; // Min confidence for auto-approve medium blast
  // Approval workflow
  approval_timeout_hours: number;      // Default: 4
  approval_channels: NotificationChannel[];
  // AI behavior
  reasoning_sensitivity: 'LOW' | 'MEDIUM' | 'HIGH'; // How aggressively AI flags events
  // Intelligence sharing
  cross_tenant_opt_in: boolean;
  // Compliance
  gdpr_mode: boolean;
  data_retention_days: number;
  // AWS-specific
  aws_accounts: AwsAccountConfig[];
}

/** AWS account configuration for a tenant. */
export interface AwsAccountConfig {
  account_id: string;
  account_alias?: string;
  role_arn: string;              // Cross-account IAM role to assume
  regions: string[];
  is_primary: boolean;
}

/** Notification channel configuration. */
export interface NotificationChannel {
  type: 'SLACK' | 'EMAIL' | 'PAGERDUTY';
  config: Record<string, string>;
  for_blast_radius: BlastRadius[];  // Which blast radius levels use this channel
}

// ============================================================================
// Connectors
// ============================================================================

/** A registered AWS connector. */
export interface Connector {
  id: string;
  tenant_id: string;
  name: string;
  account_id: string;
  role_arn: string;
  regions: string[];
  data_sources: AwsDataSource[];
  status: 'ACTIVE' | 'INACTIVE' | 'FAILED' | 'CREDENTIAL_EXPIRED';
  last_ingestion_at: string | null;
  created_at: string;
}

// ============================================================================
// Audit Log
// ============================================================================

/** Immutable audit log entry. */
export interface AuditLogEntry {
  id: string;
  tenant_id: string;
  event_type: AuditEventType;
  timestamp: string;
  actor: AuditActor;
  affected_resource?: string;    // ARN or resource identifier
  action_taken: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'REJECTED' | 'PENDING';
  // For AI decisions — full reasoning trace
  reasoning_trace?: string;
  ai_explanation?: string;
  // Additional context
  metadata: Record<string, unknown>;
}

/** Who performed an auditable action. */
export interface AuditActor {
  type: 'AI' | 'HUMAN' | 'SYSTEM';
  id: string;                    // AI model ID, user ID, or "system"
  role?: string;
}

// ============================================================================
// Fast Filter
// ============================================================================

/** Result from the fast filter model. */
export interface FastFilterResult {
  event_id: string;
  interesting: boolean;
  urgency: 'IMMEDIATE' | 'QUEUE' | 'DROP';
  reason: string;
  confidence: number;
  evaluated_at: string;
}
