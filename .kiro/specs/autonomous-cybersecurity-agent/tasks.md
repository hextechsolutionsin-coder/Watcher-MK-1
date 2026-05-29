# Implementation Plan: Autonomous Cybersecurity Reasoning Agent

## Overview

This plan breaks the platform into incremental coding tasks organized by architectural layer. The approach is AI-first: we build the data pipeline, then the AI reasoning core, then the safety and execution layer, then the UI. Each phase produces a working increment that can be demonstrated and tested.

**Key principle:** No coded detection rules. No playbooks. The AI reasons about everything.

## Phase 1: Data Foundation

- [ ] 1. Define shared data models and TypeScript interfaces
  - Create `src/types/index.ts` with all interfaces: `TelemetryEvent`, `NormalizedEvent`, `Connector`, `ConnectorStatus`, `ToolCapabilityProfile`, `ToolCapability`, `EnvironmentAsset`, `AssetRelationship`, `EnvironmentModel`, `BehavioralBaseline`, `Incident`, `ActionPlan`, `PlannedAction`, `RollbackSpec`, `SafetyGateDecision`, `ExecutionOutcome`, `ReasoningRequest`, `ReasoningResponse`, `ThreatAssessment`, `ReasoningMemoryEntry`, `AnalystFeedback`, `TrustLevel`, `TenantConfig`, `AuditLogEntry`, `ApprovalRequest`, `ApprovalDecision`
  - Define enums: `BlastRadius` (none, low, medium, high), `ActionUrgency` (immediate, queue, advisory), `ReasoningMode` (reactive, proactive, predictive, investigative), `IncidentSeverity` (critical, high, medium, low, informational), `ApprovalStatus` (pending, approved, rejected, escalated, timeout), `ExecutionStatus` (pending, executing, completed, failed, rolled_back), `TrustLevelValue` (1, 2, 3)
  - _Requirements: 1.3, 2.2, 4.2, 5.2, 7.2, 9.3_

- [ ] 2. Implement Telemetry Normalizer
  - [ ] 2.1 Implement normalizer for AWS CloudTrail events
    - Parse CloudTrail JSON format into canonical `NormalizedEvent` schema
    - Extract: actor (userIdentity), action (eventName), target asset (resources), source IP, timestamp
    - Stamp with `tenant_id`, `connector_id`, `source_tool: "aws-cloudtrail"`, `ingestion_timestamp`
    - _Requirements: 1.3_

  - [ ] 2.2 Implement normalizer for AWS GuardDuty findings
    - Parse GuardDuty finding format into canonical schema
    - Extract: finding type, severity, affected resource, actor, evidence
    - _Requirements: 1.3_

  - [ ] 2.3 Implement normalizer for AWS Security Hub findings
    - Parse ASFF (AWS Security Finding Format) into canonical schema
    - _Requirements: 1.3_

  - [ ] 2.4 Implement generic webhook normalizer
    - Accept arbitrary JSON payloads via webhook endpoint
    - Map configurable fields to canonical schema
    - Validate authentication and payload structure; reject invalid with HTTP 4xx
    - _Requirements: 1.6_

- [ ] 3. Implement Connector Manager
  - [ ] 3.1 Implement connector registration and lifecycle
    - REST endpoints: POST /api/v1/connectors, DELETE /api/v1/connectors/{id}, GET /api/v1/connectors/{id}/status
    - On registration: validate credentials, test connectivity, begin ingestion within 5 minutes
    - Health monitoring: detect telemetry gaps ≥ 60 seconds, credential expiry within 5 minutes
    - _Requirements: 1.1, 1.2, 1.4, 1.5_

  - [ ] 3.2 Implement AWS connector (CloudTrail + GuardDuty + Security Hub + Config + IAM)
    - Authenticate via cross-account IAM role (AssumeRole)
    - Subscribe to CloudTrail events, GuardDuty findings, Security Hub findings
    - Provide authenticated API access for Action Executor to use for response actions
    - _Requirements: 1.1, 1.2_

- [ ] 4. Implement Tool Discovery Engine
  - [ ] 4.1 Implement AWS capability discovery
    - On AWS connector registration, inspect granted IAM permissions
    - Produce Tool Capability Profile: list of readable data sources and writable actions
    - Example: if role has `iam:UpdateAccessKey` permission → capability "can disable/enable IAM access keys"
    - _Requirements: 2.1, 2.2_

  - [ ] 4.2 Implement capability profile storage and retrieval
    - Store Tool Capability Profiles per connector in database
    - Provide API for AI Reasoning Engine to query: "What can I do for this tenant?"
    - Update profiles when connector permissions change (check every 10 minutes)
    - _Requirements: 2.3, 2.4_

  - [ ] 4.3 Implement capability gap detection
    - When AI generates an action requiring a capability not available, flag the gap
    - Store gap information for tenant recommendations
    - _Requirements: 2.5_

- [ ] 5. Implement Environment Model
  - [ ] 5.1 Implement asset discovery from AWS
    - Query AWS APIs (EC2, IAM, S3, RDS, Lambda, VPC) to discover all assets
    - Store assets with: type, identifier, region, tags, creation date
    - Schedule full refresh every 24 hours
    - _Requirements: 3.1, 3.2_

  - [ ] 5.2 Implement relationship mapping
    - Map: IAM role → resources it can access, Security Group → instances it protects, VPC → subnets → instances
    - Store as graph (adjacency list or graph DB)
    - Update incrementally from CloudTrail events (new resources, permission changes)
    - _Requirements: 3.1, 3.5_

  - [ ] 5.3 Implement behavioral baseline tracking
    - Track per-asset and per-user activity patterns over time
    - Store: typical API calls, typical source IPs, typical access times, typical data volumes
    - Require minimum 30 days of data before baseline is considered established
    - Update baselines within 24 hours of new activity
    - _Requirements: 3.3_

  - [ ] 5.4 Implement environment context assembly for AI
    - Given an event (asset + user + action), assemble relevant environment context:
      - Asset details and criticality
      - User's behavioral baseline
      - Asset's network neighborhood
      - Recent events for this asset/user (last 24 hours)
    - Return as structured context object for AI Reasoning Engine
    - _Requirements: 3.4_

## Phase 2: AI Reasoning Core

- [ ] 6. Implement Fast Filter Model
  - [ ] 6.1 Implement fast filter inference pipeline
    - Accept normalized events from ingestion pipeline
    - Run lightweight classification: interesting (true/false) + urgency (immediate/queue/drop)
    - Target latency: < 100ms per event
    - Route interesting events to AI Reasoning Engine queue
    - Drop non-interesting events (log for audit)
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ] 6.2 Implement filter training data collection
    - Collect labeled examples: events that became incidents (positive), events that didn't (negative)
    - Feed back from AI Reasoning Engine: events the filter dropped but proactive hunting found
    - _Requirements: 6.4, 6.5_

- [ ] 7. Implement AI Reasoning Engine
  - [ ] 7.1 Implement reasoning request assembly
    - Assemble full context for AI reasoning: event + environment context + recent events + reasoning memory + threat intel + tool capabilities + tenant config
    - Format as structured prompt for LLM
    - _Requirements: 4.1, 3.4_

  - [ ] 7.2 Implement core reasoning loop (reactive mode)
    - Send assembled context to LLM (OpenAI/Anthropic/local model)
    - Parse structured output: threat assessment + action plan
    - Validate output structure (all required fields present)
    - Create Incident record if threat identified
    - Route action plan to Safety Gate
    - _Requirements: 4.1, 4.2, 4.3, 5.1_

  - [ ] 7.3 Implement action plan generation with tool awareness
    - AI generates specific API calls based on Tool Capability Profiles
    - Each action includes: tool reference, API call details, parameters, rollback spec, blast radius, reasoning
    - Validate generated actions against available capabilities (reject impossible actions)
    - _Requirements: 5.1, 5.2, 5.3_

  - [ ] 7.4 Implement reasoning trace capture
    - Store full chain-of-thought reasoning for every AI decision
    - Include: input context summary, reasoning steps, conclusion, confidence factors
    - Make available for audit trail and UI display
    - _Requirements: 14.2, 14.5_

  - [ ] 7.5 Implement proactive reasoning mode (threat hunting)
    - Schedule daily per-tenant proactive reasoning cycles
    - AI reviews: recent telemetry patterns, environment model changes, new threat intel
    - Generates findings without a triggering event
    - _Requirements: 4.6, 4.7_

  - [ ] 7.6 Implement predictive reasoning mode (forecasting)
    - Triggered by: new threat intel, configuration changes, cross-tenant patterns
    - AI assesses: "Is this tenant vulnerable to technique X?"
    - Generates forecast reports with attack paths and mitigations
    - _Requirements: 4.8_

  - [ ] 7.7 Implement follow-up reasoning
    - After action execution, AI receives outcomes
    - Reasons about results: "Did the action work? What else needs to happen?"
    - Generates follow-up action plans if needed
    - _Requirements: 5.6_

## Phase 3: Safety and Execution

- [ ] 8. Implement Safety Gate
  - [ ] 8.1 Implement blast radius scoring
    - Classify each action: none (read-only), low (single-resource write), medium (multi-resource), high (environment-wide/irreversible)
    - Use action type + target scope to determine blast radius
    - _Requirements: 7.1, 7.2_

  - [ ] 8.2 Implement trust level evaluation
    - Load tenant's current trust level
    - Compare action's blast radius against trust level permissions
    - Trust 1: only none auto-approved. Trust 2: none + low. Trust 3: none + low + medium.
    - High blast radius: always requires human approval regardless of trust level
    - _Requirements: 7.3, 7.4, 7.5, 8.1, 8.2, 8.3_

  - [ ] 8.3 Implement confidence threshold check
    - Compare AI's confidence score against tenant-configured threshold for the action's blast radius
    - Lower confidence → more likely to route to human review
    - _Requirements: 7.5_

  - [ ] 8.4 Implement reversibility validation
    - Check that every write action has a valid rollback specification
    - Reject actions without rollback (except read-only)
    - _Requirements: 7.6_

  - [ ] 8.5 Implement rate limiting
    - Track actions per minute per tenant
    - Reject if exceeding configurable limit (default: 10 write actions/minute)
    - _Requirements: 7.7_

  - [ ] 8.6 Implement Safety Gate routing decision
    - Combine all checks into final decision: APPROVED / HUMAN_REVIEW / REJECTED
    - Log decision with full reasoning to Audit Log
    - Route accordingly
    - _Requirements: 7.1, 7.8_

- [ ] 9. Implement Trust Level Management
  - [ ] 9.1 Implement trust level tracking
    - Store per-tenant trust level (1, 2, or 3)
    - New tenants start at level 1
    - Track approval rate over rolling 30-day window
    - _Requirements: 8.1, 8.2, 8.5_

  - [ ] 9.2 Implement automatic trust level progression
    - After 30 days with >90% approval rate: promote to level 2
    - After 90 days with >95% approval rate: promote to level 3
    - If approval rate drops below 80%: demote by one level
    - _Requirements: 8.3, 8.4, 8.6_

  - [ ] 9.3 Implement manual trust level override
    - Admin API to set trust level directly
    - Log override in Audit Log
    - _Requirements: 8.7_

- [ ] 10. Implement Approval Workflow
  - [ ] 10.1 Implement approval request creation and notification
    - Create approval request with: AI reasoning, action plan, blast radius, confidence
    - Send notification to designated approver within 60 seconds
    - Support channels: Slack, email, PagerDuty
    - _Requirements: 13.1, 13.2_

  - [ ] 10.2 Implement approve/reject handling
    - On approve: route to Action Executor within 30 seconds
    - On reject: log rejection, feed back to Reasoning Memory
    - On timeout: escalate via all channels
    - _Requirements: 13.3, 13.4, 13.5_

- [ ] 11. Implement Action Executor
  - [ ] 11.1 Implement generic API call executor
    - Accept approved action plan (tool + API call + parameters)
    - Resolve connector credentials for the target tool
    - Execute the API call
    - Verify outcome (query resource state after modification)
    - _Requirements: 9.1, 9.2_

  - [ ] 11.2 Implement AWS-specific action execution
    - Execute AWS API calls (IAM, EC2, S3, Security Groups) using connector's assumed role
    - Verify: query resource state after action to confirm effect
    - Examples: UpdateAccessKey, StopInstances, RevokeSecurityGroupIngress, PutBucketPolicy
    - _Requirements: 9.1, 9.2_

  - [ ] 11.3 Implement rollback registry
    - Store rollback spec for every executed write action
    - Provide rollback trigger API (for analyst, AI, or automatic)
    - Execute rollback through Safety Gate (validate before undoing)
    - _Requirements: 9.3, 9.4, 9.6_

  - [ ] 11.4 Implement retry and escalation on failure
    - On execution failure: retry once within 30 seconds
    - On second failure: escalate to human, log both failures
    - _Requirements: 9.5_

  - [ ] 11.5 Implement execution outcome reporting
    - Report outcome to: Audit Log, AI Reasoning Engine (for follow-up reasoning), Incident record
    - Include: action taken, target, timestamp, success/failure, verification result
    - _Requirements: 9.2, 14.3_

## Phase 4: Memory and Intelligence

- [ ] 12. Implement Reasoning Memory
  - [ ] 12.1 Implement incident and outcome persistence
    - Store all Incidents, action plans, execution outcomes in per-tenant storage
    - Retain for lifetime of subscription
    - _Requirements: 10.1_

  - [ ] 12.2 Implement analyst feedback handler
    - Accept feedback: correct, incorrect, false_positive, severity_override, action_rejection
    - Store feedback linked to the incident and reasoning trace
    - Make available to AI within 24 hours (via RAG retrieval)
    - _Requirements: 10.2_

  - [ ] 12.3 Implement memory retrieval for AI context
    - Given a new event, retrieve relevant past incidents (similar asset, similar pattern, similar actor)
    - Use vector similarity search over reasoning traces
    - Return: past incidents, their outcomes, analyst feedback
    - _Requirements: 10.3, 10.4_

  - [ ] 12.4 Implement weekly summary generation
    - Generate per-tenant weekly report: incidents, actions, approval rate, FP rate, confidence trends
    - Deliver via configured notification channel
    - _Requirements: 10.5_

  - [ ] 12.5 Implement tenant data deletion
    - On subscription termination: delete all tenant data within 30 days
    - Provide deletion confirmation record
    - _Requirements: 10.6_

- [ ] 13. Implement Threat Intelligence Layer
  - [ ] 13.1 Implement MITRE ATT&CK knowledge base
    - Ingest full ATT&CK framework (tactics, techniques, procedures, mitigations)
    - Store as vector embeddings for RAG retrieval
    - Update when ATT&CK releases new versions
    - _Requirements: 11.1, 11.2_

  - [ ] 13.2 Implement CVE feed ingestion
    - Ingest from NVD API
    - Store: CVE ID, affected products (CPE), CVSS score, description, mitigations
    - Available to AI within 4 hours of publication
    - _Requirements: 11.1, 11.3_

  - [ ] 13.3 Implement IOC feed ingestion
    - Ingest from configured feeds (commercial + OSINT)
    - Store: indicator type, value, source feeds, first seen, last refreshed
    - Available to AI within 2 hours of ingestion
    - Expire after 90 days without refresh
    - _Requirements: 11.1, 11.3, 11.5, 11.6_

  - [ ] 13.4 Implement dark web monitoring integration
    - Ingest alerts from dark web monitoring service
    - Match against tenant domains, IP ranges, credential patterns
    - Generate high-severity incident within 30 minutes of match
    - _Requirements: 11.4_

  - [ ] 13.5 Implement intelligence deduplication
    - Composite key: indicator_type + normalized_value
    - Single record per unique indicator with provenance metadata
    - _Requirements: 11.5_

- [ ] 14. Implement Cross-Tenant Intelligence
  - [ ] 14.1 Implement anonymization pipeline
    - Strip: tenant_id, org_name, user_ids, asset_ids, internal IPs
    - Preserve: threat patterns, techniques, behavioral signatures
    - _Requirements: 12.1, 12.2_

  - [ ] 14.2 Implement shared intelligence pool
    - Store anonymized patterns from opted-in tenants
    - Make available to AI via RAG for opted-in tenants
    - Exclude opted-out tenants from both contributing and receiving
    - _Requirements: 12.3, 12.4_

  - [ ] 14.3 Implement opt-out enforcement
    - Respect tenant opt-out preference
    - Exclude from shared pool contributions and retrievals
    - _Requirements: 12.4_

## Phase 5: Audit and Compliance

- [ ] 15. Implement Audit Logger
  - [ ] 15.1 Implement immutable audit log
    - Write-once storage (Elasticsearch with lifecycle policy or append-only DB)
    - Record: every AI decision, every action, every approval, every feedback
    - Reject modification/deletion attempts; log the attempt itself
    - _Requirements: 14.1_

  - [ ] 15.2 Implement audit log query API
    - Search by: tenant, time range, event type, asset, actor
    - Return results within 5 seconds for queries ≤ 90 days
    - _Requirements: 14.6_

  - [ ] 15.3 Implement audit log export
    - Generate JSON and CSV exports
    - Available within 5 minutes of request
    - Retain entries minimum 12 months
    - _Requirements: 14.4_

- [ ] 16. Implement Multi-Tenant Isolation
  - [ ] 16.1 Implement tenant data isolation
    - Schema-per-tenant in PostgreSQL
    - Tenant-keyed partitions in all other stores
    - JWT-based tenant context propagation on all internal calls
    - _Requirements: 15.1_

  - [ ] 16.2 Implement RBAC
    - Roles: Administrator, Analyst, Approver, Read-Only
    - Enforce at API gateway and service level
    - Role changes effective within 60 seconds
    - _Requirements: 15.3, 15.5_

  - [ ] 16.3 Implement encryption
    - At rest: AES-256 for all tenant data
    - In transit: TLS 1.2+ for all connections
    - _Requirements: 15.2_

  - [ ] 16.4 Implement subscription termination and data deletion
    - Delete all tenant data within 30 days of termination
    - Cover: primary storage, backups, replicated copies
    - Provide deletion confirmation record
    - _Requirements: 15.4_

## Phase 6: Web Console

- [ ] 17. Implement SOC UI
  - [ ] 17.1 Implement AI activity feed
    - Real-time stream of AI reasoning outputs and actions
    - Show: threat description, severity, confidence, action taken, AI explanation
    - Update within 10 seconds of each AI decision
    - _Requirements: 17.1_

  - [ ] 17.2 Implement approval queue
    - List all actions awaiting human review
    - Show: AI reasoning, proposed plan, blast radius, confidence
    - One-click approve/reject with optional rejection reason
    - Reflect status update within 5 seconds of decision
    - _Requirements: 17.2_

  - [ ] 17.3 Implement incident detail view
    - Full context: AI reasoning trace, related events, environment context, action history
    - Natural language explanation of what happened and what was done
    - Kill chain visualization (if multi-stage attack detected)
    - Predictions: next likely attack stage
    - _Requirements: 17.3_

  - [ ] 17.4 Implement rollback UI
    - One-click rollback button for every executed action with valid rollback
    - Show: what will be undone, original state that will be restored
    - _Requirements: 17.4_

  - [ ] 17.5 Implement executive risk view
    - Administrator role only (HTTP 403 for others)
    - Business risk score (0–100)
    - KPIs: MTTD, MTTR, FP rate, autonomous resolution rate
    - Trend charts: 7/30/90 day rolling windows
    - _Requirements: 17.5_

  - [ ] 17.6 Implement trust level dashboard
    - Current trust level and what it means
    - Approval rate history
    - Path to next trust level (what needs to happen)
    - _Requirements: 17.6_

  - [ ] 17.7 Implement audit trail view
    - Searchable, filterable log of all AI decisions and actions
    - Export functionality (JSON, CSV)
    - _Requirements: 17.7_

  - [ ] 17.8 Implement session management
    - 30-minute inactivity timeout
    - Session invalidation and redirect to login
    - _Requirements: 17.8_

## Phase 7: Integration and End-to-End Testing

- [ ] 18. Wire end-to-end pipeline
  - [ ] 18.1 Wire ingestion → fast filter → AI reasoning → safety gate → execution
    - Connect all components via event bus and API calls
    - Verify full flow: raw event → AI reasoning → action plan → safety check → execution → audit log
    - _Requirements: All_

  - [ ] 18.2 Wire feedback loop
    - Analyst feedback → Reasoning Memory → improved AI reasoning on next similar event
    - Verify: AI references past feedback when reasoning about similar events
    - _Requirements: 10.2, 10.3, 10.4_

  - [ ] 18.3 Wire trust level progression
    - Simulate 30 days of approvals → verify trust level increases
    - Simulate rejections → verify trust level decreases
    - _Requirements: 8.2, 8.3, 8.4, 8.6_

  - [ ] 18.4 Wire proactive hunting cycle
    - Verify: daily proactive reasoning runs without triggering event
    - Verify: findings from proactive mode create incidents and action plans
    - _Requirements: 4.7_

- [ ] 19. Implement notification integrations
  - [ ] 19.1 Implement Slack notification
    - Send approval requests, incident alerts, escalations to configured Slack channel/DM
    - Include: AI explanation, action plan summary, approve/reject buttons (if Slack supports)
    - _Requirements: 13.1_

  - [ ] 19.2 Implement email notification
    - HTML email with: threat summary, AI reasoning, action plan, approve/reject links
    - _Requirements: 13.1_

  - [ ] 19.3 Implement PagerDuty integration
    - Create PagerDuty incident for escalations and high-severity threats
    - _Requirements: 13.1_

- [ ] 20. Final checkpoint — Full system validation
  - [ ] 20.1 End-to-end scenario: credential compromise detection and response
    - Simulate: anomalous IAM key usage → AI detects → generates revoke plan → safety approves → executes → verifies → logs
    - _Requirements: 4.1, 4.2, 5.1, 5.2, 7.1, 9.1, 9.2, 14.2, 14.3_

  - [ ] 20.2 End-to-end scenario: human-in-the-loop for high-blast action
    - Simulate: AI recommends stopping production instance → safety routes to human → human approves → executes → rollback available
    - _Requirements: 7.4, 8.1, 13.1, 13.2, 13.3, 9.6_

  - [ ] 20.3 End-to-end scenario: trust level progression
    - Simulate: 30 days of correct AI decisions → trust level increases → AI gains more autonomy
    - _Requirements: 8.2, 8.3, 8.4_

  - [ ] 20.4 End-to-end scenario: AI learns from rejection
    - Simulate: AI proposes action → human rejects → AI encounters similar event → AI adjusts (lower confidence or different plan)
    - _Requirements: 10.2, 10.4, 13.4_

  - [ ] 20.5 End-to-end scenario: rollback
    - Simulate: AI takes action → analyst clicks rollback → original state restored → logged
    - _Requirements: 9.3, 9.4, 9.6_
