/**
 * Event Pipeline
 *
 * The central orchestrator that wires all components together.
 * This is the main processing loop for every security event.
 *
 * Flow:
 *   Raw AWS Event
 *     → Normalize (aws-normalizer)
 *     → Fast Filter (is this interesting?)
 *     → Context Assembly (environment + memory + tools)
 *     → AI Reasoning Engine (Bedrock Claude)
 *     → Incident Engine (create/update incident)
 *     → Safety Gate (validate action plan)
 *     → Route: APPROVED → Action Executor
 *               HUMAN_REVIEW → Approval Workflow
 *               REJECTED → Log and notify
 *     → Audit Log (everything)
 */

import { normalizeAwsEvent } from '../ingestion/aws-normalizer.js';
import { ContextAssembler } from '../ai/context-assembler.js';
import { ReasoningEngine } from '../ai/reasoning-engine.js';
import { SafetyGate } from '../safety/safety-gate.js';
import { TrustLevelService } from '../safety/trust-level.js';
import { ActionExecutor } from '../execution/action-executor.js';
import { RollbackRegistry } from '../execution/rollback-registry.js';

import {
  RawAwsEvent,
  NormalizedEvent,
  ReasoningResponse,
  Incident,
  IncidentStatus,
  IncidentSeverity,
  SafetyDecision,
  AuditEventType,
  ActionPlan,
} from '../types/index.js';

import type { AuditLogWriter } from '../execution/action-executor.js';
import type { IncidentStore } from './incident-engine.js';
import type { ApprovalWorkflow } from './approval-workflow.js';
import type { FastFilter } from './fast-filter.js';

// ============================================================================
// Pipeline Configuration
// ============================================================================

export interface PipelineConfig {
  /** Skip fast filter and process all events (useful for testing). */
  skipFastFilter: boolean;
  /** Max recent events to include in AI context. */
  maxRecentEvents: number;
}

export const DEFAULT_PIPELINE_CONFIG: PipelineConfig = {
  skipFastFilter: false,
  maxRecentEvents: 30,
};

// ============================================================================
// Pipeline Result
// ============================================================================

export interface PipelineResult {
  event_id: string;
  tenant_id: string;
  filtered_out: boolean;
  filter_reason?: string;
  reasoning_response?: ReasoningResponse;
  incident_id?: string;
  actions_approved: number;
  actions_human_review: number;
  actions_rejected: number;
  processing_ms: number;
}

// ============================================================================
// Event Pipeline
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

export class EventPipeline {
  private readonly contextAssembler: ContextAssembler;
  private readonly reasoningEngine: ReasoningEngine;
  private readonly safetyGate: SafetyGate;
  private readonly trustLevelService: TrustLevelService;
  private readonly actionExecutor: ActionExecutor;
  private readonly incidentStore: IncidentStore;
  private readonly approvalWorkflow: ApprovalWorkflow;
  private readonly auditLog: AuditLogWriter;
  private readonly fastFilter: FastFilter;
  private readonly config: PipelineConfig;

  constructor(deps: {
    contextAssembler: ContextAssembler;
    reasoningEngine: ReasoningEngine;
    safetyGate: SafetyGate;
    trustLevelService: TrustLevelService;
    actionExecutor: ActionExecutor;
    incidentStore: IncidentStore;
    approvalWorkflow: ApprovalWorkflow;
    auditLog: AuditLogWriter;
    fastFilter: FastFilter;
    config?: Partial<PipelineConfig>;
  }) {
    this.contextAssembler = deps.contextAssembler;
    this.reasoningEngine = deps.reasoningEngine;
    this.safetyGate = deps.safetyGate;
    this.trustLevelService = deps.trustLevelService;
    this.actionExecutor = deps.actionExecutor;
    this.incidentStore = deps.incidentStore;
    this.approvalWorkflow = deps.approvalWorkflow;
    this.auditLog = deps.auditLog;
    this.fastFilter = deps.fastFilter;
    this.config = { ...DEFAULT_PIPELINE_CONFIG, ...deps.config };
  }

  /**
   * Processes a raw AWS event through the full pipeline.
   * This is the main entry point called for every ingested event.
   */
  async processRawEvent(raw: RawAwsEvent): Promise<PipelineResult> {
    const start = Date.now();

    // Step 1: Normalize
    const event = normalizeAwsEvent(raw);

    return this.processNormalizedEvent(event, start);
  }

  /**
   * Processes an already-normalized event through the pipeline.
   * Used when events come from the webhook endpoint or other sources.
   */
  async processNormalizedEvent(
    event: NormalizedEvent,
    startTime?: number
  ): Promise<PipelineResult> {
    const start = startTime ?? Date.now();

    // Step 2: Fast Filter
    if (!this.config.skipFastFilter) {
      const filterResult = await this.fastFilter.evaluate(event);
      if (!filterResult.interesting) {
        await this.auditLog.writeEntry({
          tenant_id: event.tenant_id,
          event_type: AuditEventType.AI_REASONING_COMPLETED,
          timestamp: new Date().toISOString(),
          actor: { type: 'AI', id: 'fast-filter' },
          action_taken: `Event filtered out: ${filterResult.reason}`,
          outcome: 'SUCCESS',
          metadata: { event_id: event.id, filter_reason: filterResult.reason },
        });

        return {
          event_id: event.id,
          tenant_id: event.tenant_id,
          filtered_out: true,
          filter_reason: filterResult.reason,
          actions_approved: 0,
          actions_human_review: 0,
          actions_rejected: 0,
          processing_ms: Date.now() - start,
        };
      }
    }

    // Step 3: Assemble context for AI
    const request = await this.contextAssembler.assembleReactive(
      event.tenant_id,
      event.account_id,
      event
    );

    // Step 4: AI Reasoning
    const response = await this.reasoningEngine.reason(request);

    await this.auditLog.writeEntry({
      tenant_id: event.tenant_id,
      event_type: AuditEventType.AI_REASONING_COMPLETED,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: response.model_id },
      action_taken: response.is_threat
        ? `Threat detected: ${response.assessment?.threat_type}`
        : 'No threat detected',
      outcome: 'SUCCESS',
      reasoning_trace: response.reasoning_trace,
      ai_explanation: response.explanation,
      metadata: {
        event_id: event.id,
        is_threat: response.is_threat,
        severity: response.assessment?.severity,
        confidence: response.assessment?.confidence,
        tokens_used: response.tokens_used,
      },
    });

    // Step 5: If no threat, we're done
    if (!response.is_threat || !response.assessment) {
      return {
        event_id: event.id,
        tenant_id: event.tenant_id,
        filtered_out: false,
        reasoning_response: response,
        actions_approved: 0,
        actions_human_review: 0,
        actions_rejected: 0,
        processing_ms: Date.now() - start,
      };
    }

    // Step 6: Create Incident
    const incident = await this.incidentStore.createFromReasoning(
      event.tenant_id,
      event.account_id,
      event,
      response
    );

    await this.auditLog.writeEntry({
      tenant_id: event.tenant_id,
      event_type: AuditEventType.INCIDENT_CREATED,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: response.model_id },
      affected_resource: incident.affected_assets[0],
      action_taken: `Incident created: ${incident.threat_type}`,
      outcome: 'SUCCESS',
      metadata: { incident_id: incident.id, severity: incident.severity },
    });

    // Step 7: If no action plan, return advisory incident
    if (!response.action_plan || response.action_plan.actions.length === 0) {
      return {
        event_id: event.id,
        tenant_id: event.tenant_id,
        filtered_out: false,
        reasoning_response: response,
        incident_id: incident.id,
        actions_approved: 0,
        actions_human_review: 0,
        actions_rejected: 0,
        processing_ms: Date.now() - start,
      };
    }

    // Step 8: Safety Gate validation
    const trustRecord = await this.trustLevelService.getOrCreate(event.tenant_id);
    const toolProfiles = request.tool_capabilities;

    const planValidation = await this.safetyGate.validatePlan(
      response.action_plan,
      trustRecord.trust_level,
      toolProfiles,
      request.tenant_config
    );

    await this.auditLog.writeEntry({
      tenant_id: event.tenant_id,
      event_type: AuditEventType.AI_ACTION_PLANNED,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: response.model_id },
      action_taken: `Action plan validated: ${planValidation.approved_count} approved, ${planValidation.human_review_count} review, ${planValidation.rejected_count} rejected`,
      outcome: planValidation.has_rejections ? 'FAILURE' : 'SUCCESS',
      metadata: {
        incident_id: incident.id,
        plan_id: response.action_plan.id,
        approved: planValidation.approved_count,
        human_review: planValidation.human_review_count,
        rejected: planValidation.rejected_count,
      },
    });

    // Step 9: Route actions
    const approvedActionIds = new Set<string>();
    const humanReviewActionIds: string[] = [];

    for (const result of planValidation.action_results) {
      if (result.decision === SafetyDecision.APPROVED) {
        approvedActionIds.add(result.action_id);
      } else if (result.decision === SafetyDecision.HUMAN_REVIEW) {
        humanReviewActionIds.push(result.action_id);
      }
      // REJECTED actions are logged but not executed or queued
    }

    // Step 10: Execute approved actions
    if (approvedActionIds.size > 0) {
      await this.actionExecutor.executePlan(
        response.action_plan,
        event.tenant_id,
        approvedActionIds
      );
    }

    // Step 11: Queue human review actions
    if (humanReviewActionIds.length > 0) {
      const humanReviewActions = response.action_plan.actions.filter(
        (a) => humanReviewActionIds.includes(a.id)
      );

      await this.approvalWorkflow.createRequest(
        event.tenant_id,
        incident.id,
        response.action_plan.id,
        humanReviewActions,
        response
      );
    }

    return {
      event_id: event.id,
      tenant_id: event.tenant_id,
      filtered_out: false,
      reasoning_response: response,
      incident_id: incident.id,
      actions_approved: planValidation.approved_count,
      actions_human_review: planValidation.human_review_count,
      actions_rejected: planValidation.rejected_count,
      processing_ms: Date.now() - start,
    };
  }
}
