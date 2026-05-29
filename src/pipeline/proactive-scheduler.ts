/**
 * Proactive Hunt Scheduler (Task 20)
 *
 * Runs autonomous threat hunting cycles for each tenant at least once per 24h.
 * No analyst initiation required — the AI proactively looks for hidden threats.
 */

import { ContextAssembler } from '../ai/context-assembler.js';
import { ReasoningEngine } from '../ai/reasoning-engine.js';
import { SafetyGate } from '../safety/safety-gate.js';
import { TrustLevelService } from '../safety/trust-level.js';
import { ActionExecutor } from '../execution/action-executor.js';
import { InMemoryIncidentStore } from './incident-engine.js';
import { InMemoryApprovalWorkflow } from './approval-workflow.js';
import { AuditEventType, SafetyDecision } from '../types/index.js';
import type { AuditLogWriter } from '../execution/action-executor.js';

export interface TenantRegistry {
  getActiveTenants(): Promise<Array<{ tenantId: string; accountId: string }>>;
}

export class ProactiveHuntScheduler {
  private readonly contextAssembler: ContextAssembler;
  private readonly reasoningEngine: ReasoningEngine;
  private readonly safetyGate: SafetyGate;
  private readonly trustLevelService: TrustLevelService;
  private readonly actionExecutor: ActionExecutor;
  private readonly incidentStore: InMemoryIncidentStore;
  private readonly approvalWorkflow: InMemoryApprovalWorkflow;
  private readonly auditLog: AuditLogWriter;
  private readonly tenantRegistry: TenantRegistry;

  /** Track last hunt time per tenant to enforce 24h minimum. */
  private readonly lastHuntTime = new Map<string, number>();

  constructor(deps: {
    contextAssembler: ContextAssembler;
    reasoningEngine: ReasoningEngine;
    safetyGate: SafetyGate;
    trustLevelService: TrustLevelService;
    actionExecutor: ActionExecutor;
    incidentStore: InMemoryIncidentStore;
    approvalWorkflow: InMemoryApprovalWorkflow;
    auditLog: AuditLogWriter;
    tenantRegistry: TenantRegistry;
  }) {
    this.contextAssembler = deps.contextAssembler;
    this.reasoningEngine = deps.reasoningEngine;
    this.safetyGate = deps.safetyGate;
    this.trustLevelService = deps.trustLevelService;
    this.actionExecutor = deps.actionExecutor;
    this.incidentStore = deps.incidentStore;
    this.approvalWorkflow = deps.approvalWorkflow;
    this.auditLog = deps.auditLog;
    this.tenantRegistry = deps.tenantRegistry;
  }

  /**
   * Runs a proactive hunt for a single tenant.
   * Returns the number of threats found.
   */
  async runHuntForTenant(tenantId: string, accountId: string): Promise<number> {
    const now = Date.now();
    const lastHunt = this.lastHuntTime.get(tenantId) ?? 0;
    const hoursSinceLastHunt = (now - lastHunt) / (1000 * 60 * 60);

    if (hoursSinceLastHunt < 24) {
      return 0; // Too soon
    }

    this.lastHuntTime.set(tenantId, now);

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.AI_PROACTIVE_HUNT,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: 'proactive-scheduler' },
      action_taken: 'Proactive threat hunt cycle started',
      outcome: 'PENDING',
      metadata: { account_id: accountId },
    });

    const request = await this.contextAssembler.assembleProactive(tenantId, accountId);
    const response = await this.reasoningEngine.reason(request);

    let threatsFound = 0;

    if (response.is_threat && response.assessment) {
      threatsFound++;

      const incident = await this.incidentStore.createFromReasoning(
        tenantId, accountId,
        // Proactive hunts don't have a triggering event — use a synthetic one
        {
          id: `proactive-${Date.now()}`,
          tenant_id: tenantId,
          connector_id: 'proactive-hunt',
          account_id: accountId,
          region: 'us-east-1',
          source: 'CLOUDTRAIL' as any,
          attack_surface: response.assessment.mitre_techniques[0]
            ? 'CLOUD_IAM' as any
            : 'CLOUD_IAM' as any,
          event_type: 'proactive:hunt',
          actor: { type: 'UNKNOWN', identifier: 'unknown' },
          target: {
            resource_type: 'Unknown',
            resource_id: response.assessment.affected_assets[0] ?? 'unknown',
            attack_surface: 'CLOUD_IAM' as any,
          },
          raw_payload: {},
          ingestion_timestamp: new Date().toISOString(),
        },
        response
      );

      if (response.action_plan && response.action_plan.actions.length > 0) {
        const trustRecord = await this.trustLevelService.getOrCreate(tenantId);
        const planValidation = await this.safetyGate.validatePlan(
          response.action_plan,
          trustRecord.trust_level,
          request.tool_capabilities,
          request.tenant_config
        );

        const approvedIds = new Set(
          planValidation.action_results
            .filter((r) => r.decision === SafetyDecision.APPROVED)
            .map((r) => r.action_id)
        );

        const humanReviewActions = response.action_plan.actions.filter((a) =>
          planValidation.action_results.find(
            (r) => r.action_id === a.id && r.decision === SafetyDecision.HUMAN_REVIEW
          )
        );

        if (approvedIds.size > 0) {
          await this.actionExecutor.executePlan(response.action_plan, tenantId, approvedIds);
        }

        if (humanReviewActions.length > 0) {
          await this.approvalWorkflow.createRequest(
            tenantId, incident.id, response.action_plan.id, humanReviewActions, response
          );
        }
      }
    }

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.AI_PROACTIVE_HUNT,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: 'proactive-scheduler' },
      action_taken: `Proactive hunt completed: ${threatsFound} threat(s) found`,
      outcome: 'SUCCESS',
      metadata: { threats_found: threatsFound, tokens_used: response.tokens_used },
    });

    return threatsFound;
  }

  /**
   * Runs proactive hunts for all active tenants.
   * Called by a scheduled job every hour — each tenant hunts at most once per 24h.
   */
  async runAllTenants(): Promise<Map<string, number>> {
    const tenants = await this.tenantRegistry.getActiveTenants();
    const results = new Map<string, number>();

    for (const { tenantId, accountId } of tenants) {
      try {
        const found = await this.runHuntForTenant(tenantId, accountId);
        results.set(tenantId, found);
      } catch {
        results.set(tenantId, -1); // -1 indicates error
      }
    }

    return results;
  }
}
