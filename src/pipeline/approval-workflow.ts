/**
 * Approval Workflow (Task 11)
 *
 * Manages the human-in-the-loop for actions that the Safety Gate
 * routes to HUMAN_REVIEW. Sends notifications, tracks decisions,
 * handles timeouts, and triggers execution on approval.
 */

import {
  ApprovalRequest,
  ApprovalStatus,
  PlannedAction,
  ReasoningResponse,
  AuditEventType,
} from '../types/index.js';

import type { AuditLogWriter } from '../execution/action-executor.js';

// ============================================================================
// Interfaces
// ============================================================================

export interface ApprovalWorkflow {
  createRequest(
    tenantId: string,
    incidentId: string,
    actionPlanId: string,
    actions: PlannedAction[],
    response: ReasoningResponse
  ): Promise<ApprovalRequest>;

  approve(requestId: string, tenantId: string, approvedBy: string): Promise<ApprovalRequest>;
  reject(requestId: string, tenantId: string, rejectedBy: string, reason: string): Promise<ApprovalRequest>;
  getById(requestId: string, tenantId: string): Promise<ApprovalRequest | null>;
  getPendingByTenant(tenantId: string): Promise<ApprovalRequest[]>;
  checkTimeouts(tenantId: string): Promise<string[]>;
}

export interface ApprovalNotifier {
  notify(request: ApprovalRequest, channels: string[]): Promise<void>;
}

// ============================================================================
// In-Memory Approval Workflow (prototype)
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

export class InMemoryApprovalWorkflow implements ApprovalWorkflow {
  private readonly requests = new Map<string, ApprovalRequest>();
  private readonly auditLog: AuditLogWriter;
  private readonly notifier: ApprovalNotifier;
  private readonly timeoutHours: number;

  constructor(
    auditLog: AuditLogWriter,
    notifier: ApprovalNotifier,
    timeoutHours = 4
  ) {
    this.auditLog = auditLog;
    this.notifier = notifier;
    this.timeoutHours = timeoutHours;
  }

  async createRequest(
    tenantId: string,
    incidentId: string,
    actionPlanId: string,
    actions: PlannedAction[],
    response: ReasoningResponse
  ): Promise<ApprovalRequest> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.timeoutHours * 60 * 60 * 1000);

    const request: ApprovalRequest = {
      id: generateId(),
      tenant_id: tenantId,
      incident_id: incidentId,
      action_plan_id: actionPlanId,
      actions,
      ai_explanation: response.explanation,
      ai_reasoning_trace: response.reasoning_trace,
      threat_assessment: response.assessment!,
      status: ApprovalStatus.PENDING,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    this.requests.set(`${tenantId}:${request.id}`, request);

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.APPROVAL_REQUESTED,
      timestamp: now.toISOString(),
      actor: { type: 'AI', id: 'approval-workflow' },
      action_taken: `Approval requested for ${actions.length} action(s) on incident ${incidentId}`,
      outcome: 'PENDING',
      metadata: {
        request_id: request.id,
        incident_id: incidentId,
        action_count: actions.length,
        expires_at: expiresAt.toISOString(),
      },
    });

    // Send notification (fire and forget — don't block pipeline)
    this.notifier.notify(request, []).catch(() => {
      // Notification failure is non-fatal
    });

    return request;
  }

  async approve(
    requestId: string,
    tenantId: string,
    approvedBy: string
  ): Promise<ApprovalRequest> {
    const request = await this.getOrThrow(requestId, tenantId);
    this.assertPending(request);

    const updated: ApprovalRequest = {
      ...request,
      status: ApprovalStatus.APPROVED,
      decision_by: approvedBy,
      decided_at: new Date().toISOString(),
    };

    this.requests.set(`${tenantId}:${requestId}`, updated);

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.APPROVAL_GRANTED,
      timestamp: new Date().toISOString(),
      actor: { type: 'HUMAN', id: approvedBy },
      action_taken: `Approved ${request.actions.length} action(s) for incident ${request.incident_id}`,
      outcome: 'SUCCESS',
      metadata: { request_id: requestId, incident_id: request.incident_id },
    });

    return updated;
  }

  async reject(
    requestId: string,
    tenantId: string,
    rejectedBy: string,
    reason: string
  ): Promise<ApprovalRequest> {
    const request = await this.getOrThrow(requestId, tenantId);
    this.assertPending(request);

    const updated: ApprovalRequest = {
      ...request,
      status: ApprovalStatus.REJECTED,
      decision_by: rejectedBy,
      rejection_reason: reason,
      decided_at: new Date().toISOString(),
    };

    this.requests.set(`${tenantId}:${requestId}`, updated);

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.APPROVAL_REJECTED,
      timestamp: new Date().toISOString(),
      actor: { type: 'HUMAN', id: rejectedBy },
      action_taken: `Rejected actions for incident ${request.incident_id}: ${reason}`,
      outcome: 'REJECTED',
      metadata: { request_id: requestId, incident_id: request.incident_id, reason },
    });

    return updated;
  }

  async getById(requestId: string, tenantId: string): Promise<ApprovalRequest | null> {
    return this.requests.get(`${tenantId}:${requestId}`) ?? null;
  }

  async getPendingByTenant(tenantId: string): Promise<ApprovalRequest[]> {
    return [...this.requests.values()].filter(
      (r) => r.tenant_id === tenantId && r.status === ApprovalStatus.PENDING
    );
  }

  async checkTimeouts(tenantId: string): Promise<string[]> {
    const pending = await this.getPendingByTenant(tenantId);
    const now = new Date();
    const timedOut: string[] = [];

    for (const request of pending) {
      if (new Date(request.expires_at) < now) {
        const updated: ApprovalRequest = {
          ...request,
          status: ApprovalStatus.ESCALATED,
        };
        this.requests.set(`${tenantId}:${request.id}`, updated);
        timedOut.push(request.id);

        await this.auditLog.writeEntry({
          tenant_id: tenantId,
          event_type: AuditEventType.APPROVAL_TIMEOUT,
          timestamp: now.toISOString(),
          actor: { type: 'SYSTEM', id: 'approval-workflow' },
          action_taken: `Approval request timed out after ${this.timeoutHours}h for incident ${request.incident_id}`,
          outcome: 'FAILURE',
          metadata: { request_id: request.id, incident_id: request.incident_id },
        });
      }
    }

    return timedOut;
  }

  private async getOrThrow(requestId: string, tenantId: string): Promise<ApprovalRequest> {
    const request = this.requests.get(`${tenantId}:${requestId}`);
    if (!request) throw new Error(`Approval request '${requestId}' not found`);
    return request;
  }

  private assertPending(request: ApprovalRequest): void {
    if (request.status !== ApprovalStatus.PENDING) {
      throw new Error(`Approval request '${request.id}' is not pending (status: ${request.status})`);
    }
  }
}

// ============================================================================
// No-op Notifier (for testing / when no channels configured)
// ============================================================================

export class NoopApprovalNotifier implements ApprovalNotifier {
  async notify(_request: ApprovalRequest, _channels: string[]): Promise<void> {
    // No-op — real implementation sends Slack/email/PagerDuty
  }
}
