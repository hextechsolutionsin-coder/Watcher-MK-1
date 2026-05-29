/**
 * Action Executor
 *
 * Executes AI-generated action plans against real AWS infrastructure.
 * This is a dumb executor — it doesn't decide what to do, it just runs
 * the API calls the AI planned and the Safety Gate approved.
 *
 * Execution flow per action:
 *   1. Resolve connector credentials
 *   2. Execute the AWS API call
 *   3. Verify the action took effect
 *   4. Register rollback in the Rollback Registry
 *   5. Log to Audit Trail
 *   6. Report outcome back to caller
 *
 * On failure: retry once, then escalate.
 */

import {
  PlannedAction,
  ActionPlan,
  ExecutionRecord,
  ExecutionStatus,
  BlastRadius,
  ActionUrgency,
  AuditLogEntry,
  AuditEventType,
} from '../types/index.js';

import { RollbackRegistry } from './rollback-registry.js';

// ============================================================================
// AWS API Client Interface
// ============================================================================

/**
 * Interface for executing AWS API calls.
 * In production: uses AWS SDK v3 clients with assumed-role credentials.
 * In tests: mocked.
 */
export interface AwsApiClient {
  /**
   * Executes an AWS API call and returns the response.
   * @param service  AWS service name (e.g. 'iam', 'ec2', 's3')
   * @param apiCall  API method name (e.g. 'UpdateAccessKey')
   * @param params   API parameters
   * @param roleArn  IAM role to assume for this call
   */
  execute(
    service: string,
    apiCall: string,
    params: Record<string, unknown>,
    roleArn: string
  ): Promise<AwsApiResult>;
}

export interface AwsApiResult {
  success: boolean;
  requestId?: string;
  response?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
}

// ============================================================================
// Connector Credentials Interface
// ============================================================================

export interface ConnectorCredentials {
  getRoleArn(connectorId: string, tenantId: string): Promise<string | null>;
}

// ============================================================================
// Audit Log Writer Interface
// ============================================================================

export interface AuditLogWriter {
  writeEntry(entry: Partial<AuditLogEntry>): Promise<void>;
}

// ============================================================================
// Execution Record Store Interface
// ============================================================================

export interface ExecutionStore {
  save(record: ExecutionRecord): Promise<void>;
  update(id: string, tenantId: string, updates: Partial<ExecutionRecord>): Promise<void>;
  getById(id: string, tenantId: string): Promise<ExecutionRecord | null>;
  getByPlanId(planId: string, tenantId: string): Promise<ExecutionRecord[]>;
}

// ============================================================================
// Verification Strategies
// ============================================================================

/**
 * Verifies that an action took effect by querying the resource state.
 * Returns a description of the verified state, or null if verification
 * is not possible for this action type.
 */
export async function verifyAction(
  client: AwsApiClient,
  action: PlannedAction,
  roleArn: string
): Promise<string | null> {
  // Verification queries per action type
  const verifications: Record<string, { service: string; apiCall: string; params: (p: Record<string, unknown>) => Record<string, unknown>; extract: (r: Record<string, unknown>) => string }> = {
    'aws:iam:disable-access-key': {
      service: 'iam',
      apiCall: 'ListAccessKeys',
      params: (p) => ({ UserName: p['UserName'] }),
      extract: (r) => {
        const keys = (r['AccessKeyMetadata'] as Array<Record<string, unknown>>) ?? [];
        const key = keys.find((k) => k['AccessKeyId'] === action.api_params['AccessKeyId']);
        return key ? `Key status: ${key['Status']}` : 'Key not found';
      },
    },
    'aws:ec2:stop-instance': {
      service: 'ec2',
      apiCall: 'DescribeInstances',
      params: (p) => ({ InstanceIds: p['InstanceIds'] }),
      extract: (r) => {
        const reservations = (r['Reservations'] as Array<Record<string, unknown>>) ?? [];
        const instance = (reservations[0]?.['Instances'] as Array<Record<string, unknown>>)?.[0];
        const state = (instance?.['State'] as Record<string, unknown>)?.['Name'];
        return `Instance state: ${state ?? 'unknown'}`;
      },
    },
    'aws:s3:block-public-access': {
      service: 's3',
      apiCall: 'GetPublicAccessBlock',
      params: (p) => ({ Bucket: p['Bucket'] }),
      extract: (r) => {
        const config = r['PublicAccessBlockConfiguration'] as Record<string, unknown>;
        return config ? `Public access blocked: ${JSON.stringify(config)}` : 'Config not found';
      },
    },
  };

  const strategy = verifications[action.tool_action_id];
  if (!strategy) return null; // No verification strategy for this action

  try {
    const result = await client.execute(
      strategy.service,
      strategy.apiCall,
      strategy.params(action.api_params),
      roleArn
    );

    if (result.success && result.response) {
      return strategy.extract(result.response);
    }
    return `Verification query failed: ${result.errorMessage ?? 'unknown error'}`;
  } catch {
    return 'Verification query threw an exception';
  }
}

// ============================================================================
// Action Executor
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

export interface ActionExecutorConfig {
  /** Max retry attempts on failure. Default: 1. */
  maxRetries: number;
  /** Delay between retries in ms. Default: 2000. */
  retryDelayMs: number;
}

export const DEFAULT_EXECUTOR_CONFIG: ActionExecutorConfig = {
  maxRetries: 1,
  retryDelayMs: 2000,
};

/**
 * Executes approved AI action plans against AWS infrastructure.
 */
export class ActionExecutor {
  private readonly apiClient: AwsApiClient;
  private readonly credentials: ConnectorCredentials;
  private readonly rollbackRegistry: RollbackRegistry;
  private readonly auditLog: AuditLogWriter;
  private readonly executionStore: ExecutionStore;
  private readonly config: ActionExecutorConfig;

  constructor(
    apiClient: AwsApiClient,
    credentials: ConnectorCredentials,
    rollbackRegistry: RollbackRegistry,
    auditLog: AuditLogWriter,
    executionStore: ExecutionStore,
    config: Partial<ActionExecutorConfig> = {}
  ) {
    this.apiClient = apiClient;
    this.credentials = credentials;
    this.rollbackRegistry = rollbackRegistry;
    this.auditLog = auditLog;
    this.executionStore = executionStore;
    this.config = { ...DEFAULT_EXECUTOR_CONFIG, ...config };
  }

  /**
   * Executes all approved actions in a plan sequentially.
   * Returns execution records for each action.
   */
  async executePlan(
    plan: ActionPlan,
    tenantId: string,
    approvedActionIds: Set<string>
  ): Promise<PlanExecutionResult> {
    const records: ExecutionRecord[] = [];
    const skipped: string[] = [];

    for (const action of plan.actions.sort((a, b) => a.sequence - b.sequence)) {
      if (!approvedActionIds.has(action.id)) {
        skipped.push(action.id);
        continue;
      }

      const record = await this.executeAction(action, plan.id, tenantId);
      records.push(record);

      // If a non-read action fails after retries, stop the plan
      if (!record.success && action.blast_radius !== BlastRadius.NONE) {
        await this.auditLog.writeEntry({
          tenant_id: tenantId,
          event_type: AuditEventType.ACTION_FAILED,
          timestamp: new Date().toISOString(),
          actor: { type: 'AI', id: 'action-executor' },
          action_taken: `Plan execution halted after action '${action.description}' failed`,
          outcome: 'FAILURE',
          metadata: { plan_id: plan.id, failed_action_id: action.id, error: record.error_message },
        });
        break;
      }
    }

    const succeeded = records.filter((r) => r.success).length;
    const failed = records.filter((r) => !r.success).length;

    return {
      plan_id: plan.id,
      execution_records: records,
      skipped_action_ids: skipped,
      succeeded_count: succeeded,
      failed_count: failed,
      completed_at: new Date().toISOString(),
    };
  }

  /**
   * Executes a single action with retry logic.
   */
  async executeAction(
    action: PlannedAction,
    planId: string,
    tenantId: string
  ): Promise<ExecutionRecord> {
    const now = new Date().toISOString();
    const recordId = generateId();

    // Create initial record
    const record: ExecutionRecord = {
      id: recordId,
      tenant_id: tenantId,
      incident_id: planId, // plan_id used as incident_id for tracing
      action_plan_id: planId,
      planned_action: action,
      status: ExecutionStatus.EXECUTING,
      executed_at: now,
      success: false,
      outcome_description: 'Execution in progress',
      retry_count: 0,
      rollback_registered: false,
      created_at: now,
    };

    await this.executionStore.save(record);

    // Resolve connector credentials
    const roleArn = await this.credentials.getRoleArn(action.connector_id, tenantId);
    if (!roleArn) {
      return await this.failRecord(record, tenantId, `No credentials found for connector '${action.connector_id}'`);
    }

    // Execute with retry
    let lastError = '';
    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      if (attempt > 0) {
        record.retry_count = attempt;
        await this.sleep(this.config.retryDelayMs);
      }

      const result = await this.apiClient.execute(
        action.aws_service,
        action.aws_api_call,
        action.api_params,
        roleArn
      );

      if (result.success) {
        return await this.succeedRecord(record, tenantId, result, action, roleArn);
      }

      lastError = result.errorMessage ?? result.errorCode ?? 'Unknown error';
    }

    // All retries exhausted
    return await this.failRecord(record, tenantId, lastError);
  }

  /**
   * Executes a rollback for a previously executed action.
   */
  async executeRollback(
    rollbackId: string,
    tenantId: string,
    requestedBy: string
  ): Promise<ExecutionRecord> {
    const rollbackEntry = await this.rollbackRegistry.getForExecution(rollbackId, tenantId)
      ?? await this.rollbackRegistry['store'].getById(rollbackId, tenantId);

    if (!rollbackEntry) {
      throw new Error(`Rollback entry '${rollbackId}' not found`);
    }

    if (rollbackEntry.status !== 'AVAILABLE') {
      throw new Error(`Rollback '${rollbackId}' is not available (status: ${rollbackEntry.status})`);
    }

    const spec = rollbackEntry.rollback_spec;
    const now = new Date().toISOString();
    const recordId = generateId();

    // Find the original action's connector
    const originalRecord = await this.executionStore.getById(
      rollbackEntry.execution_record_id,
      tenantId
    );
    const connectorId = originalRecord?.planned_action.connector_id ?? 'unknown';
    const roleArn = await this.credentials.getRoleArn(connectorId, tenantId);

    if (!roleArn) {
      throw new Error(`No credentials found for connector '${connectorId}'`);
    }

    const rollbackRecord: ExecutionRecord = {
      id: recordId,
      tenant_id: tenantId,
      incident_id: rollbackEntry.execution_record_id,
      action_plan_id: rollbackEntry.execution_record_id,
      planned_action: {
        id: generateId(),
        sequence: 0,
        description: `ROLLBACK: ${rollbackEntry.action_description}`,
        reasoning: `Rollback requested by ${requestedBy}`,
        connector_id: connectorId,
        tool_action_id: `rollback:${rollbackEntry.action_id}`,
        aws_service: spec.aws_service,
        aws_api_call: spec.aws_api_call,
        api_params: spec.api_params,
        blast_radius: rollbackEntry.blast_radius,
        urgency: ActionUrgency.IMMEDIATE,
        confidence: 100,
      },
      status: ExecutionStatus.EXECUTING,
      executed_at: now,
      success: false,
      outcome_description: 'Rollback in progress',
      retry_count: 0,
      rollback_registered: false,
      created_at: now,
    };

    await this.executionStore.save(rollbackRecord);

    const result = await this.apiClient.execute(
      spec.aws_service,
      spec.aws_api_call,
      spec.api_params,
      roleArn
    );

    if (result.success) {
      await this.rollbackRegistry.markExecuted(rollbackEntry.id, tenantId, requestedBy);

      const completed: ExecutionRecord = {
        ...rollbackRecord,
        status: ExecutionStatus.ROLLED_BACK,
        completed_at: new Date().toISOString(),
        aws_request_id: result.requestId,
        success: true,
        outcome_description: `Rollback completed: ${spec.description}`,
      };

      await this.executionStore.update(recordId, tenantId, completed);

      await this.auditLog.writeEntry({
        tenant_id: tenantId,
        event_type: AuditEventType.ACTION_ROLLED_BACK,
        timestamp: new Date().toISOString(),
        actor: { type: requestedBy.startsWith('ai:') ? 'AI' : 'HUMAN', id: requestedBy },
        affected_resource: rollbackEntry.action_description,
        action_taken: `Rolled back: ${spec.description}`,
        outcome: 'SUCCESS',
        metadata: { rollback_id: rollbackEntry.id, original_execution_id: rollbackEntry.execution_record_id },
      });

      return completed;
    }

    const failed: ExecutionRecord = {
      ...rollbackRecord,
      status: ExecutionStatus.FAILED,
      completed_at: new Date().toISOString(),
      success: false,
      outcome_description: `Rollback failed: ${result.errorMessage ?? 'unknown error'}`,
      error_message: result.errorMessage,
    };

    await this.executionStore.update(recordId, tenantId, failed);
    return failed;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async succeedRecord(
    record: ExecutionRecord,
    tenantId: string,
    result: AwsApiResult,
    action: PlannedAction,
    roleArn: string
  ): Promise<ExecutionRecord> {
    // Verify the action took effect
    const verificationResult = await verifyAction(this.apiClient, action, roleArn);

    // Register rollback if action has a rollback spec
    let rollbackRegistered = false;
    if (action.rollback_spec && action.blast_radius !== BlastRadius.NONE) {
      try {
        await this.rollbackRegistry.register(tenantId, record.id, action);
        rollbackRegistered = true;
      } catch {
        // Rollback registration failure is non-fatal — log it but don't fail the action
      }
    }

    const completed: ExecutionRecord = {
      ...record,
      status: ExecutionStatus.COMPLETED,
      completed_at: new Date().toISOString(),
      aws_request_id: result.requestId,
      success: true,
      outcome_description: `Executed successfully: ${action.description}`,
      verification_result: verificationResult ?? undefined,
      rollback_registered: rollbackRegistered,
    };

    await this.executionStore.update(record.id, tenantId, completed);

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.ACTION_EXECUTED,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: 'action-executor' },
      affected_resource: action.api_params['InstanceIds']?.toString()
        ?? action.api_params['AccessKeyId']?.toString()
        ?? action.api_params['Bucket']?.toString()
        ?? 'unknown',
      action_taken: `${action.aws_service}:${action.aws_api_call} — ${action.description}`,
      outcome: 'SUCCESS',
      ai_explanation: action.reasoning,
      metadata: {
        action_id: action.id,
        tool_action_id: action.tool_action_id,
        blast_radius: action.blast_radius,
        rollback_registered: rollbackRegistered,
        verification: verificationResult,
        aws_request_id: result.requestId,
      },
    });

    return completed;
  }

  private async failRecord(
    record: ExecutionRecord,
    tenantId: string,
    errorMessage: string
  ): Promise<ExecutionRecord> {
    const failed: ExecutionRecord = {
      ...record,
      status: ExecutionStatus.FAILED,
      completed_at: new Date().toISOString(),
      success: false,
      outcome_description: `Execution failed: ${errorMessage}`,
      error_message: errorMessage,
    };

    await this.executionStore.update(record.id, tenantId, failed);

    await this.auditLog.writeEntry({
      tenant_id: tenantId,
      event_type: AuditEventType.ACTION_FAILED,
      timestamp: new Date().toISOString(),
      actor: { type: 'AI', id: 'action-executor' },
      action_taken: `Failed: ${record.planned_action.description}`,
      outcome: 'FAILURE',
      metadata: {
        action_id: record.planned_action.id,
        error: errorMessage,
        retry_count: record.retry_count,
      },
    });

    return failed;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ============================================================================
// Supporting Types
// ============================================================================

export interface PlanExecutionResult {
  plan_id: string;
  execution_records: ExecutionRecord[];
  skipped_action_ids: string[];
  succeeded_count: number;
  failed_count: number;
  completed_at: string;
}
