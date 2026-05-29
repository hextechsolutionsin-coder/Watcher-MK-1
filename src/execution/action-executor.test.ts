import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ActionExecutor,
  AwsApiClient,
  AwsApiResult,
  ConnectorCredentials,
  AuditLogWriter,
  ExecutionStore,
  verifyAction,
} from './action-executor.js';
import { RollbackRegistry, RollbackStore, RollbackEntry } from './rollback-registry.js';
import {
  PlannedAction,
  ActionPlan,
  ExecutionRecord,
  ExecutionStatus,
  BlastRadius,
  ActionUrgency,
  AuditLogEntry,
} from '../types/index.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeAction(overrides?: Partial<PlannedAction>): PlannedAction {
  return {
    id: 'action-001',
    sequence: 1,
    description: 'Disable IAM access key',
    reasoning: 'Key used from anomalous IP',
    connector_id: 'conn-001',
    tool_action_id: 'aws:iam:disable-access-key',
    aws_service: 'iam',
    aws_api_call: 'UpdateAccessKey',
    api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Inactive' },
    blast_radius: BlastRadius.LOW,
    urgency: ActionUrgency.IMMEDIATE,
    confidence: 85,
    rollback_spec: {
      aws_service: 'iam',
      aws_api_call: 'UpdateAccessKey',
      api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Active' },
      description: 'Re-enable the access key',
    },
    ...overrides,
  };
}

function makePlan(actions: PlannedAction[]): ActionPlan {
  return {
    id: 'plan-001',
    incident_id: 'inc-001',
    actions,
    overall_reasoning: 'Contain the threat',
    created_at: new Date().toISOString(),
  };
}

function createMockApiClient(result: Partial<AwsApiResult> = {}): AwsApiClient {
  return {
    execute: vi.fn(async () => ({
      success: true,
      requestId: 'req-abc123',
      response: {},
      ...result,
    })),
  };
}

function createMockCredentials(roleArn: string | null = 'arn:aws:iam::123:role/WatcherRole'): ConnectorCredentials {
  return { getRoleArn: vi.fn(async () => roleArn) };
}

function createMockAuditLog(): AuditLogWriter & { entries: Partial<AuditLogEntry>[] } {
  const entries: Partial<AuditLogEntry>[] = [];
  return {
    entries,
    writeEntry: vi.fn(async (e) => { entries.push(e); }),
  };
}

function createMockExecutionStore(): ExecutionStore & { records: Map<string, ExecutionRecord> } {
  const records = new Map<string, ExecutionRecord>();
  return {
    records,
    async save(r) { records.set(`${r.tenant_id}:${r.id}`, r); },
    async update(id, tenantId, updates) {
      const key = `${tenantId}:${id}`;
      const existing = records.get(key);
      if (existing) records.set(key, { ...existing, ...updates });
    },
    async getById(id, tenantId) { return records.get(`${tenantId}:${id}`) ?? null; },
    async getByPlanId(planId, tenantId) {
      return [...records.values()].filter(r => r.tenant_id === tenantId && r.action_plan_id === planId);
    },
  };
}

function createMockRollbackStore(): RollbackStore & { entries: Map<string, RollbackEntry> } {
  const entries = new Map<string, RollbackEntry>();
  const byExecId = new Map<string, RollbackEntry>();
  return {
    entries,
    async save(e) {
      entries.set(`${e.tenant_id}:${e.id}`, e);
      byExecId.set(`${e.tenant_id}:${e.execution_record_id}`, e);
    },
    async getById(id, tid) { return entries.get(`${tid}:${id}`) ?? null; },
    async getByExecutionRecordId(eid, tid) { return byExecId.get(`${tid}:${eid}`) ?? null; },
    async getAvailableByTenant(tid) {
      return [...entries.values()].filter(e => e.tenant_id === tid && e.status === 'AVAILABLE');
    },
    async updateStatus(id, tid, status, executedAt, executedBy) {
      const key = `${tid}:${id}`;
      const e = entries.get(key);
      if (e) {
        const updated = { ...e, status, ...(executedAt && { executed_at: executedAt }), ...(executedBy && { executed_by: executedBy }) };
        entries.set(key, updated);
        byExecId.set(`${tid}:${e.execution_record_id}`, updated);
      }
    },
  };
}

function createExecutor(overrides?: {
  apiResult?: Partial<AwsApiResult>;
  roleArn?: string | null;
  retryDelayMs?: number;
}) {
  const roleArn = overrides !== undefined && 'roleArn' in overrides
    ? overrides.roleArn
    : 'arn:aws:iam::123:role/WatcherRole';
  const apiClient = createMockApiClient(overrides?.apiResult);
  const credentials = createMockCredentials(roleArn);
  const auditLog = createMockAuditLog();
  const executionStore = createMockExecutionStore();
  const rollbackStore = createMockRollbackStore();
  const rollbackRegistry = new RollbackRegistry(rollbackStore);

  const executor = new ActionExecutor(
    apiClient, credentials, rollbackRegistry, auditLog, executionStore,
    { maxRetries: 1, retryDelayMs: overrides?.retryDelayMs ?? 0 }
  );

  return { executor, apiClient, credentials, auditLog, executionStore, rollbackStore, rollbackRegistry };
}

// ── verifyAction ──────────────────────────────────────────────────────────────

describe('verifyAction', () => {
  it('verifies IAM key disable by querying ListAccessKeys', async () => {
    const action = makeAction({ tool_action_id: 'aws:iam:disable-access-key', api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Inactive', UserName: 'alice' } });
    const client = createMockApiClient({
      response: {
        AccessKeyMetadata: [{ AccessKeyId: 'AKIAEXAMPLE', Status: 'Inactive' }],
      },
    });

    const result = await verifyAction(client, action, 'arn:aws:iam::123:role/WatcherRole');
    expect(result).toContain('Inactive');
  });

  it('returns null for actions without a verification strategy', async () => {
    const action = makeAction({ tool_action_id: 'aws:guardduty:get-findings' });
    const client = createMockApiClient();

    const result = await verifyAction(client, action, 'arn:aws:iam::123:role/WatcherRole');
    expect(result).toBeNull();
  });

  it('returns error message when verification query fails', async () => {
    const action = makeAction({ tool_action_id: 'aws:iam:disable-access-key' });
    const client = createMockApiClient({ success: false, errorMessage: 'AccessDenied' });

    const result = await verifyAction(client, action, 'arn:aws:iam::123:role/WatcherRole');
    expect(result).toContain('Verification query failed');
  });
});

// ── ActionExecutor.executeAction ──────────────────────────────────────────────

describe('ActionExecutor.executeAction', () => {
  it('returns a COMPLETED record on success', async () => {
    const { executor } = createExecutor();
    const action = makeAction();

    const record = await executor.executeAction(action, 'plan-001', 'tenant-abc');

    expect(record.success).toBe(true);
    expect(record.status).toBe(ExecutionStatus.COMPLETED);
    expect(record.outcome_description).toContain('Executed successfully');
    expect(record.aws_request_id).toBe('req-abc123');
    expect(record.completed_at).toBeDefined();
  });

  it('registers a rollback on successful write action', async () => {
    const { executor, rollbackStore } = createExecutor();
    const action = makeAction({ blast_radius: BlastRadius.LOW });

    await executor.executeAction(action, 'plan-001', 'tenant-abc');

    expect(rollbackStore.entries.size).toBe(1);
    const entry = [...rollbackStore.entries.values()][0]!;
    expect(entry.status).toBe('AVAILABLE');
    expect(entry.rollback_spec).toEqual(action.rollback_spec);
  });

  it('does NOT register rollback for NONE blast radius actions', async () => {
    const { executor, rollbackStore } = createExecutor();
    const action = makeAction({ blast_radius: BlastRadius.NONE, rollback_spec: undefined });

    await executor.executeAction(action, 'plan-001', 'tenant-abc');

    expect(rollbackStore.entries.size).toBe(0);
  });

  it('writes an audit log entry on success', async () => {
    const { executor, auditLog } = createExecutor();
    await executor.executeAction(makeAction(), 'plan-001', 'tenant-abc');

    expect(auditLog.entries.length).toBeGreaterThan(0);
    const entry = auditLog.entries.find(e => e.event_type === 'ACTION_EXECUTED');
    expect(entry).toBeDefined();
    expect(entry!.outcome).toBe('SUCCESS');
    expect(entry!.ai_explanation).toBe('Key used from anomalous IP');
  });

  it('returns FAILED record when API call fails after retries', async () => {
    const { executor } = createExecutor({ apiResult: { success: false, errorMessage: 'AccessDenied' } });
    const action = makeAction();

    const record = await executor.executeAction(action, 'plan-001', 'tenant-abc');

    expect(record.success).toBe(false);
    expect(record.status).toBe(ExecutionStatus.FAILED);
    expect(record.error_message).toBe('AccessDenied');
    expect(record.retry_count).toBe(1); // retried once
  });

  it('writes an audit log entry on failure', async () => {
    const { executor, auditLog } = createExecutor({ apiResult: { success: false, errorMessage: 'Throttled' } });
    await executor.executeAction(makeAction(), 'plan-001', 'tenant-abc');

    const failEntry = auditLog.entries.find(e => e.event_type === 'ACTION_FAILED');
    expect(failEntry).toBeDefined();
    expect(failEntry!.outcome).toBe('FAILURE');
  });

  it('returns FAILED record when no credentials found', async () => {
    const { executor } = createExecutor({ roleArn: null });
    const record = await executor.executeAction(makeAction(), 'plan-001', 'tenant-abc');

    expect(record.success).toBe(false);
    expect(record.error_message).toContain('No credentials');
  });

  it('saves initial record to execution store before API call', async () => {
    const { executor, executionStore, apiClient } = createExecutor();

    // Intercept the API call to check store state mid-execution
    let storeSize = 0;
    (apiClient.execute as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      storeSize = executionStore.records.size;
      return { success: true, requestId: 'req-001', response: {} };
    });

    await executor.executeAction(makeAction(), 'plan-001', 'tenant-abc');

    expect(storeSize).toBe(1); // record was saved before API call
  });
});

// ── ActionExecutor.executePlan ────────────────────────────────────────────────

describe('ActionExecutor.executePlan', () => {
  it('executes all approved actions in sequence order', async () => {
    const { executor, apiClient } = createExecutor();
    const mainCallOrder: string[] = [];

    (apiClient.execute as ReturnType<typeof vi.fn>).mockImplementation(async (_s, apiCall) => {
      // Only track the main action calls (UpdateAccessKey, StopInstances)
      // Ignore verification calls (ListAccessKeys, DescribeInstances)
      if (apiCall === 'UpdateAccessKey' || apiCall === 'StopInstances') {
        mainCallOrder.push(apiCall as string);
      }
      return { success: true, requestId: 'req-001', response: {} };
    });

    const actions = [
      makeAction({ id: 'a1', sequence: 2, aws_api_call: 'StopInstances', tool_action_id: 'aws:ec2:stop-instance' }),
      makeAction({ id: 'a2', sequence: 1, aws_api_call: 'UpdateAccessKey', tool_action_id: 'aws:iam:disable-access-key' }),
    ];
    const plan = makePlan(actions);
    const approved = new Set(['a1', 'a2']);

    await executor.executePlan(plan, 'tenant-abc', approved);

    // Should execute in sequence order: 1 (UpdateAccessKey) then 2 (StopInstances)
    expect(mainCallOrder[0]).toBe('UpdateAccessKey');
    expect(mainCallOrder[1]).toBe('StopInstances');
  });

  it('skips actions not in the approved set', async () => {
    const { executor, apiClient } = createExecutor();
    // Use guardduty action — no verification strategy, so exactly 1 API call per action
    const actions = [
      makeAction({ id: 'a1', tool_action_id: 'aws:guardduty:get-findings', aws_service: 'guardduty', aws_api_call: 'GetFindings', blast_radius: BlastRadius.NONE, rollback_spec: undefined }),
      makeAction({ id: 'a2', sequence: 2, tool_action_id: 'aws:guardduty:list-findings', aws_service: 'guardduty', aws_api_call: 'ListFindings', blast_radius: BlastRadius.NONE, rollback_spec: undefined }),
    ];
    const plan = makePlan(actions);
    const approved = new Set(['a1']); // only a1 approved

    const result = await executor.executePlan(plan, 'tenant-abc', approved);

    expect(apiClient.execute).toHaveBeenCalledOnce();
    expect(result.skipped_action_ids).toContain('a2');
  });

  it('returns correct counts', async () => {
    const { executor } = createExecutor();
    const plan = makePlan([
      makeAction({ id: 'a1' }),
      makeAction({ id: 'a2', sequence: 2 }),
    ]);
    const approved = new Set(['a1', 'a2']);

    const result = await executor.executePlan(plan, 'tenant-abc', approved);

    expect(result.succeeded_count).toBe(2);
    expect(result.failed_count).toBe(0);
    expect(result.plan_id).toBe('plan-001');
  });

  it('halts plan execution after a write action fails', async () => {
    const { executor, executionStore } = createExecutor({
      apiResult: { success: false, errorMessage: 'AccessDenied' },
    });

    const plan = makePlan([
      makeAction({ id: 'a1', sequence: 1, blast_radius: BlastRadius.LOW }),
      makeAction({ id: 'a2', sequence: 2, blast_radius: BlastRadius.LOW }),
    ]);
    const approved = new Set(['a1', 'a2']);

    const result = await executor.executePlan(plan, 'tenant-abc', approved);

    // a1 fails → plan halts → a2 never executed
    expect(result.failed_count).toBe(1);
    expect(result.succeeded_count).toBe(0);
    // Only a1's execution record should exist (a2 was never started)
    const records = await executionStore.getByPlanId('plan-001', 'tenant-abc');
    expect(records).toHaveLength(1);
    expect(records[0]!.planned_action.id).toBe('a1');
  });

  it('does NOT halt plan after a NONE blast radius action fails', async () => {
    const { executor, apiClient } = createExecutor();
    let callCount = 0;

    (apiClient.execute as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      callCount++;
      if (callCount <= 2) return { success: false, errorMessage: 'NotFound' }; // a1 fails (2 attempts)
      return { success: true, requestId: 'req-001', response: {} }; // a2 succeeds
    });

    const plan = makePlan([
      makeAction({ id: 'a1', sequence: 1, blast_radius: BlastRadius.NONE, rollback_spec: undefined }),
      makeAction({ id: 'a2', sequence: 2, blast_radius: BlastRadius.LOW }),
    ]);
    const approved = new Set(['a1', 'a2']);

    const result = await executor.executePlan(plan, 'tenant-abc', approved);

    // a1 (read-only) failed but a2 still executed
    expect(result.failed_count).toBe(1);
    expect(result.succeeded_count).toBe(1);
  });
});

// ── ActionExecutor.executeRollback ────────────────────────────────────────────

describe('ActionExecutor.executeRollback', () => {
  it('executes rollback and marks entry as EXECUTED', async () => {
    const { executor, rollbackStore, rollbackRegistry, executionStore } = createExecutor();

    // First execute an action to create a rollback entry
    const action = makeAction();
    const execRecord = await executor.executeAction(action, 'plan-001', 'tenant-abc');

    // Get the rollback entry
    const rollbackEntry = [...rollbackStore.entries.values()][0]!;

    // Execute the rollback
    const rollbackRecord = await executor.executeRollback(rollbackEntry.id, 'tenant-abc', 'analyst:alice');

    expect(rollbackRecord.success).toBe(true);
    expect(rollbackRecord.status).toBe(ExecutionStatus.ROLLED_BACK);
    expect(rollbackRecord.outcome_description).toContain('Rollback completed');

    // Rollback entry should be marked as executed
    const updatedEntry = await rollbackStore.getById(rollbackEntry.id, 'tenant-abc');
    expect(updatedEntry!.status).toBe('EXECUTED');
    expect(updatedEntry!.executed_by).toBe('analyst:alice');
  });

  it('writes an audit log entry for rollback', async () => {
    const { executor, rollbackStore, auditLog } = createExecutor();

    const action = makeAction();
    await executor.executeAction(action, 'plan-001', 'tenant-abc');
    const rollbackEntry = [...rollbackStore.entries.values()][0]!;

    await executor.executeRollback(rollbackEntry.id, 'tenant-abc', 'analyst:alice');

    const rollbackAudit = auditLog.entries.find(e => e.event_type === 'ACTION_ROLLED_BACK');
    expect(rollbackAudit).toBeDefined();
    expect(rollbackAudit!.outcome).toBe('SUCCESS');
  });

  it('throws when rollback entry not found', async () => {
    const { executor } = createExecutor();
    await expect(executor.executeRollback('nonexistent', 'tenant-abc', 'analyst:alice'))
      .rejects.toThrow('not found');
  });

  it('returns failed record when rollback API call fails', async () => {
    const { executor, rollbackStore, apiClient } = createExecutor();

    // Execute original action
    await executor.executeAction(makeAction(), 'plan-001', 'tenant-abc');
    const rollbackEntry = [...rollbackStore.entries.values()][0]!;

    // Make the rollback API call fail
    (apiClient.execute as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      success: false,
      errorMessage: 'AccessDenied',
    });

    const record = await executor.executeRollback(rollbackEntry.id, 'tenant-abc', 'analyst:alice');

    expect(record.success).toBe(false);
    expect(record.status).toBe(ExecutionStatus.FAILED);
  });
});
