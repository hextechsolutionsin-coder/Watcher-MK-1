import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  SafetyGate,
  RateLimiter,
  validateToolPermission,
  validateReversibility,
  validateConfidence,
  validateTrustLevel,
  DEFAULT_SAFETY_CONFIG,
} from './safety-gate.js';
import {
  PlannedAction,
  ActionPlan,
  SafetyDecision,
  BlastRadius,
  ActionUrgency,
  TrustLevel,
  ToolCapabilityProfile,
  TenantConfig,
  AwsDataSource,
} from '../types/index.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeAction(overrides?: Partial<PlannedAction>): PlannedAction {
  return {
    id: 'action-001',
    sequence: 1,
    description: 'Disable compromised IAM access key',
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

function makeProfile(overrides?: Partial<ToolCapabilityProfile>): ToolCapabilityProfile {
  return {
    connector_id: 'conn-001',
    tenant_id: 'tenant-abc',
    tool_type: 'AWS',
    account_id: '123456789012',
    region: 'us-east-1',
    readable_sources: [AwsDataSource.CLOUDTRAIL],
    writable_actions: [
      {
        action_id: 'aws:iam:disable-access-key',
        description: 'Disable IAM key',
        aws_service: 'iam',
        aws_api_call: 'UpdateAccessKey',
        required_params: ['AccessKeyId', 'Status'],
        blast_radius: BlastRadius.LOW,
        reversible: true,
        rollback_api_call: 'UpdateAccessKey',
      },
      {
        action_id: 'aws:ec2:stop-instance',
        description: 'Stop EC2 instance',
        aws_service: 'ec2',
        aws_api_call: 'StopInstances',
        required_params: ['InstanceIds'],
        blast_radius: BlastRadius.MEDIUM,
        reversible: true,
        rollback_api_call: 'StartInstances',
      },
      {
        action_id: 'aws:cloudtrail:lookup-events',
        description: 'Query CloudTrail',
        aws_service: 'cloudtrail',
        aws_api_call: 'LookupEvents',
        required_params: ['LookupAttributes'],
        blast_radius: BlastRadius.NONE,
        reversible: false,
      },
    ],
    discovered_at: '2024-06-01T00:00:00Z',
    last_updated: '2024-06-01T00:00:00Z',
    ...overrides,
  };
}

function makeTenantConfig(overrides?: Partial<TenantConfig>): TenantConfig {
  return {
    tenant_id: 'tenant-abc',
    trust_level: TrustLevel.TWO,
    confidence_threshold_low: 70,
    confidence_threshold_medium: 85,
    approval_timeout_hours: 4,
    approval_channels: [],
    reasoning_sensitivity: 'MEDIUM',
    cross_tenant_opt_in: false,
    gdpr_mode: false,
    data_retention_days: 365,
    aws_accounts: [],
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

function createMockRateLimiter(withinLimit = true): RateLimiter {
  return {
    checkAndIncrement: vi.fn(async () => withinLimit),
    getCurrentCount: vi.fn(async () => 0),
  };
}

// ── validateToolPermission ────────────────────────────────────────────────────

describe('validateToolPermission', () => {
  it('passes when action is in the capability profile', () => {
    const action = makeAction({ tool_action_id: 'aws:iam:disable-access-key' });
    const result = validateToolPermission(action, [makeProfile()]);
    expect(result.passed).toBe(true);
  });

  it('fails when action is NOT in the capability profile', () => {
    const action = makeAction({ tool_action_id: 'aws:ec2:terminate-instance' });
    const result = validateToolPermission(action, [makeProfile()]);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('aws:ec2:terminate-instance');
  });

  it('fails when no profiles are available', () => {
    const action = makeAction();
    const result = validateToolPermission(action, []);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('No tool capability profiles');
  });

  it('checks across multiple profiles', () => {
    const profile1 = makeProfile({ writable_actions: [] });
    const profile2 = makeProfile();
    const action = makeAction({ tool_action_id: 'aws:iam:disable-access-key' });
    const result = validateToolPermission(action, [profile1, profile2]);
    expect(result.passed).toBe(true);
  });
});

// ── validateReversibility ─────────────────────────────────────────────────────

describe('validateReversibility', () => {
  it('passes for NONE blast radius without rollback spec', () => {
    const action = makeAction({ blast_radius: BlastRadius.NONE, rollback_spec: undefined });
    const result = validateReversibility(action);
    expect(result.passed).toBe(true);
    expect(result.reason).toContain('Read-only');
  });

  it('passes for write action with valid rollback spec', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW });
    const result = validateReversibility(action);
    expect(result.passed).toBe(true);
  });

  it('fails for write action without rollback spec', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, rollback_spec: undefined });
    const result = validateReversibility(action);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('no rollback specification');
  });

  it('fails for write action with incomplete rollback spec', () => {
    const action = makeAction({
      blast_radius: BlastRadius.MEDIUM,
      rollback_spec: { aws_service: '', aws_api_call: '', api_params: {}, description: 'undo' },
    });
    const result = validateReversibility(action);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('incomplete');
  });

  it('fails for HIGH blast radius without rollback', () => {
    const action = makeAction({ blast_radius: BlastRadius.HIGH, rollback_spec: undefined });
    const result = validateReversibility(action);
    expect(result.passed).toBe(false);
  });
});

// ── validateConfidence ────────────────────────────────────────────────────────

describe('validateConfidence', () => {
  const config = DEFAULT_SAFETY_CONFIG;

  it('always passes for NONE blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.NONE, confidence: 0 });
    const result = validateConfidence(action, config, makeTenantConfig());
    expect(result.passed).toBe(true);
  });

  it('passes for LOW blast radius when confidence >= threshold', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 75 });
    const result = validateConfidence(action, config, makeTenantConfig({ confidence_threshold_low: 70 }));
    expect(result.passed).toBe(true);
  });

  it('fails for LOW blast radius when confidence < threshold', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 65 });
    const result = validateConfidence(action, config, makeTenantConfig({ confidence_threshold_low: 70 }));
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('65%');
    expect(result.reason).toContain('70%');
  });

  it('passes for MEDIUM blast radius when confidence >= threshold', () => {
    const action = makeAction({ blast_radius: BlastRadius.MEDIUM, confidence: 90 });
    const result = validateConfidence(action, config, makeTenantConfig({ confidence_threshold_medium: 85 }));
    expect(result.passed).toBe(true);
  });

  it('fails for MEDIUM blast radius when confidence < threshold', () => {
    const action = makeAction({ blast_radius: BlastRadius.MEDIUM, confidence: 80 });
    const result = validateConfidence(action, config, makeTenantConfig({ confidence_threshold_medium: 85 }));
    expect(result.passed).toBe(false);
  });

  it('always fails for HIGH blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.HIGH, confidence: 100 });
    const result = validateConfidence(action, config, makeTenantConfig());
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('HIGH blast radius');
  });

  it('uses tenant-specific thresholds over defaults', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 60 });
    // Tenant has lower threshold than default
    const result = validateConfidence(action, config, makeTenantConfig({ confidence_threshold_low: 55 }));
    expect(result.passed).toBe(true);
  });
});

// ── validateTrustLevel ────────────────────────────────────────────────────────

describe('validateTrustLevel', () => {
  it('Level 1 passes NONE blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.NONE });
    const result = validateTrustLevel(action, TrustLevel.ONE);
    expect(result.passed).toBe(true);
  });

  it('Level 1 fails LOW blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW });
    const result = validateTrustLevel(action, TrustLevel.ONE);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('Trust level 1');
  });

  it('Level 2 passes LOW blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW });
    const result = validateTrustLevel(action, TrustLevel.TWO);
    expect(result.passed).toBe(true);
  });

  it('Level 2 fails MEDIUM blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.MEDIUM });
    const result = validateTrustLevel(action, TrustLevel.TWO);
    expect(result.passed).toBe(false);
  });

  it('Level 3 passes MEDIUM blast radius', () => {
    const action = makeAction({ blast_radius: BlastRadius.MEDIUM });
    const result = validateTrustLevel(action, TrustLevel.THREE);
    expect(result.passed).toBe(true);
  });

  it('always fails HIGH blast radius regardless of trust level', () => {
    const action = makeAction({ blast_radius: BlastRadius.HIGH });
    expect(validateTrustLevel(action, TrustLevel.ONE).passed).toBe(false);
    expect(validateTrustLevel(action, TrustLevel.TWO).passed).toBe(false);
    expect(validateTrustLevel(action, TrustLevel.THREE).passed).toBe(false);
  });
});

// ── SafetyGate.validateAction ─────────────────────────────────────────────────

describe('SafetyGate.validateAction', () => {
  let gate: SafetyGate;
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = createMockRateLimiter(true);
    gate = new SafetyGate(rateLimiter);
  });

  it('APPROVED: NONE blast radius action at any trust level', async () => {
    const action = makeAction({
      tool_action_id: 'aws:cloudtrail:lookup-events',
      blast_radius: BlastRadius.NONE,
      rollback_spec: undefined,
    });
    const result = await gate.validateAction(action, TrustLevel.ONE, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.APPROVED);
  });

  it('APPROVED: LOW blast radius at Level 2 with sufficient confidence', async () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 85 });
    const result = await gate.validateAction(action, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.APPROVED);
  });

  it('HUMAN_REVIEW: LOW blast radius at Level 1 (insufficient trust)', async () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 90 });
    const result = await gate.validateAction(action, TrustLevel.ONE, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.HUMAN_REVIEW);
  });

  it('HUMAN_REVIEW: LOW blast radius with low confidence', async () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 50 });
    const result = await gate.validateAction(action, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.HUMAN_REVIEW);
  });

  it('HUMAN_REVIEW: HIGH blast radius always', async () => {
    const action = makeAction({
      blast_radius: BlastRadius.HIGH,
      confidence: 99,
      rollback_spec: { aws_service: 'ec2', aws_api_call: 'StartInstances', api_params: {}, description: 'restart' },
    });
    const result = await gate.validateAction(action, TrustLevel.THREE, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.HUMAN_REVIEW);
  });

  it('REJECTED: action not in capability profile', async () => {
    const action = makeAction({ tool_action_id: 'aws:ec2:terminate-instance' });
    const result = await gate.validateAction(action, TrustLevel.THREE, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.REJECTED);
    expect(result.reasons[0]).toContain('aws:ec2:terminate-instance');
  });

  it('REJECTED: write action without rollback spec', async () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, rollback_spec: undefined });
    const result = await gate.validateAction(action, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.REJECTED);
    expect(result.reasons[0]).toContain('no rollback specification');
  });

  it('REJECTED: rate limit exceeded', async () => {
    rateLimiter = createMockRateLimiter(false);
    gate = new SafetyGate(rateLimiter);

    const action = makeAction({ blast_radius: BlastRadius.LOW });
    const result = await gate.validateAction(action, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.decision).toBe(SafetyDecision.REJECTED);
    expect(result.reasons[0]).toContain('Rate limit');
  });

  it('result includes blast_radius, trust_level, and confidence', async () => {
    const action = makeAction({ blast_radius: BlastRadius.LOW, confidence: 85 });
    const result = await gate.validateAction(action, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.blast_radius).toBe(BlastRadius.LOW);
    expect(result.trust_level).toBe(TrustLevel.TWO);
    expect(result.confidence).toBe(85);
    expect(result.evaluated_at).toBeDefined();
  });

  it('does NOT call rate limiter for NONE blast radius actions', async () => {
    const action = makeAction({
      tool_action_id: 'aws:cloudtrail:lookup-events',
      blast_radius: BlastRadius.NONE,
      rollback_spec: undefined,
    });
    await gate.validateAction(action, TrustLevel.ONE, [makeProfile()], makeTenantConfig());

    expect(rateLimiter.checkAndIncrement).not.toHaveBeenCalled();
  });
});

// ── SafetyGate.validatePlan ───────────────────────────────────────────────────

describe('SafetyGate.validatePlan', () => {
  let gate: SafetyGate;

  beforeEach(() => {
    gate = new SafetyGate(createMockRateLimiter(true));
  });

  it('fully_autonomous when all actions are APPROVED', async () => {
    const plan = makePlan([
      makeAction({ id: 'a1', tool_action_id: 'aws:cloudtrail:lookup-events', blast_radius: BlastRadius.NONE, rollback_spec: undefined }),
      makeAction({ id: 'a2', blast_radius: BlastRadius.LOW, confidence: 85 }),
    ]);

    const result = await gate.validatePlan(plan, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.fully_autonomous).toBe(true);
    expect(result.requires_human_review).toBe(false);
    expect(result.has_rejections).toBe(false);
    expect(result.approved_count).toBe(2);
  });

  it('requires_human_review when any action needs review', async () => {
    const plan = makePlan([
      makeAction({ id: 'a1', blast_radius: BlastRadius.LOW, confidence: 85 }),
      makeAction({ id: 'a2', blast_radius: BlastRadius.HIGH, confidence: 99,
        rollback_spec: { aws_service: 'ec2', aws_api_call: 'StartInstances', api_params: {}, description: 'restart' } }),
    ]);

    const result = await gate.validatePlan(plan, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.requires_human_review).toBe(true);
    expect(result.fully_autonomous).toBe(false);
    expect(result.human_review_count).toBe(1);
    expect(result.approved_count).toBe(1);
  });

  it('has_rejections when any action is rejected', async () => {
    const plan = makePlan([
      makeAction({ id: 'a1', blast_radius: BlastRadius.LOW, confidence: 85 }),
      makeAction({ id: 'a2', tool_action_id: 'aws:nonexistent:action' }),
    ]);

    const result = await gate.validatePlan(plan, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.has_rejections).toBe(true);
    expect(result.rejected_count).toBe(1);
  });

  it('returns correct counts for mixed plan', async () => {
    const plan = makePlan([
      makeAction({ id: 'a1', tool_action_id: 'aws:cloudtrail:lookup-events', blast_radius: BlastRadius.NONE, rollback_spec: undefined }),
      makeAction({ id: 'a2', blast_radius: BlastRadius.LOW, confidence: 85 }),
      makeAction({ id: 'a3', blast_radius: BlastRadius.HIGH, confidence: 99,
        rollback_spec: { aws_service: 'ec2', aws_api_call: 'StartInstances', api_params: {}, description: 'restart' } }),
      makeAction({ id: 'a4', tool_action_id: 'aws:nonexistent:action' }),
    ]);

    const result = await gate.validatePlan(plan, TrustLevel.TWO, [makeProfile()], makeTenantConfig());

    expect(result.approved_count).toBe(2);
    expect(result.human_review_count).toBe(1);
    expect(result.rejected_count).toBe(1);
    expect(result.action_results).toHaveLength(4);
  });

  it('returns plan_id in result', async () => {
    const plan = makePlan([makeAction()]);
    const result = await gate.validatePlan(plan, TrustLevel.TWO, [makeProfile()], makeTenantConfig());
    expect(result.plan_id).toBe('plan-001');
  });
});
