/**
 * Tests for the AI Reasoning Engine.
 *
 * The Bedrock API call is mocked — we test:
 * 1. Response parsing (valid JSON, malformed JSON, missing fields)
 * 2. Prompt routing (correct prompt built per reasoning mode)
 * 3. Full reasoning flow (mock invoker → parsed response)
 * 4. Edge cases (no tools, no memory, unparseable output)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  ReasoningEngine,
  BedrockInvoker,
  BedrockInvokeResult,
  parseReasoningResponse,
} from './reasoning-engine.js';
import {
  ReasoningRequest,
  ReasoningMode,
  IncidentSeverity,
  BlastRadius,
  ActionUrgency,
  AttackSurface,
  AwsDataSource,
  TrustLevel,
  NormalizedEvent,
  EnvironmentContext,
  TenantConfig,
  ToolCapabilityProfile,
  ReasoningMemoryEntry,
} from '../types/index.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeEvent(overrides?: Partial<NormalizedEvent>): NormalizedEvent {
  return {
    id: 'evt-001',
    tenant_id: 'tenant-abc',
    connector_id: 'conn-001',
    account_id: '123456789012',
    region: 'us-east-1',
    source: AwsDataSource.CLOUDTRAIL,
    attack_surface: AttackSurface.CLOUD_IAM,
    event_type: 'iam:CreateAccessKey',
    actor: { type: 'IAM_USER', identifier: 'arn:aws:iam::123456789012:user/alice', account_id: '123456789012' },
    target: {
      resource_type: 'AWS::IAM::User',
      resource_id: 'arn:aws:iam::123456789012:user/alice',
      attack_surface: AttackSurface.CLOUD_IAM,
    },
    source_ip: '198.51.100.99',
    raw_payload: {},
    ingestion_timestamp: '2024-06-01T10:00:00Z',
    ...overrides,
  };
}

function makeEnvContext(overrides?: Partial<EnvironmentContext>): EnvironmentContext {
  return {
    tenant_id: 'tenant-abc',
    account_id: '123456789012',
    total_assets: 42,
    critical_assets: [],
    recent_config_changes: [],
    active_incidents_count: 0,
    assembled_at: '2024-06-01T10:00:00Z',
    ...overrides,
  };
}

function makeTenantConfig(overrides?: Partial<TenantConfig>): TenantConfig {
  return {
    tenant_id: 'tenant-abc',
    trust_level: TrustLevel.ONE,
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

function makeToolProfile(overrides?: Partial<ToolCapabilityProfile>): ToolCapabilityProfile {
  return {
    connector_id: 'conn-001',
    tenant_id: 'tenant-abc',
    tool_type: 'AWS',
    account_id: '123456789012',
    region: 'us-east-1',
    readable_sources: [AwsDataSource.CLOUDTRAIL, AwsDataSource.GUARDDUTY],
    writable_actions: [
      {
        action_id: 'aws:iam:disable-access-key',
        description: 'Disable an IAM access key',
        aws_service: 'iam',
        aws_api_call: 'UpdateAccessKey',
        required_params: ['AccessKeyId', 'Status'],
        blast_radius: BlastRadius.LOW,
        reversible: true,
        rollback_api_call: 'UpdateAccessKey',
      },
    ],
    discovered_at: '2024-06-01T00:00:00Z',
    last_updated: '2024-06-01T00:00:00Z',
    ...overrides,
  };
}

function makeRequest(overrides?: Partial<ReasoningRequest>): ReasoningRequest {
  return {
    id: 'req-001',
    tenant_id: 'tenant-abc',
    mode: ReasoningMode.REACTIVE,
    trigger_event: makeEvent(),
    environment_context: makeEnvContext(),
    recent_events: [],
    relevant_memory: [],
    tool_capabilities: [makeToolProfile()],
    tenant_config: makeTenantConfig(),
    created_at: '2024-06-01T10:00:00Z',
    ...overrides,
  };
}

// ── Valid threat response JSON ─────────────────────────────────────────────────

const THREAT_RESPONSE_JSON = JSON.stringify({
  is_threat: true,
  assessment: {
    threat_type: 'Credential Compromise',
    threat_description: 'IAM access key used from anomalous IP in Russia',
    severity: 'HIGH',
    confidence: 87,
    mitre_techniques: [
      { technique_id: 'T1078.004', technique_name: 'Valid Accounts: Cloud Accounts', tactic: 'Initial Access' },
    ],
    affected_assets: ['arn:aws:iam::123456789012:user/alice'],
    kill_chain_stage: 'Initial Access',
    related_incident_ids: [],
    predictions: {
      next_likely_action: 'Data exfiltration from S3',
      probability: 72,
      recommended_preemption: 'Audit S3 access logs for this key',
    },
  },
  action_plan: {
    overall_reasoning: 'Revoking the key stops the attacker immediately',
    actions: [
      {
        sequence: 1,
        description: 'Disable the compromised IAM access key',
        reasoning: 'Key is actively being used by attacker from Russia',
        connector_id: 'conn-001',
        tool_action_id: 'aws:iam:disable-access-key',
        aws_service: 'iam',
        aws_api_call: 'UpdateAccessKey',
        api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Inactive' },
        blast_radius: 'LOW',
        urgency: 'IMMEDIATE',
        confidence: 90,
        rollback_spec: {
          aws_service: 'iam',
          aws_api_call: 'UpdateAccessKey',
          api_params: { AccessKeyId: 'AKIAEXAMPLE', Status: 'Active' },
          description: 'Re-enable the access key',
        },
      },
    ],
  },
  explanation: 'A compromised IAM key was used from Russia. I disabled it immediately.',
  reasoning_trace: 'Step 1: Observed API call from 198.51.100.99 (Russia)...',
});

const NON_THREAT_RESPONSE_JSON = JSON.stringify({
  is_threat: false,
  explanation: 'This is normal CI/CD pipeline activity. The IP is a known GitHub Actions runner.',
  reasoning_trace: 'Step 1: Checked source IP against known CI/CD ranges...',
});

// ── parseReasoningResponse ────────────────────────────────────────────────────

describe('parseReasoningResponse', () => {
  it('parses a valid threat response correctly', () => {
    const result = parseReasoningResponse(
      THREAT_RESPONSE_JSON, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'us.anthropic.claude-sonnet-4-6', 1500
    );

    expect(result.is_threat).toBe(true);
    expect(result.tenant_id).toBe('tenant-abc');
    expect(result.mode).toBe(ReasoningMode.REACTIVE);
    expect(result.tokens_used).toBe(1500);
    expect(result.id).toBeDefined();
    expect(result.created_at).toBeDefined();
  });

  it('parses threat assessment fields correctly', () => {
    const result = parseReasoningResponse(
      THREAT_RESPONSE_JSON, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    expect(result.assessment).toBeDefined();
    expect(result.assessment!.threat_type).toBe('Credential Compromise');
    expect(result.assessment!.severity).toBe(IncidentSeverity.HIGH);
    expect(result.assessment!.confidence).toBe(87);
    expect(result.assessment!.mitre_techniques).toHaveLength(1);
    expect(result.assessment!.mitre_techniques[0]!.technique_id).toBe('T1078.004');
    expect(result.assessment!.kill_chain_stage).toBe('Initial Access');
    expect(result.assessment!.predictions.probability).toBe(72);
  });

  it('parses action plan correctly', () => {
    const result = parseReasoningResponse(
      THREAT_RESPONSE_JSON, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    expect(result.action_plan).toBeDefined();
    expect(result.action_plan!.actions).toHaveLength(1);

    const action = result.action_plan!.actions[0]!;
    expect(action.tool_action_id).toBe('aws:iam:disable-access-key');
    expect(action.aws_service).toBe('iam');
    expect(action.aws_api_call).toBe('UpdateAccessKey');
    expect(action.blast_radius).toBe(BlastRadius.LOW);
    expect(action.urgency).toBe(ActionUrgency.IMMEDIATE);
    expect(action.confidence).toBe(90);
    expect(action.api_params).toEqual({ AccessKeyId: 'AKIAEXAMPLE', Status: 'Inactive' });
  });

  it('parses rollback spec correctly', () => {
    const result = parseReasoningResponse(
      THREAT_RESPONSE_JSON, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    const action = result.action_plan!.actions[0]!;
    expect(action.rollback_spec).toBeDefined();
    expect(action.rollback_spec!.aws_api_call).toBe('UpdateAccessKey');
    expect(action.rollback_spec!.api_params).toEqual({ AccessKeyId: 'AKIAEXAMPLE', Status: 'Active' });
    expect(action.rollback_spec!.description).toBe('Re-enable the access key');
  });

  it('parses a non-threat response correctly', () => {
    const result = parseReasoningResponse(
      NON_THREAT_RESPONSE_JSON, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    expect(result.is_threat).toBe(false);
    expect(result.assessment).toBeUndefined();
    expect(result.action_plan).toBeUndefined();
    expect(result.explanation).toContain('normal CI/CD');
  });

  it('handles JSON wrapped in markdown code blocks', () => {
    const wrapped = '```json\n' + THREAT_RESPONSE_JSON + '\n```';
    const result = parseReasoningResponse(
      wrapped, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    expect(result.is_threat).toBe(true);
    expect(result.assessment).toBeDefined();
  });

  it('handles plain code block without json tag', () => {
    const wrapped = '```\n' + NON_THREAT_RESPONSE_JSON + '\n```';
    const result = parseReasoningResponse(
      wrapped, 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    expect(result.is_threat).toBe(false);
  });

  it('returns safe fallback for unparseable response', () => {
    const result = parseReasoningResponse(
      'This is not JSON at all', 'req-001', 'tenant-abc',
      ReasoningMode.REACTIVE, 'model-id', 100
    );

    expect(result.is_threat).toBe(false);
    expect(result.explanation).toContain('unparseable');
    expect(result.assessment).toBeUndefined();
    expect(result.action_plan).toBeUndefined();
  });

  it('clamps confidence to 0-100 range', () => {
    const json = JSON.stringify({
      is_threat: true,
      assessment: {
        threat_type: 'Test', threat_description: 'Test',
        severity: 'HIGH', confidence: 150,
        mitre_techniques: [], affected_assets: [],
        predictions: { next_likely_action: 'x', probability: -10, recommended_preemption: 'y' },
      },
      explanation: 'test', reasoning_trace: 'test',
    });

    const result = parseReasoningResponse(json, 'req-001', 'tenant-abc', ReasoningMode.REACTIVE, 'model-id', 100);

    expect(result.assessment!.confidence).toBe(100);
    expect(result.assessment!.predictions.probability).toBe(0);
  });

  it('defaults severity to MEDIUM for unknown severity strings', () => {
    const json = JSON.stringify({
      is_threat: true,
      assessment: {
        threat_type: 'Test', threat_description: 'Test',
        severity: 'EXTREME', confidence: 50,
        mitre_techniques: [], affected_assets: [],
        predictions: { next_likely_action: 'x', probability: 50, recommended_preemption: 'y' },
      },
      explanation: 'test', reasoning_trace: 'test',
    });

    const result = parseReasoningResponse(json, 'req-001', 'tenant-abc', ReasoningMode.REACTIVE, 'model-id', 100);
    expect(result.assessment!.severity).toBe(IncidentSeverity.MEDIUM);
  });

  it('skips actions missing required fields', () => {
    const json = JSON.stringify({
      is_threat: true,
      assessment: {
        threat_type: 'Test', threat_description: 'Test',
        severity: 'HIGH', confidence: 80,
        mitre_techniques: [], affected_assets: [],
        predictions: { next_likely_action: 'x', probability: 50, recommended_preemption: 'y' },
      },
      action_plan: {
        overall_reasoning: 'test',
        actions: [
          { sequence: 1, description: 'valid action', tool_action_id: 'aws:iam:disable-access-key', aws_service: 'iam', aws_api_call: 'UpdateAccessKey', api_params: {}, blast_radius: 'LOW', urgency: 'IMMEDIATE', confidence: 80, connector_id: 'conn-001', reasoning: 'test' },
          { sequence: 2, description: 'missing required fields' }, // no tool_action_id
        ],
      },
      explanation: 'test', reasoning_trace: 'test',
    });

    const result = parseReasoningResponse(json, 'req-001', 'tenant-abc', ReasoningMode.REACTIVE, 'model-id', 100);
    expect(result.action_plan!.actions).toHaveLength(1);
  });
});

// ── ReasoningEngine ───────────────────────────────────────────────────────────

describe('ReasoningEngine', () => {
  let mockInvoker: BedrockInvoker;
  let engine: ReasoningEngine;

  beforeEach(() => {
    mockInvoker = {
      invoke: vi.fn(async (): Promise<BedrockInvokeResult> => ({
        content: THREAT_RESPONSE_JSON,
        input_tokens: 1000,
        output_tokens: 500,
      })),
    };
    engine = new ReasoningEngine(mockInvoker);
  });

  it('calls the invoker with the correct model and returns a parsed response', async () => {
    const request = makeRequest();
    const result = await engine.reason(request);

    expect(mockInvoker.invoke).toHaveBeenCalledOnce();
    expect(result.is_threat).toBe(true);
    expect(result.tenant_id).toBe('tenant-abc');
    expect(result.tokens_used).toBe(1500);
  });

  it('passes the system prompt to the invoker', async () => {
    const request = makeRequest();
    await engine.reason(request);

    const [, , systemPrompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(systemPrompt).toContain('Watcher MK1');
    expect(systemPrompt).toContain('autonomous cybersecurity');
  });

  it('builds a reactive prompt containing event details', async () => {
    const request = makeRequest({ mode: ReasoningMode.REACTIVE });
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('iam:CreateAccessKey');
    expect(prompt).toContain('198.51.100.99');
    expect(prompt).toContain('arn:aws:iam::123456789012:user/alice');
  });

  it('builds a proactive prompt for PROACTIVE mode', async () => {
    const request = makeRequest({
      mode: ReasoningMode.PROACTIVE,
      trigger_event: undefined,
      trigger_description: 'Autonomous threat hunting cycle',
    });
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('threat hunt');
  });

  it('builds a predictive prompt for PREDICTIVE mode', async () => {
    const request = makeRequest({
      mode: ReasoningMode.PREDICTIVE,
      trigger_event: undefined,
      trigger_description: 'New CVE CVE-2024-1234 affects EC2 instances',
    });
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('CVE-2024-1234');
  });

  it('builds an investigative prompt for INVESTIGATIVE mode', async () => {
    const request = makeRequest({
      mode: ReasoningMode.INVESTIGATIVE,
      trigger_event: undefined,
      trigger_description: 'Investigate suspicious activity on prod-db',
    });
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('prod-db');
  });

  it('throws for REACTIVE mode without a trigger_event', async () => {
    const request = makeRequest({ mode: ReasoningMode.REACTIVE, trigger_event: undefined });
    await expect(engine.reason(request)).rejects.toThrow('REACTIVE mode requires a trigger_event');
  });

  it('includes tool capabilities in the prompt', async () => {
    const request = makeRequest();
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('aws:iam:disable-access-key');
    expect(prompt).toContain('blast_radius: LOW');
  });

  it('includes environment context in the prompt', async () => {
    const request = makeRequest({
      environment_context: makeEnvContext({ total_assets: 99, active_incidents_count: 3 }),
    });
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('99');
  });

  it('handles non-threat response from AI', async () => {
    (mockInvoker.invoke as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      content: NON_THREAT_RESPONSE_JSON,
      input_tokens: 800,
      output_tokens: 200,
    });

    const request = makeRequest();
    const result = await engine.reason(request);

    expect(result.is_threat).toBe(false);
    expect(result.action_plan).toBeUndefined();
    expect(result.explanation).toContain('normal CI/CD');
  });

  it('handles unparseable AI response gracefully', async () => {
    (mockInvoker.invoke as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      content: 'I cannot analyze this event.',
      input_tokens: 500,
      output_tokens: 50,
    });

    const request = makeRequest();
    const result = await engine.reason(request);

    expect(result.is_threat).toBe(false);
    expect(result.explanation).toContain('unparseable');
  });

  it('includes memory entries in the prompt when available', async () => {
    const memory: ReasoningMemoryEntry[] = [{
      id: 'mem-001',
      tenant_id: 'tenant-abc',
      incident_id: 'inc-001',
      threat_type: 'Credential Compromise',
      threat_description: 'Previous IAM key compromise from Russia',
      affected_asset_types: ['AWS::IAM::AccessKey'],
      mitre_technique_ids: ['T1078.004'],
      actions_taken: ['Disabled access key'],
      outcome: 'RESOLVED',
      embedding_text: 'credential compromise IAM key Russia',
      created_at: '2024-05-01T00:00:00Z',
    }];

    const request = makeRequest({ relevant_memory: memory });
    await engine.reason(request);

    const [, prompt] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(prompt).toContain('Credential Compromise');
    expect(prompt).toContain('Previous IAM key compromise');
  });

  it('uses custom config when provided', async () => {
    const customEngine = new ReasoningEngine(mockInvoker, {
      primaryModel: 'anthropic.claude-3-haiku-20240307-v1:0',
      maxTokens: 2048,
      temperature: 0.2,
    });

    const request = makeRequest();
    const result = await customEngine.reason(request);

    const [modelId, , , maxTokens, temperature] = (mockInvoker.invoke as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(modelId).toBe('anthropic.claude-3-haiku-20240307-v1:0');
    expect(maxTokens).toBe(2048);
    expect(temperature).toBe(0.2);
    expect(result.model_id).toBe('anthropic.claude-3-haiku-20240307-v1:0');
  });
});
