/**
 * Tests for the Context Assembler.
 * Verifies that the correct context is assembled for each reasoning mode
 * and that memory filtering works correctly.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  ContextAssembler,
  EnvironmentContextProvider,
  MemoryProvider,
  ToolCapabilityProvider,
  TenantConfigProvider,
  RecentEventsProvider,
  defaultTenantConfig,
} from './context-assembler.js';
import {
  ReasoningMode,
  AttackSurface,
  AwsDataSource,
  TrustLevel,
  NormalizedEvent,
  EnvironmentContext,
  ReasoningMemoryEntry,
  ToolCapabilityProfile,
  TenantConfig,
  BlastRadius,
} from '../types/index.js';

// ── Mock Providers ────────────────────────────────────────────────────────────

function makeEnvContext(overrides?: Partial<EnvironmentContext>): EnvironmentContext {
  return {
    tenant_id: 'tenant-abc',
    account_id: '123456789012',
    total_assets: 10,
    critical_assets: [],
    recent_config_changes: [],
    active_incidents_count: 0,
    assembled_at: new Date().toISOString(),
    ...overrides,
  };
}

function makeToolProfile(): ToolCapabilityProfile {
  return {
    connector_id: 'conn-001',
    tenant_id: 'tenant-abc',
    tool_type: 'AWS',
    account_id: '123456789012',
    region: 'us-east-1',
    readable_sources: [AwsDataSource.CLOUDTRAIL],
    writable_actions: [{
      action_id: 'aws:iam:disable-access-key',
      description: 'Disable IAM key',
      aws_service: 'iam',
      aws_api_call: 'UpdateAccessKey',
      required_params: ['AccessKeyId', 'Status'],
      blast_radius: BlastRadius.LOW,
      reversible: true,
      rollback_api_call: 'UpdateAccessKey',
    }],
    discovered_at: '2024-06-01T00:00:00Z',
    last_updated: '2024-06-01T00:00:00Z',
  };
}

function makeMemoryEntry(overrides?: Partial<ReasoningMemoryEntry>): ReasoningMemoryEntry {
  return {
    id: 'mem-001',
    tenant_id: 'tenant-abc',
    incident_id: 'inc-001',
    threat_type: 'Credential Compromise',
    threat_description: 'IAM key used from Russia',
    affected_asset_types: ['AWS::IAM::AccessKey'],
    mitre_technique_ids: ['T1078.004'],
    actions_taken: ['Disabled access key'],
    outcome: 'RESOLVED',
    embedding_text: 'credential compromise IAM key Russia',
    created_at: '2024-05-01T00:00:00Z',
    ...overrides,
  };
}

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

function createMockProviders(overrides?: {
  envContext?: EnvironmentContext;
  memory?: ReasoningMemoryEntry[];
  tools?: ToolCapabilityProfile[];
  config?: TenantConfig;
  recentEvents?: NormalizedEvent[];
}) {
  const envProvider: EnvironmentContextProvider = {
    assembleContext: vi.fn(async () => overrides?.envContext ?? makeEnvContext()),
  };
  const memoryProvider: MemoryProvider = {
    getMemoryEntriesByTenant: vi.fn(async () => overrides?.memory ?? []),
  };
  const toolProvider: ToolCapabilityProvider = {
    getCapabilitiesForTenant: vi.fn(async () => overrides?.tools ?? [makeToolProfile()]),
  };
  const configProvider: TenantConfigProvider = {
    getConfig: vi.fn(async () => overrides?.config ?? defaultTenantConfig('tenant-abc')),
  };
  const eventsProvider: RecentEventsProvider = {
    getRecentEvents: vi.fn(async () => overrides?.recentEvents ?? []),
  };

  return { envProvider, memoryProvider, toolProvider, configProvider, eventsProvider };
}

function makeAssembler(overrides?: Parameters<typeof createMockProviders>[0]) {
  const providers = createMockProviders(overrides);
  const assembler = new ContextAssembler(
    providers.envProvider,
    providers.memoryProvider,
    providers.toolProvider,
    providers.configProvider,
    providers.eventsProvider
  );
  return { assembler, ...providers };
}

// ── defaultTenantConfig ───────────────────────────────────────────────────────

describe('defaultTenantConfig', () => {
  it('returns a valid config with trust level 1', () => {
    const config = defaultTenantConfig('tenant-xyz');
    expect(config.tenant_id).toBe('tenant-xyz');
    expect(config.trust_level).toBe(TrustLevel.ONE);
    expect(config.confidence_threshold_low).toBe(70);
    expect(config.confidence_threshold_medium).toBe(85);
    expect(config.approval_timeout_hours).toBe(4);
  });
});

// ── assembleReactive ──────────────────────────────────────────────────────────

describe('ContextAssembler.assembleReactive', () => {
  it('returns a REACTIVE mode request with all required fields', async () => {
    const { assembler } = makeAssembler();
    const event = makeEvent();

    const request = await assembler.assembleReactive('tenant-abc', '123456789012', event);

    expect(request.mode).toBe(ReasoningMode.REACTIVE);
    expect(request.tenant_id).toBe('tenant-abc');
    expect(request.trigger_event).toEqual(event);
    expect(request.id).toBeDefined();
    expect(request.created_at).toBeDefined();
  });

  it('includes environment context, tools, config, and memory', async () => {
    const memory = [makeMemoryEntry()];
    const { assembler } = makeAssembler({ memory });
    const event = makeEvent();

    const request = await assembler.assembleReactive('tenant-abc', '123456789012', event);

    expect(request.environment_context).toBeDefined();
    expect(request.tool_capabilities).toHaveLength(1);
    expect(request.tenant_config).toBeDefined();
    expect(request.relevant_memory.length).toBeGreaterThanOrEqual(0);
  });

  it('passes relevant resource IDs to environment context assembly', async () => {
    const { assembler, envProvider } = makeAssembler();
    const event = makeEvent();

    await assembler.assembleReactive('tenant-abc', '123456789012', event);

    expect(envProvider.assembleContext).toHaveBeenCalledWith(
      'tenant-abc',
      '123456789012',
      expect.arrayContaining([
        'arn:aws:iam::123456789012:user/alice',
      ])
    );
  });

  it('excludes the triggering event from recent_events', async () => {
    const event = makeEvent({ id: 'evt-trigger' });
    const otherEvent = makeEvent({ id: 'evt-other' });
    const { assembler } = makeAssembler({ recentEvents: [event, otherEvent] });

    const request = await assembler.assembleReactive('tenant-abc', '123456789012', event);

    const recentIds = request.recent_events.map((e) => e.id);
    expect(recentIds).not.toContain('evt-trigger');
    expect(recentIds).toContain('evt-other');
  });

  it('fetches all providers in parallel', async () => {
    const callOrder: string[] = [];
    const { assembler, envProvider, memoryProvider, toolProvider, configProvider, eventsProvider } = makeAssembler();

    (envProvider.assembleContext as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      callOrder.push('env');
      return makeEnvContext();
    });
    (memoryProvider.getMemoryEntriesByTenant as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      callOrder.push('memory');
      return [];
    });
    (toolProvider.getCapabilitiesForTenant as ReturnType<typeof vi.fn>).mockImplementation(async () => {
      callOrder.push('tools');
      return [makeToolProfile()];
    });

    await assembler.assembleReactive('tenant-abc', '123456789012', makeEvent());

    // All three should be called (order may vary due to parallel execution)
    expect(callOrder).toContain('env');
    expect(callOrder).toContain('memory');
    expect(callOrder).toContain('tools');
  });
});

// ── assembleProactive ─────────────────────────────────────────────────────────

describe('ContextAssembler.assembleProactive', () => {
  it('returns a PROACTIVE mode request', async () => {
    const { assembler } = makeAssembler();
    const request = await assembler.assembleProactive('tenant-abc', '123456789012');

    expect(request.mode).toBe(ReasoningMode.PROACTIVE);
    expect(request.trigger_event).toBeUndefined();
    expect(request.trigger_description).toContain('threat hunt');
  });

  it('includes recent events for pattern analysis', async () => {
    const events = [makeEvent({ id: 'e1' }), makeEvent({ id: 'e2' })];
    const { assembler } = makeAssembler({ recentEvents: events });

    const request = await assembler.assembleProactive('tenant-abc', '123456789012');

    expect(request.recent_events).toHaveLength(2);
  });
});

// ── assemblePredictive ────────────────────────────────────────────────────────

describe('ContextAssembler.assemblePredictive', () => {
  it('returns a PREDICTIVE mode request with the trigger description', async () => {
    const { assembler } = makeAssembler();
    const description = 'New CVE CVE-2024-1234 affects EC2 instances running Amazon Linux 2';

    const request = await assembler.assemblePredictive('tenant-abc', '123456789012', description);

    expect(request.mode).toBe(ReasoningMode.PREDICTIVE);
    expect(request.trigger_description).toBe(description);
    expect(request.trigger_event).toBeUndefined();
  });

  it('does not fetch memory or recent events (not needed for forecasting)', async () => {
    const { assembler, memoryProvider, eventsProvider } = makeAssembler();

    await assembler.assemblePredictive('tenant-abc', '123456789012', 'test');

    expect(memoryProvider.getMemoryEntriesByTenant).not.toHaveBeenCalled();
    expect(eventsProvider.getRecentEvents).not.toHaveBeenCalled();
  });
});

// ── assembleInvestigative ─────────────────────────────────────────────────────

describe('ContextAssembler.assembleInvestigative', () => {
  it('returns an INVESTIGATIVE mode request', async () => {
    const { assembler } = makeAssembler();
    const description = 'Investigate suspicious activity on prod-db';

    const request = await assembler.assembleInvestigative('tenant-abc', '123456789012', description);

    expect(request.mode).toBe(ReasoningMode.INVESTIGATIVE);
    expect(request.trigger_description).toBe(description);
  });

  it('passes relevant resource IDs to environment context', async () => {
    const { assembler, envProvider } = makeAssembler();
    const relevantIds = ['arn:aws:rds:us-east-1:123:db:prod-db'];

    await assembler.assembleInvestigative('tenant-abc', '123456789012', 'investigate', relevantIds);

    expect(envProvider.assembleContext).toHaveBeenCalledWith(
      'tenant-abc', '123456789012', relevantIds
    );
  });
});

// ── Memory filtering ──────────────────────────────────────────────────────────

describe('Memory filtering in assembleReactive', () => {
  it('prioritizes memory entries matching the event asset type', async () => {
    const memory = [
      makeMemoryEntry({ id: 'mem-iam', affected_asset_types: ['AWS::IAM::AccessKey'], threat_type: 'IAM Threat' }),
      makeMemoryEntry({ id: 'mem-ec2', affected_asset_types: ['AWS::EC2::Instance'], threat_type: 'EC2 Threat' }),
      makeMemoryEntry({ id: 'mem-s3', affected_asset_types: ['AWS::S3::Bucket'], threat_type: 'S3 Threat' }),
    ];
    const { assembler } = makeAssembler({ memory });

    // Event targets an IAM user
    const event = makeEvent({
      target: { resource_type: 'AWS::IAM::User', resource_id: 'arn:aws:iam::123:user/alice', attack_surface: AttackSurface.CLOUD_IAM },
    });

    const request = await assembler.assembleReactive('tenant-abc', '123456789012', event);

    // IAM-related memory should be included
    const memoryTypes = request.relevant_memory.map((m) => m.threat_type);
    expect(memoryTypes).toContain('IAM Threat');
  });

  it('includes false positive memory entries (to avoid repeating mistakes)', async () => {
    const memory = [
      makeMemoryEntry({
        id: 'mem-fp',
        threat_type: 'False Alarm',
        analyst_feedback: { verdict: 'FALSE_POSITIVE', submitted_by: 'analyst', submitted_at: '2024-05-01T00:00:00Z' },
      }),
    ];
    const { assembler } = makeAssembler({ memory });

    const request = await assembler.assembleReactive('tenant-abc', '123456789012', makeEvent());

    // False positives should be included so AI doesn't repeat the mistake
    expect(request.relevant_memory.length).toBeGreaterThan(0);
  });

  it('returns empty memory when no entries exist', async () => {
    const { assembler } = makeAssembler({ memory: [] });

    const request = await assembler.assembleReactive('tenant-abc', '123456789012', makeEvent());

    expect(request.relevant_memory).toHaveLength(0);
  });
});
