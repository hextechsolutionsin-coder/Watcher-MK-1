/**
 * Pipeline Singleton
 *
 * Creates and exports a single shared EventPipeline instance used by all
 * server routes. Wires together all components with real implementations.
 */

import { BedrockRuntimeClient } from '@aws-sdk/client-bedrock-runtime';
import { EventPipeline } from '../pipeline/event-pipeline.js';
import { ReasoningEngine, AwsBedrockInvoker, BEDROCK_MODELS } from '../ai/reasoning-engine.js';
import { ContextAssembler } from '../ai/context-assembler.js';
import { SafetyGate } from '../safety/safety-gate.js';
import { TrustLevelService } from '../safety/trust-level.js';
import { ActionExecutor } from '../execution/action-executor.js';
import { RollbackRegistry } from '../execution/rollback-registry.js';
import { HeuristicFastFilter } from '../pipeline/fast-filter.js';
import { InMemoryIncidentStore } from '../pipeline/incident-engine.js';
import { InMemoryApprovalWorkflow, NoopApprovalNotifier } from '../pipeline/approval-workflow.js';
import { EnvironmentModelService } from '../environment/environment-model.js';
import { MemoryStore } from '../memory/memory-store.js';
import { MemoryLayer } from '../memory/memory-layer.js';
import { loadMemoryLayerConfig } from '../memory/memory-layer-config.js';
import { TrustLevel, TenantConfig } from '../types/index.js';

import type {
  EnvironmentContextProvider,
  MemoryProvider,
  ToolCapabilityProvider,
  TenantConfigProvider,
  RecentEventsProvider,
} from '../ai/context-assembler.js';
import type { AuditLogWriter } from '../execution/action-executor.js';
import type { RateLimiter } from '../safety/safety-gate.js';
import type { TrustLevelStore } from '../safety/trust-level.js';
import type { RollbackStore } from '../execution/rollback-registry.js';
import type { ExecutionStore } from '../execution/action-executor.js';
import type { ConnectorCredentials } from '../execution/action-executor.js';
import type { DatabaseClient } from '../memory/memory-store.js';

// ============================================================================
// In-memory implementations for prototype
// ============================================================================

/** Simple in-memory audit log — logs to console + stores in array */
class InMemoryAuditLog implements AuditLogWriter {
  readonly entries: unknown[] = [];

  async writeEntry(entry: Parameters<AuditLogWriter['writeEntry']>[0]): Promise<void> {
    this.entries.push({ ...entry, logged_at: new Date().toISOString() });
    // Also log to console so you can see AI decisions in the server window
    const actor = entry.actor?.type === 'AI' ? '🤖 AI' : '👤 Human';
    console.log(`[Audit] ${actor} | ${entry.event_type} | ${entry.action_taken}`);
    if (entry.ai_explanation) {
      console.log(`[AI]   ${entry.ai_explanation}`);
    }
  }
}

/** In-memory rate limiter — allows up to 10 write actions per minute */
class InMemoryRateLimiter implements RateLimiter {
  private counts = new Map<string, { count: number; resetAt: number }>();

  async checkAndIncrement(tenantId: string): Promise<boolean> {
    const now = Date.now();
    const window = this.counts.get(tenantId);

    if (!window || now > window.resetAt) {
      this.counts.set(tenantId, { count: 1, resetAt: now + 60_000 });
      return true;
    }

    if (window.count >= 10) return false;
    window.count++;
    return true;
  }

  async getCurrentCount(tenantId: string): Promise<number> {
    return this.counts.get(tenantId)?.count ?? 0;
  }
}

/** In-memory trust level store */
class InMemoryTrustStore implements TrustLevelStore {
  private records = new Map<string, import('../types/index.js').TenantTrustRecord>();

  async getRecord(tenantId: string) {
    return this.records.get(tenantId) ?? null;
  }

  async upsertRecord(record: import('../types/index.js').TenantTrustRecord) {
    this.records.set(record.tenant_id, record);
  }
}

/** In-memory rollback store */
class InMemoryRollbackStore implements RollbackStore {
  private entries = new Map<string, import('../execution/rollback-registry.js').RollbackEntry>();
  private byExecId = new Map<string, import('../execution/rollback-registry.js').RollbackEntry>();

  async save(entry: import('../execution/rollback-registry.js').RollbackEntry) {
    this.entries.set(`${entry.tenant_id}:${entry.id}`, entry);
    this.byExecId.set(`${entry.tenant_id}:${entry.execution_record_id}`, entry);
  }

  async getById(id: string, tenantId: string) {
    return this.entries.get(`${tenantId}:${id}`) ?? null;
  }

  async getByExecutionRecordId(execId: string, tenantId: string) {
    return this.byExecId.get(`${tenantId}:${execId}`) ?? null;
  }

  async getAvailableByTenant(tenantId: string) {
    return [...this.entries.values()].filter(
      (e) => e.tenant_id === tenantId && e.status === 'AVAILABLE'
    );
  }

  async updateStatus(
    id: string,
    tenantId: string,
    status: import('../execution/rollback-registry.js').RollbackStatus,
    executedAt?: string,
    executedBy?: string
  ) {
    const key = `${tenantId}:${id}`;
    const entry = this.entries.get(key);
    if (entry) {
      const updated = { ...entry, status, ...(executedAt && { executed_at: executedAt }), ...(executedBy && { executed_by: executedBy }) };
      this.entries.set(key, updated);
    }
  }
}

/** In-memory execution store */
class InMemoryExecutionStore implements ExecutionStore {
  private records = new Map<string, import('../types/index.js').ExecutionRecord>();

  async save(record: import('../types/index.js').ExecutionRecord) {
    this.records.set(`${record.tenant_id}:${record.id}`, record);
  }

  async update(id: string, tenantId: string, updates: Partial<import('../types/index.js').ExecutionRecord>) {
    const key = `${tenantId}:${id}`;
    const existing = this.records.get(key);
    if (existing) this.records.set(key, { ...existing, ...updates });
  }

  async getById(id: string, tenantId: string) {
    return this.records.get(`${tenantId}:${id}`) ?? null;
  }

  async getByPlanId(planId: string, tenantId: string) {
    return [...this.records.values()].filter(
      (r) => r.tenant_id === tenantId && r.action_plan_id === planId
    );
  }
}

/** AWS API client — uses real AWS SDK calls via assumed-role credentials */
import { RealAwsApiClient } from '../connectors/aws-connector.js';

/** Connector credentials — returns the real role ARN from registered connectors */
class RealConnectorCredentials implements ConnectorCredentials {
  async getRoleArn(connectorId: string, _tenantId: string): Promise<string | null> {
    const { getConnectors } = await import('../pipeline/polling-loop.js');
    const connector = getConnectors().find((c) => c.id === connectorId);
    return connector?.role_arn ?? null;
  }
}

/** In-memory database client for MemoryStore */
class InMemoryDbClient implements DatabaseClient {
  private tables = new Map<string, Map<string, Record<string, unknown>>>();

  private getTable(table: string) {
    if (!this.tables.has(table)) this.tables.set(table, new Map());
    return this.tables.get(table)!;
  }

  async insert(table: string, record: Record<string, unknown>) {
    const key = `${record['tenant_id']}:${record['id']}`;
    this.getTable(table).set(key, { ...record });
  }

  async findById(table: string, id: string, tenantId: string) {
    return this.getTable(table).get(`${tenantId}:${id}`) ?? null;
  }

  async findByTenantId(table: string, tenantId: string, opts?: { limit?: number; offset?: number }) {
    const results = [...this.getTable(table).values()].filter((r) => r['tenant_id'] === tenantId);
    const offset = opts?.offset ?? 0;
    const limit = opts?.limit ?? results.length;
    return results.slice(offset, offset + limit);
  }

  async update(table: string, id: string, tenantId: string, updates: Record<string, unknown>) {
    const key = `${tenantId}:${id}`;
    const existing = this.getTable(table).get(key);
    if (existing) this.getTable(table).set(key, { ...existing, ...updates });
  }

  async deleteByTenantId(table: string, tenantId: string) {
    const t = this.getTable(table);
    let count = 0;
    for (const [k, r] of t.entries()) {
      if (r['tenant_id'] === tenantId) { t.delete(k); count++; }
    }
    return count;
  }
}

// ============================================================================
// Default tenant config
// ============================================================================

function makeDefaultTenantConfig(tenantId: string): TenantConfig {
  return {
    tenant_id: tenantId,
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
  };
}

// ============================================================================
// Context providers backed by in-memory stores
// ============================================================================

const memoryLayerConfig = loadMemoryLayerConfig();
const memoryLayer = new MemoryLayer(memoryLayerConfig);
const incidentStore = new InMemoryIncidentStore();
const tenantConfigs = new Map<string, TenantConfig>();
const recentEvents: import('../types/index.js').NormalizedEvent[] = [];

const envProvider: EnvironmentContextProvider = {
  async assembleContext(tenantId, accountId, relevantResourceIds) {
    return {
      tenant_id: tenantId,
      account_id: accountId,
      total_assets: 0,
      critical_assets: [],
      recent_config_changes: [],
      active_incidents_count: 0,
      assembled_at: new Date().toISOString(),
    };
  },
};

const memoryProvider: MemoryProvider = memoryLayer;

const toolProvider: ToolCapabilityProvider = {
  async getCapabilitiesForTenant(_tenantId) {
    // Build tool capabilities from registered connectors
    const { getConnectors } = await import('../pipeline/polling-loop.js');
    const { BlastRadius } = await import('../types/index.js');
    const registeredConnectors = getConnectors();

    if (registeredConnectors.length === 0) return [];

    return registeredConnectors
      .filter((c) => c.status === 'ACTIVE')
      .map((c) => ({
        connector_id: c.id,
        tenant_id: c.tenant_id,
        tool_type: 'AWS' as const,
        account_id: c.account_id,
        region: c.regions[0] ?? 'us-east-1',
        readable_sources: c.data_sources,
        writable_actions: [
          {
            action_id: 'aws:iam:disable-access-key',
            description: 'Disable an IAM access key (revoke without deleting)',
            aws_service: 'iam',
            aws_api_call: 'UpdateAccessKey',
            required_params: ['UserName', 'AccessKeyId', 'Status'],
            blast_radius: BlastRadius.LOW,
            reversible: true,
            rollback_api_call: 'UpdateAccessKey',
          },
          {
            action_id: 'aws:ec2:stop-instance',
            description: 'Stop an EC2 instance',
            aws_service: 'ec2',
            aws_api_call: 'StopInstances',
            required_params: ['InstanceIds'],
            blast_radius: BlastRadius.MEDIUM,
            reversible: true,
            rollback_api_call: 'StartInstances',
          },
          {
            action_id: 'aws:ec2:revoke-sg-ingress',
            description: 'Remove an inbound rule from a security group to block traffic',
            aws_service: 'ec2',
            aws_api_call: 'RevokeSecurityGroupIngress',
            required_params: ['GroupId', 'IpPermissions'],
            blast_radius: BlastRadius.MEDIUM,
            reversible: true,
            rollback_api_call: 'AuthorizeSecurityGroupIngress',
          },
          {
            action_id: 'aws:iam:attach-deny-policy',
            description: 'Attach an explicit deny policy to block all actions for a user',
            aws_service: 'iam',
            aws_api_call: 'AttachUserPolicy',
            required_params: ['UserName', 'PolicyArn'],
            blast_radius: BlastRadius.MEDIUM,
            reversible: true,
            rollback_api_call: 'DetachUserPolicy',
          },
          {
            action_id: 'aws:ec2:create-snapshot',
            description: 'Create a snapshot of an EBS volume for forensic preservation',
            aws_service: 'ec2',
            aws_api_call: 'CreateSnapshot',
            required_params: ['VolumeId'],
            blast_radius: BlastRadius.LOW,
            reversible: false,
          },
        ],
        discovered_at: c.registered_at,
        last_updated: c.last_poll_at ?? c.registered_at,
      }));
  },
};

const configProvider: TenantConfigProvider = {
  async getConfig(tenantId) {
    if (!tenantConfigs.has(tenantId)) {
      tenantConfigs.set(tenantId, makeDefaultTenantConfig(tenantId));
    }
    return tenantConfigs.get(tenantId)!;
  },
};

const eventsProvider: RecentEventsProvider = {
  async getRecentEvents(_tenantId, limit) {
    return recentEvents.slice(-limit);
  },
};

// ============================================================================
// Build the pipeline
// ============================================================================

const region = process.env['AWS_REGION'] ?? 'us-east-1';
const auditLog = new InMemoryAuditLog();
const bedrockInvoker = new AwsBedrockInvoker(region);
const reasoningEngine = new ReasoningEngine(bedrockInvoker, {
  primaryModel: BEDROCK_MODELS.CLAUDE_SONNET_46,
  region,
});

const contextAssembler = new ContextAssembler(
  envProvider,
  memoryProvider,
  toolProvider,
  configProvider,
  eventsProvider
);

const safetyGate = new SafetyGate(new InMemoryRateLimiter());
const trustLevelService = new TrustLevelService(new InMemoryTrustStore());
const rollbackRegistry = new RollbackRegistry(new InMemoryRollbackStore());

const actionExecutor = new ActionExecutor(
  new RealAwsApiClient(),
  new RealConnectorCredentials(),
  rollbackRegistry,
  auditLog,
  new InMemoryExecutionStore(),
  { maxRetries: 1, retryDelayMs: 1000 }
);

const approvalWorkflow = new InMemoryApprovalWorkflow(auditLog, new NoopApprovalNotifier());

export const pipeline = new EventPipeline({
  contextAssembler,
  reasoningEngine,
  safetyGate,
  trustLevelService,
  actionExecutor,
  incidentStore,
  approvalWorkflow,
  auditLog,
  fastFilter: new HeuristicFastFilter('MEDIUM'),
  config: { skipFastFilter: true }, // Skip filter for webhook events — treat all as interesting
});

// Initialize the memory layer (connects to Supermemory or enters fallback mode)
memoryLayer.initialize().catch((err) => {
  console.error('[Pipeline] Failed to initialize MemoryLayer:', err);
});

export { incidentStore, approvalWorkflow, auditLog, memoryLayer };

export async function shutdownPipeline(): Promise<void> {
  await memoryLayer.shutdown();
}
