/**
 * Environment Model
 *
 * Maintains a live, continuously-updated representation of a tenant's AWS
 * infrastructure. This is the AI's situational awareness — it needs to
 * understand the environment to reason about threats in context.
 *
 * Without this, the AI can detect "something bad happened" but cannot reason
 * about "how bad is this for THIS customer" or "what's the right response
 * given THEIR infrastructure."
 *
 * What it tracks:
 * - Assets (EC2, IAM users/roles, S3 buckets, RDS, Lambda, etc.)
 * - Relationships (IAM permissions, network reachability, data flows)
 * - Behavioral baselines (what's normal per asset and per user)
 * - Configuration state (encryption, public exposure, known CVEs)
 */

import {
  EnvironmentAsset,
  AssetRelationship,
  BehavioralBaseline,
  EnvironmentContext,
  AttackSurface,
  NormalizedEvent,
} from '../types/index.js';

// ============================================================================
// Storage Interface
// ============================================================================

/**
 * Persistence interface for the environment model.
 * Swap for real DynamoDB/PostgreSQL/Neptune in production.
 */
export interface EnvironmentStore {
  // Assets
  upsertAsset(asset: EnvironmentAsset): Promise<void>;
  getAsset(tenantId: string, resourceId: string): Promise<EnvironmentAsset | null>;
  getAssetsByTenant(tenantId: string): Promise<EnvironmentAsset[]>;
  getAssetsBySurface(tenantId: string, surface: AttackSurface): Promise<EnvironmentAsset[]>;
  getCriticalAssets(tenantId: string, minCriticality: number): Promise<EnvironmentAsset[]>;
  deleteAsset(tenantId: string, resourceId: string): Promise<void>;

  // Relationships
  upsertRelationship(rel: AssetRelationship): Promise<void>;
  getRelationshipsForAsset(tenantId: string, assetId: string): Promise<AssetRelationship[]>;
  deleteRelationshipsByTenant(tenantId: string): Promise<void>;

  // Baselines
  upsertBaseline(baseline: BehavioralBaseline): Promise<void>;
  getBaseline(tenantId: string, entityId: string): Promise<BehavioralBaseline | null>;
  getBaselinesByTenant(tenantId: string): Promise<BehavioralBaseline[]>;
}

// ============================================================================
// AWS Resource Discovery Interface
// ============================================================================

/**
 * Interface for querying live AWS resource state.
 * In production this calls AWS APIs (EC2, IAM, S3, RDS, Lambda, etc.).
 * In tests this is mocked.
 */
export interface AwsResourceDiscovery {
  discoverAssets(accountId: string, region: string): Promise<DiscoveredAsset[]>;
  discoverRelationships(accountId: string, assets: EnvironmentAsset[]): Promise<DiscoveredRelationship[]>;
}

/** Raw asset data returned from AWS discovery. */
export interface DiscoveredAsset {
  resource_type: string;
  resource_id: string;       // ARN
  resource_name?: string;
  region: string;
  account_id: string;
  tags: Record<string, string>;
  is_public_facing: boolean;
  known_vulnerabilities: string[];
  raw_config: Record<string, unknown>;
}

/** Raw relationship data returned from AWS discovery. */
export interface DiscoveredRelationship {
  source_resource_id: string;
  target_resource_id: string;
  relationship_type: AssetRelationship['relationship_type'];
  description: string;
  is_overprivileged: boolean;
}

// ============================================================================
// Criticality Scoring
// ============================================================================

/**
 * Assigns a criticality score (1–10) to an asset based on its type and tags.
 *
 * Rules (highest wins):
 * - Production-tagged resources: +3
 * - Internet-facing resources: +2
 * - Data stores (RDS, DynamoDB, S3): +2
 * - IAM roles/users with broad permissions: +2
 * - Dev/test-tagged resources: -2
 */
export function scoreAssetCriticality(
  resourceType: string,
  tags: Record<string, string>,
  isPublicFacing: boolean
): number {
  let score = 5; // baseline

  const rt = resourceType.toLowerCase();
  const env = (tags['Environment'] ?? tags['environment'] ?? tags['env'] ?? '').toLowerCase();
  const name = (tags['Name'] ?? tags['name'] ?? '').toLowerCase();

  // Environment tag adjustments
  if (env.includes('prod') || env.includes('production')) score += 3;
  else if (env.includes('dev') || env.includes('test') || env.includes('staging')) score -= 2;

  // Name-based heuristics
  if (name.includes('prod') || name.includes('production')) score += 2;
  if (name.includes('dev') || name.includes('test')) score -= 1;

  // Resource type adjustments
  if (rt.includes('rds') || rt.includes('dynamodb') || rt.includes('redshift')) score += 2;
  if (rt.includes('s3')) score += 1;
  if (rt.includes('iam::role') || rt.includes('iam::user')) score += 1;
  if (rt.includes('secretsmanager') || rt.includes('kms')) score += 2;

  // Public exposure
  if (isPublicFacing) score += 2;

  return Math.max(1, Math.min(10, score));
}

/**
 * Infers the AttackSurface for a resource type string.
 * Mirrors the logic in aws-normalizer.ts but kept local to avoid circular deps.
 */
export function inferSurface(resourceType: string): AttackSurface {
  const rt = resourceType.toLowerCase();
  if (rt.includes('iam') || rt.includes('sts')) return AttackSurface.CLOUD_IAM;
  if (rt.includes('vpc') || rt.includes('elasticloadbalancing') || rt.includes('route53') ||
      rt.includes('cloudfront') || rt.includes('subnet')) return AttackSurface.CLOUD_NETWORK;
  if (rt.includes('ec2') || rt.includes('autoscaling')) return AttackSurface.CLOUD_COMPUTE;
  if (rt.includes('s3') || rt.includes('glacier')) return AttackSurface.CLOUD_STORAGE;
  if (rt.includes('lambda') || rt.includes('apigateway') || rt.includes('sqs') || rt.includes('sns')) return AttackSurface.CLOUD_SERVERLESS;
  if (rt.includes('rds') || rt.includes('dynamodb') || rt.includes('redshift') || rt.includes('elasticache')) return AttackSurface.CLOUD_DATABASE;
  if (rt.includes('eks') || rt.includes('ecs') || rt.includes('ecr')) return AttackSurface.CLOUD_CONTAINER;
  if (rt.includes('codepipeline') || rt.includes('codebuild') || rt.includes('codecommit')) return AttackSurface.CLOUD_CICD;
  return AttackSurface.CLOUD_IAM;
}

// ============================================================================
// Baseline Updater
// ============================================================================

/**
 * Updates a behavioral baseline from a new normalized event.
 * Called every time an event is processed for an asset or user.
 */
export function updateBaselineFromEvent(
  existing: BehavioralBaseline | null,
  event: NormalizedEvent,
  entityId: string,
  entityType: 'ASSET' | 'USER'
): BehavioralBaseline {
  const now = new Date().toISOString();
  const hour = new Date().getUTCHours();

  if (!existing) {
    // Cold start — create a new baseline from this first event
    return {
      entity_id: entityId,
      entity_type: entityType,
      tenant_id: event.tenant_id,
      typical_api_calls: [event.event_type],
      typical_source_ips: event.source_ip ? [event.source_ip] : [],
      typical_regions: [event.region],
      typical_active_hours_utc: [hour],
      typical_data_volume_mb_per_day: 0,
      lookback_days: 0,
      established: false,
      last_updated: now,
    };
  }

  // Merge new observations into existing baseline
  const apiCalls = addUnique(existing.typical_api_calls, event.event_type, 50);
  const sourceIps = event.source_ip
    ? addUnique(existing.typical_source_ips, event.source_ip, 20)
    : existing.typical_source_ips;
  const regions = addUnique(existing.typical_regions, event.region, 10);
  const hours = addUnique(existing.typical_active_hours_utc, hour, 24);

  // Mark as established after 30 days
  const daysSinceCreation = existing.lookback_days + 1;
  const established = daysSinceCreation >= 30;

  return {
    ...existing,
    typical_api_calls: apiCalls,
    typical_source_ips: sourceIps,
    typical_regions: regions,
    typical_active_hours_utc: hours,
    lookback_days: daysSinceCreation,
    established,
    last_updated: now,
  };
}

/** Adds a value to an array if not already present, capped at maxSize. */
function addUnique<T>(arr: T[], value: T, maxSize: number): T[] {
  if (arr.includes(value)) return arr;
  const updated = [...arr, value];
  return updated.length > maxSize ? updated.slice(-maxSize) : updated;
}

// ============================================================================
// Anomaly Detection Helpers
// ============================================================================

export interface BaselineDeviationResult {
  is_anomalous: boolean;
  deviation_score: number;   // 0–100, higher = more anomalous
  reasons: string[];
}

/**
 * Compares an event against a behavioral baseline and returns a deviation score.
 * Used by the AI as one input to its reasoning — not a detection rule itself.
 */
export function computeBaselineDeviation(
  event: NormalizedEvent,
  baseline: BehavioralBaseline | null
): BaselineDeviationResult {
  if (!baseline || !baseline.established) {
    return {
      is_anomalous: false,
      deviation_score: 0,
      reasons: ['No established baseline — insufficient history'],
    };
  }

  const reasons: string[] = [];
  let score = 0;

  // New API call type never seen before
  if (!baseline.typical_api_calls.includes(event.event_type)) {
    score += 25;
    reasons.push(`New API call type: ${event.event_type}`);
  }

  // Source IP never seen before
  if (event.source_ip && !baseline.typical_source_ips.includes(event.source_ip)) {
    score += 30;
    reasons.push(`New source IP: ${event.source_ip}`);
  }

  // New region never seen before
  if (!baseline.typical_regions.includes(event.region)) {
    score += 20;
    reasons.push(`New region: ${event.region}`);
  }

  // Unusual hour (not in typical active hours)
  const hour = new Date().getUTCHours();
  if (baseline.typical_active_hours_utc.length > 0 &&
      !baseline.typical_active_hours_utc.includes(hour)) {
    score += 15;
    reasons.push(`Unusual hour: ${hour}:00 UTC`);
  }

  const finalScore = Math.min(100, score);
  return {
    is_anomalous: finalScore >= 40,
    deviation_score: finalScore,
    reasons,
  };
}

// ============================================================================
// Environment Model Service
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

/**
 * The Environment Model service.
 * Manages the full lifecycle of environment data for a tenant:
 * - Full refresh from AWS APIs (scheduled daily)
 * - Incremental updates from ingested events (real-time)
 * - Behavioral baseline tracking (per asset and user)
 * - Context assembly for AI reasoning requests
 */
export class EnvironmentModelService {
  private readonly store: EnvironmentStore;
  private readonly discovery: AwsResourceDiscovery;

  /** Minimum criticality to include in AI context as "critical asset". */
  private static readonly CRITICAL_ASSET_THRESHOLD = 7;

  /** Max recent config changes to include in AI context. */
  private static readonly MAX_RECENT_CHANGES = 20;

  constructor(store: EnvironmentStore, discovery: AwsResourceDiscovery) {
    this.store = store;
    this.discovery = discovery;
  }

  // ── Full Refresh ────────────────────────────────────────────────────────────

  /**
   * Performs a full discovery of all assets and relationships in an AWS account.
   * Scheduled to run every 24 hours per tenant.
   * Returns counts of assets and relationships discovered.
   */
  async fullRefresh(
    tenantId: string,
    accountId: string,
    region: string
  ): Promise<RefreshResult> {
    const discoveredAssets = await this.discovery.discoverAssets(accountId, region);
    const now = new Date().toISOString();

    // Upsert all discovered assets
    const assets: EnvironmentAsset[] = [];
    for (const raw of discoveredAssets) {
      const asset: EnvironmentAsset = {
        id: generateId(),
        tenant_id: tenantId,
        account_id: raw.account_id,
        region: raw.region,
        resource_type: raw.resource_type,
        resource_id: raw.resource_id,
        resource_name: raw.resource_name,
        attack_surface: inferSurface(raw.resource_type),
        criticality: scoreAssetCriticality(raw.resource_type, raw.tags, raw.is_public_facing),
        tags: raw.tags,
        is_public_facing: raw.is_public_facing,
        known_vulnerabilities: raw.known_vulnerabilities,
        last_seen: now,
        created_at: now,
      };
      await this.store.upsertAsset(asset);
      assets.push(asset);
    }

    // Discover and upsert relationships
    const discoveredRels = await this.discovery.discoverRelationships(accountId, assets);
    for (const raw of discoveredRels) {
      const rel: AssetRelationship = {
        id: generateId(),
        tenant_id: tenantId,
        source_asset_id: raw.source_resource_id,
        target_asset_id: raw.target_resource_id,
        relationship_type: raw.relationship_type,
        description: raw.description,
        is_overprivileged: raw.is_overprivileged,
        created_at: now,
      };
      await this.store.upsertRelationship(rel);
    }

    return {
      assets_discovered: assets.length,
      relationships_discovered: discoveredRels.length,
      refreshed_at: now,
    };
  }

  // ── Incremental Update ──────────────────────────────────────────────────────

  /**
   * Processes a normalized event to update the environment model incrementally.
   * Called for every event that passes the fast filter.
   * Updates: asset last_seen, behavioral baselines.
   */
  async processEvent(event: NormalizedEvent): Promise<void> {
    // Update asset last_seen
    const existing = await this.store.getAsset(event.tenant_id, event.target.resource_id);
    if (existing) {
      await this.store.upsertAsset({
        ...existing,
        last_seen: event.ingestion_timestamp,
      });
    }

    // Update behavioral baseline for the target asset
    await this.updateBaseline(
      event,
      event.target.resource_id,
      'ASSET'
    );

    // Update behavioral baseline for the actor (user/role)
    if (event.actor.identifier && event.actor.identifier !== 'unknown') {
      await this.updateBaseline(
        event,
        event.actor.identifier,
        'USER'
      );
    }
  }

  private async updateBaseline(
    event: NormalizedEvent,
    entityId: string,
    entityType: 'ASSET' | 'USER'
  ): Promise<void> {
    const existing = await this.store.getBaseline(event.tenant_id, entityId);
    const updated = updateBaselineFromEvent(existing, event, entityId, entityType);
    await this.store.upsertBaseline(updated);
  }

  // ── Asset Queries ───────────────────────────────────────────────────────────

  async getAsset(tenantId: string, resourceId: string): Promise<EnvironmentAsset | null> {
    return this.store.getAsset(tenantId, resourceId);
  }

  async getAllAssets(tenantId: string): Promise<EnvironmentAsset[]> {
    return this.store.getAssetsByTenant(tenantId);
  }

  async getAssetsBySurface(tenantId: string, surface: AttackSurface): Promise<EnvironmentAsset[]> {
    return this.store.getAssetsBySurface(tenantId, surface);
  }

  async getCriticalAssets(tenantId: string): Promise<EnvironmentAsset[]> {
    return this.store.getCriticalAssets(tenantId, EnvironmentModelService.CRITICAL_ASSET_THRESHOLD);
  }

  async getRelationshipsForAsset(tenantId: string, assetId: string): Promise<AssetRelationship[]> {
    return this.store.getRelationshipsForAsset(tenantId, assetId);
  }

  // ── Baseline Queries ────────────────────────────────────────────────────────

  async getBaseline(tenantId: string, entityId: string): Promise<BehavioralBaseline | null> {
    return this.store.getBaseline(tenantId, entityId);
  }

  async getDeviationForEvent(
    event: NormalizedEvent
  ): Promise<BaselineDeviationResult> {
    const baseline = await this.store.getBaseline(event.tenant_id, event.actor.identifier);
    return computeBaselineDeviation(event, baseline);
  }

  // ── Context Assembly ────────────────────────────────────────────────────────

  /**
   * Assembles an EnvironmentContext for the AI Reasoning Engine.
   * Called before every reasoning request to give the AI situational awareness.
   *
   * Returns a focused slice of the environment — not everything, just what's
   * relevant for reasoning about the current event or threat.
   */
  async assembleContext(
    tenantId: string,
    accountId: string,
    relevantResourceIds?: string[]
  ): Promise<EnvironmentContext> {
    const now = new Date().toISOString();

    const [allAssets, criticalAssets] = await Promise.all([
      this.store.getAssetsByTenant(tenantId),
      this.store.getCriticalAssets(tenantId, EnvironmentModelService.CRITICAL_ASSET_THRESHOLD),
    ]);

    // If specific resources are relevant (e.g. the asset in the current event),
    // include their neighbors too
    let contextAssets = criticalAssets;
    if (relevantResourceIds && relevantResourceIds.length > 0) {
      const relevantAssets = allAssets.filter((a) =>
        relevantResourceIds.includes(a.resource_id)
      );
      // Merge without duplicates
      const seen = new Set(contextAssets.map((a) => a.resource_id));
      for (const asset of relevantAssets) {
        if (!seen.has(asset.resource_id)) {
          contextAssets.push(asset);
          seen.add(asset.resource_id);
        }
      }
    }

    // Recent config changes = assets updated in the last 2 hours
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    const recentChanges = allAssets
      .filter((a) => a.last_seen >= twoHoursAgo)
      .map((a) => `${a.resource_type}:${a.resource_name ?? a.resource_id}`)
      .slice(0, EnvironmentModelService.MAX_RECENT_CHANGES);

    return {
      tenant_id: tenantId,
      account_id: accountId,
      total_assets: allAssets.length,
      critical_assets: contextAssets,
      recent_config_changes: recentChanges,
      active_incidents_count: 0, // populated by the caller from incident store
      assembled_at: now,
    };
  }
}

// ============================================================================
// Supporting Types
// ============================================================================

export interface RefreshResult {
  assets_discovered: number;
  relationships_discovered: number;
  refreshed_at: string;
}
