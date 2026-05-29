/**
 * Tests for the Environment Model service.
 * Covers asset scoring, baseline tracking, deviation detection,
 * full refresh, incremental updates, and context assembly.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  EnvironmentModelService,
  EnvironmentStore,
  AwsResourceDiscovery,
  DiscoveredAsset,
  DiscoveredRelationship,
  scoreAssetCriticality,
  inferSurface,
  updateBaselineFromEvent,
  computeBaselineDeviation,
} from './environment-model.js';
import {
  EnvironmentAsset,
  AssetRelationship,
  BehavioralBaseline,
  AttackSurface,
  NormalizedEvent,
  AwsDataSource,
} from '../types/index.js';

// ── Mock Store ────────────────────────────────────────────────────────────────

function createMockStore(): EnvironmentStore & {
  assets: Map<string, EnvironmentAsset>;
  relationships: Map<string, AssetRelationship>;
  baselines: Map<string, BehavioralBaseline>;
} {
  const assets = new Map<string, EnvironmentAsset>();
  const relationships = new Map<string, AssetRelationship>();
  const baselines = new Map<string, BehavioralBaseline>();

  const assetKey = (tid: string, rid: string) => `${tid}:${rid}`;
  const baselineKey = (tid: string, eid: string) => `${tid}:${eid}`;

  return {
    assets, relationships, baselines,

    async upsertAsset(asset) { assets.set(assetKey(asset.tenant_id, asset.resource_id), asset); },
    async getAsset(tid, rid) { return assets.get(assetKey(tid, rid)) ?? null; },
    async getAssetsByTenant(tid) { return [...assets.values()].filter(a => a.tenant_id === tid); },
    async getAssetsBySurface(tid, surface) {
      return [...assets.values()].filter(a => a.tenant_id === tid && a.attack_surface === surface);
    },
    async getCriticalAssets(tid, min) {
      return [...assets.values()].filter(a => a.tenant_id === tid && a.criticality >= min);
    },
    async deleteAsset(tid, rid) { assets.delete(assetKey(tid, rid)); },

    async upsertRelationship(rel) { relationships.set(rel.id, rel); },
    async getRelationshipsForAsset(tid, assetId) {
      return [...relationships.values()].filter(
        r => r.tenant_id === tid && (r.source_asset_id === assetId || r.target_asset_id === assetId)
      );
    },
    async deleteRelationshipsByTenant(tid) {
      for (const [k, r] of relationships.entries()) {
        if (r.tenant_id === tid) relationships.delete(k);
      }
    },

    async upsertBaseline(b) { baselines.set(baselineKey(b.tenant_id, b.entity_id), b); },
    async getBaseline(tid, eid) { return baselines.get(baselineKey(tid, eid)) ?? null; },
    async getBaselinesByTenant(tid) { return [...baselines.values()].filter(b => b.tenant_id === tid); },
  };
}

// ── Mock Discovery ────────────────────────────────────────────────────────────

function createMockDiscovery(
  assets: DiscoveredAsset[] = [],
  relationships: DiscoveredRelationship[] = []
): AwsResourceDiscovery {
  return {
    discoverAssets: vi.fn(async () => assets),
    discoverRelationships: vi.fn(async () => relationships),
  };
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeDiscoveredAsset(overrides?: Partial<DiscoveredAsset>): DiscoveredAsset {
  return {
    resource_type: 'AWS::IAM::User',
    resource_id: 'arn:aws:iam::123456789012:user/alice',
    resource_name: 'alice',
    region: 'us-east-1',
    account_id: '123456789012',
    tags: { Environment: 'production', Name: 'alice' },
    is_public_facing: false,
    known_vulnerabilities: [],
    raw_config: {},
    ...overrides,
  };
}

function makeNormalizedEvent(overrides?: Partial<NormalizedEvent>): NormalizedEvent {
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
    source_ip: '203.0.113.1',
    raw_payload: {},
    ingestion_timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeEstablishedBaseline(overrides?: Partial<BehavioralBaseline>): BehavioralBaseline {
  return {
    entity_id: 'arn:aws:iam::123456789012:user/alice',
    entity_type: 'USER',
    tenant_id: 'tenant-abc',
    typical_api_calls: ['iam:GetUser', 'iam:ListAccessKeys', 'iam:CreateAccessKey'],
    typical_source_ips: ['10.0.0.1', '10.0.0.2'],
    typical_regions: ['us-east-1'],
    typical_active_hours_utc: [9, 10, 11, 12, 13, 14, 15, 16, 17],
    typical_data_volume_mb_per_day: 10,
    lookback_days: 45,
    established: true,
    last_updated: new Date().toISOString(),
    ...overrides,
  };
}

// ── scoreAssetCriticality ─────────────────────────────────────────────────────

describe('scoreAssetCriticality', () => {
  it('gives production-tagged resources a higher score', () => {
    const prod = scoreAssetCriticality('AWS::EC2::Instance', { Environment: 'production' }, false);
    const dev = scoreAssetCriticality('AWS::EC2::Instance', { Environment: 'development' }, false);
    expect(prod).toBeGreaterThan(dev);
  });

  it('gives public-facing resources a higher score', () => {
    const pub = scoreAssetCriticality('AWS::EC2::Instance', {}, true);
    const priv = scoreAssetCriticality('AWS::EC2::Instance', {}, false);
    expect(pub).toBeGreaterThan(priv);
  });

  it('gives data stores a higher score than compute', () => {
    const rds = scoreAssetCriticality('AWS::RDS::DBInstance', {}, false);
    const ec2 = scoreAssetCriticality('AWS::EC2::Instance', {}, false);
    expect(rds).toBeGreaterThan(ec2);
  });

  it('gives secrets manager resources a high score', () => {
    const secret = scoreAssetCriticality('AWS::SecretsManager::Secret', { Environment: 'production' }, false);
    expect(secret).toBeGreaterThanOrEqual(8);
  });

  it('always returns a score between 1 and 10', () => {
    const cases = [
      ['AWS::EC2::Instance', { Environment: 'production' }, true],
      ['AWS::S3::Bucket', { Environment: 'dev' }, false],
      ['AWS::IAM::Role', {}, false],
      ['AWS::RDS::DBInstance', { Environment: 'production' }, true],
    ] as const;

    for (const [rt, tags, pub] of cases) {
      const score = scoreAssetCriticality(rt, tags as Record<string, string>, pub);
      expect(score).toBeGreaterThanOrEqual(1);
      expect(score).toBeLessThanOrEqual(10);
    }
  });

  it('dev-tagged resources score lower than baseline', () => {
    const dev = scoreAssetCriticality('AWS::EC2::Instance', { Environment: 'dev' }, false);
    expect(dev).toBeLessThan(5);
  });
});

// ── inferSurface ──────────────────────────────────────────────────────────────

describe('inferSurface', () => {
  it('correctly maps resource types to attack surfaces', () => {
    expect(inferSurface('AWS::IAM::User')).toBe(AttackSurface.CLOUD_IAM);
    expect(inferSurface('AWS::EC2::Instance')).toBe(AttackSurface.CLOUD_COMPUTE);
    expect(inferSurface('AWS::S3::Bucket')).toBe(AttackSurface.CLOUD_STORAGE);
    expect(inferSurface('AWS::RDS::DBInstance')).toBe(AttackSurface.CLOUD_DATABASE);
    expect(inferSurface('AWS::Lambda::Function')).toBe(AttackSurface.CLOUD_SERVERLESS);
    expect(inferSurface('AWS::EKS::Cluster')).toBe(AttackSurface.CLOUD_CONTAINER);
    expect(inferSurface('AWS::CodePipeline::Pipeline')).toBe(AttackSurface.CLOUD_CICD);
    expect(inferSurface('AWS::EC2::VPC')).toBe(AttackSurface.CLOUD_NETWORK);
  });
});

// ── updateBaselineFromEvent ───────────────────────────────────────────────────

describe('updateBaselineFromEvent', () => {
  it('creates a cold-start baseline when no existing baseline', () => {
    const event = makeNormalizedEvent();
    const result = updateBaselineFromEvent(null, event, 'arn:aws:iam::123456789012:user/alice', 'USER');

    expect(result.entity_id).toBe('arn:aws:iam::123456789012:user/alice');
    expect(result.entity_type).toBe('USER');
    expect(result.tenant_id).toBe('tenant-abc');
    expect(result.typical_api_calls).toContain('iam:CreateAccessKey');
    expect(result.typical_source_ips).toContain('203.0.113.1');
    expect(result.typical_regions).toContain('us-east-1');
    expect(result.established).toBe(false);
    expect(result.lookback_days).toBe(0);
  });

  it('merges new observations into existing baseline', () => {
    const existing = makeEstablishedBaseline({
      typical_api_calls: ['iam:GetUser'],
      typical_source_ips: ['10.0.0.1'],
    });
    const event = makeNormalizedEvent({ event_type: 'iam:CreateUser', source_ip: '10.0.0.5' });

    const result = updateBaselineFromEvent(existing, event, existing.entity_id, 'USER');

    expect(result.typical_api_calls).toContain('iam:GetUser');
    expect(result.typical_api_calls).toContain('iam:CreateUser');
    expect(result.typical_source_ips).toContain('10.0.0.1');
    expect(result.typical_source_ips).toContain('10.0.0.5');
  });

  it('does not duplicate existing values', () => {
    const existing = makeEstablishedBaseline({
      typical_api_calls: ['iam:GetUser', 'iam:CreateAccessKey'],
    });
    const event = makeNormalizedEvent({ event_type: 'iam:GetUser' });

    const result = updateBaselineFromEvent(existing, event, existing.entity_id, 'USER');

    const count = result.typical_api_calls.filter((c) => c === 'iam:GetUser').length;
    expect(count).toBe(1);
  });

  it('marks baseline as established after 30 days', () => {
    const existing = makeEstablishedBaseline({ lookback_days: 29, established: false });
    const event = makeNormalizedEvent();

    const result = updateBaselineFromEvent(existing, event, existing.entity_id, 'USER');

    expect(result.established).toBe(true);
    expect(result.lookback_days).toBe(30);
  });

  it('handles events with no source IP', () => {
    const event = makeNormalizedEvent({ source_ip: undefined });
    const result = updateBaselineFromEvent(null, event, 'entity-1', 'ASSET');

    expect(result.typical_source_ips).toHaveLength(0);
  });

  it('caps api_calls list at 50 entries', () => {
    const existing = makeEstablishedBaseline({
      typical_api_calls: Array.from({ length: 50 }, (_, i) => `iam:Action${i}`),
    });
    const event = makeNormalizedEvent({ event_type: 'iam:NewAction' });

    const result = updateBaselineFromEvent(existing, event, existing.entity_id, 'USER');

    expect(result.typical_api_calls.length).toBeLessThanOrEqual(50);
    expect(result.typical_api_calls).toContain('iam:NewAction');
  });
});

// ── computeBaselineDeviation ──────────────────────────────────────────────────

describe('computeBaselineDeviation', () => {
  it('returns zero deviation when no baseline exists', () => {
    const event = makeNormalizedEvent();
    const result = computeBaselineDeviation(event, null);

    expect(result.deviation_score).toBe(0);
    expect(result.is_anomalous).toBe(false);
    expect(result.reasons[0]).toContain('No established baseline');
  });

  it('returns zero deviation when baseline is not yet established', () => {
    const baseline = makeEstablishedBaseline({ established: false });
    const event = makeNormalizedEvent();
    const result = computeBaselineDeviation(event, baseline);

    expect(result.deviation_score).toBe(0);
    expect(result.is_anomalous).toBe(false);
  });

  it('detects new API call type as anomalous', () => {
    const baseline = makeEstablishedBaseline({
      typical_api_calls: ['iam:GetUser', 'iam:ListAccessKeys'],
    });
    const event = makeNormalizedEvent({ event_type: 'iam:DeleteUser' });

    const result = computeBaselineDeviation(event, baseline);

    expect(result.deviation_score).toBeGreaterThan(0);
    expect(result.reasons.some((r) => r.includes('New API call type'))).toBe(true);
  });

  it('detects new source IP as anomalous', () => {
    const baseline = makeEstablishedBaseline({
      typical_source_ips: ['10.0.0.1', '10.0.0.2'],
    });
    const event = makeNormalizedEvent({ source_ip: '198.51.100.99' });

    const result = computeBaselineDeviation(event, baseline);

    expect(result.deviation_score).toBeGreaterThan(0);
    expect(result.reasons.some((r) => r.includes('New source IP'))).toBe(true);
  });

  it('detects new region as anomalous', () => {
    const baseline = makeEstablishedBaseline({ typical_regions: ['us-east-1'] });
    const event = makeNormalizedEvent({ region: 'ap-southeast-1' });

    const result = computeBaselineDeviation(event, baseline);

    expect(result.deviation_score).toBeGreaterThan(0);
    expect(result.reasons.some((r) => r.includes('New region'))).toBe(true);
  });

  it('marks event as anomalous when deviation score >= 40', () => {
    const baseline = makeEstablishedBaseline({
      typical_api_calls: ['iam:GetUser'],
      typical_source_ips: ['10.0.0.1'],
      typical_regions: ['us-east-1'],
    });
    // New API + new IP = 25 + 30 = 55 → anomalous
    const event = makeNormalizedEvent({
      event_type: 'iam:DeleteUser',
      source_ip: '198.51.100.99',
    });

    const result = computeBaselineDeviation(event, baseline);

    expect(result.is_anomalous).toBe(true);
    expect(result.deviation_score).toBeGreaterThanOrEqual(40);
  });

  it('returns no anomaly for fully expected behavior', () => {
    const baseline = makeEstablishedBaseline({
      typical_api_calls: ['iam:CreateAccessKey'],
      typical_source_ips: ['203.0.113.1'],
      typical_regions: ['us-east-1'],
    });
    const event = makeNormalizedEvent({
      event_type: 'iam:CreateAccessKey',
      source_ip: '203.0.113.1',
      region: 'us-east-1',
    });

    const result = computeBaselineDeviation(event, baseline);

    // Only possible anomaly is the hour — score should be low
    expect(result.deviation_score).toBeLessThan(40);
    expect(result.is_anomalous).toBe(false);
  });

  it('caps deviation score at 100', () => {
    const baseline = makeEstablishedBaseline({
      typical_api_calls: ['iam:GetUser'],
      typical_source_ips: ['10.0.0.1'],
      typical_regions: ['us-east-1'],
      typical_active_hours_utc: [9],
    });
    const event = makeNormalizedEvent({
      event_type: 'iam:DeleteUser',
      source_ip: '198.51.100.99',
      region: 'cn-north-1',
    });

    const result = computeBaselineDeviation(event, baseline);
    expect(result.deviation_score).toBeLessThanOrEqual(100);
  });
});

// ── EnvironmentModelService ───────────────────────────────────────────────────

describe('EnvironmentModelService', () => {
  let store: ReturnType<typeof createMockStore>;
  let service: EnvironmentModelService;

  beforeEach(() => {
    store = createMockStore();
    service = new EnvironmentModelService(store, createMockDiscovery());
  });

  describe('fullRefresh', () => {
    it('discovers and stores assets from AWS', async () => {
      const assets = [
        makeDiscoveredAsset({ resource_id: 'arn:aws:iam::123:user/alice', resource_type: 'AWS::IAM::User' }),
        makeDiscoveredAsset({ resource_id: 'arn:aws:ec2:us-east-1:123:instance/i-001', resource_type: 'AWS::EC2::Instance' }),
        makeDiscoveredAsset({ resource_id: 'arn:aws:s3:::my-bucket', resource_type: 'AWS::S3::Bucket' }),
      ];
      const discovery = createMockDiscovery(assets);
      service = new EnvironmentModelService(store, discovery);

      const result = await service.fullRefresh('tenant-abc', '123456789012', 'us-east-1');

      expect(result.assets_discovered).toBe(3);
      expect(store.assets.size).toBe(3);
    });

    it('assigns correct attack surfaces to discovered assets', async () => {
      const assets = [
        makeDiscoveredAsset({ resource_id: 'arn:aws:iam::123:user/alice', resource_type: 'AWS::IAM::User' }),
        makeDiscoveredAsset({ resource_id: 'arn:aws:s3:::bucket', resource_type: 'AWS::S3::Bucket' }),
      ];
      service = new EnvironmentModelService(store, createMockDiscovery(assets));

      await service.fullRefresh('tenant-abc', '123456789012', 'us-east-1');

      const iamAsset = await store.getAsset('tenant-abc', 'arn:aws:iam::123:user/alice');
      const s3Asset = await store.getAsset('tenant-abc', 'arn:aws:s3:::bucket');

      expect(iamAsset?.attack_surface).toBe(AttackSurface.CLOUD_IAM);
      expect(s3Asset?.attack_surface).toBe(AttackSurface.CLOUD_STORAGE);
    });

    it('assigns criticality scores to discovered assets', async () => {
      const assets = [
        makeDiscoveredAsset({
          resource_id: 'arn:aws:rds:us-east-1:123:db:prod-db',
          resource_type: 'AWS::RDS::DBInstance',
          tags: { Environment: 'production' },
          is_public_facing: false,
        }),
        makeDiscoveredAsset({
          resource_id: 'arn:aws:ec2:us-east-1:123:instance/i-dev',
          resource_type: 'AWS::EC2::Instance',
          tags: { Environment: 'dev' },
          is_public_facing: false,
        }),
      ];
      service = new EnvironmentModelService(store, createMockDiscovery(assets));

      await service.fullRefresh('tenant-abc', '123456789012', 'us-east-1');

      const prodDb = await store.getAsset('tenant-abc', 'arn:aws:rds:us-east-1:123:db:prod-db');
      const devEc2 = await store.getAsset('tenant-abc', 'arn:aws:ec2:us-east-1:123:instance/i-dev');

      expect(prodDb!.criticality).toBeGreaterThan(devEc2!.criticality);
    });

    it('discovers and stores relationships', async () => {
      const assets = [makeDiscoveredAsset()];
      const rels: DiscoveredRelationship[] = [{
        source_resource_id: 'arn:aws:iam::123:role/AdminRole',
        target_resource_id: 'arn:aws:s3:::sensitive-bucket',
        relationship_type: 'IAM_PERMISSION',
        description: 'AdminRole has s3:* on sensitive-bucket',
        is_overprivileged: true,
      }];
      service = new EnvironmentModelService(store, createMockDiscovery(assets, rels));

      const result = await service.fullRefresh('tenant-abc', '123456789012', 'us-east-1');

      expect(result.relationships_discovered).toBe(1);
      expect(store.relationships.size).toBe(1);
    });

    it('returns zero counts when no assets are discovered', async () => {
      const result = await service.fullRefresh('tenant-abc', '123456789012', 'us-east-1');

      expect(result.assets_discovered).toBe(0);
      expect(result.relationships_discovered).toBe(0);
      expect(result.refreshed_at).toBeDefined();
    });
  });

  describe('processEvent', () => {
    it('updates asset last_seen when asset exists in store', async () => {
      // Pre-populate an asset
      const asset: EnvironmentAsset = {
        id: 'asset-001',
        tenant_id: 'tenant-abc',
        account_id: '123456789012',
        region: 'us-east-1',
        resource_type: 'AWS::IAM::User',
        resource_id: 'arn:aws:iam::123456789012:user/alice',
        attack_surface: AttackSurface.CLOUD_IAM,
        criticality: 7,
        tags: {},
        is_public_facing: false,
        known_vulnerabilities: [],
        last_seen: '2024-01-01T00:00:00Z',
        created_at: '2024-01-01T00:00:00Z',
      };
      await store.upsertAsset(asset);

      const event = makeNormalizedEvent();
      await service.processEvent(event);

      const updated = await store.getAsset('tenant-abc', 'arn:aws:iam::123456789012:user/alice');
      expect(updated!.last_seen).not.toBe('2024-01-01T00:00:00Z');
    });

    it('creates a baseline for the actor on first event', async () => {
      const event = makeNormalizedEvent();
      await service.processEvent(event);

      const baseline = await store.getBaseline('tenant-abc', 'arn:aws:iam::123456789012:user/alice');
      expect(baseline).not.toBeNull();
      expect(baseline!.typical_api_calls).toContain('iam:CreateAccessKey');
    });

    it('creates a baseline for the target asset on first event', async () => {
      const event = makeNormalizedEvent();
      await service.processEvent(event);

      const baseline = await store.getBaseline('tenant-abc', 'arn:aws:iam::123456789012:user/alice');
      expect(baseline).not.toBeNull();
    });

    it('does not create baseline for unknown actors', async () => {
      const event = makeNormalizedEvent({
        actor: { type: 'UNKNOWN', identifier: 'unknown' },
      });
      await service.processEvent(event);

      const baseline = await store.getBaseline('tenant-abc', 'unknown');
      expect(baseline).toBeNull();
    });
  });

  describe('assembleContext', () => {
    beforeEach(async () => {
      // Populate store with a mix of assets
      const assets: DiscoveredAsset[] = [
        makeDiscoveredAsset({ resource_id: 'arn:1', resource_type: 'AWS::RDS::DBInstance', tags: { Environment: 'production' } }),
        makeDiscoveredAsset({ resource_id: 'arn:2', resource_type: 'AWS::EC2::Instance', tags: { Environment: 'production' } }),
        makeDiscoveredAsset({ resource_id: 'arn:3', resource_type: 'AWS::EC2::Instance', tags: { Environment: 'dev' } }),
        makeDiscoveredAsset({ resource_id: 'arn:4', resource_type: 'AWS::S3::Bucket', tags: { Environment: 'production' }, is_public_facing: true }),
      ];
      service = new EnvironmentModelService(store, createMockDiscovery(assets));
      await service.fullRefresh('tenant-abc', '123456789012', 'us-east-1');
    });

    it('returns correct total_assets count', async () => {
      const ctx = await service.assembleContext('tenant-abc', '123456789012');
      expect(ctx.total_assets).toBe(4);
    });

    it('includes only critical assets (criticality >= 7) by default', async () => {
      const ctx = await service.assembleContext('tenant-abc', '123456789012');
      for (const asset of ctx.critical_assets) {
        expect(asset.criticality).toBeGreaterThanOrEqual(7);
      }
    });

    it('includes relevant assets even if not critical', async () => {
      const ctx = await service.assembleContext('tenant-abc', '123456789012', ['arn:3']);
      const ids = ctx.critical_assets.map((a) => a.resource_id);
      expect(ids).toContain('arn:3');
    });

    it('does not duplicate assets when relevant asset is already critical', async () => {
      const ctx = await service.assembleContext('tenant-abc', '123456789012', ['arn:1']);
      const ids = ctx.critical_assets.map((a) => a.resource_id);
      const count = ids.filter((id) => id === 'arn:1').length;
      expect(count).toBe(1);
    });

    it('returns correct metadata fields', async () => {
      const ctx = await service.assembleContext('tenant-abc', '123456789012');
      expect(ctx.tenant_id).toBe('tenant-abc');
      expect(ctx.account_id).toBe('123456789012');
      expect(ctx.assembled_at).toBeDefined();
      expect(new Date(ctx.assembled_at).getTime()).not.toBeNaN();
    });

    it('returns empty context for tenant with no assets', async () => {
      const ctx = await service.assembleContext('tenant-empty', '999999999999');
      expect(ctx.total_assets).toBe(0);
      expect(ctx.critical_assets).toHaveLength(0);
    });
  });

  describe('getDeviationForEvent', () => {
    it('returns deviation result using stored baseline', async () => {
      const baseline = makeEstablishedBaseline();
      await store.upsertBaseline(baseline);

      const event = makeNormalizedEvent({ event_type: 'iam:DeleteUser', source_ip: '198.51.100.99' });
      const result = await service.getDeviationForEvent(event);

      expect(result.deviation_score).toBeGreaterThan(0);
    });

    it('returns zero deviation when no baseline exists', async () => {
      const event = makeNormalizedEvent();
      const result = await service.getDeviationForEvent(event);

      expect(result.deviation_score).toBe(0);
      expect(result.is_anomalous).toBe(false);
    });
  });
});
