/**
 * Tests for the Tool Discovery Engine.
 * Verifies that IAM permissions are correctly mapped to ToolCapabilityProfiles
 * that the AI Reasoning Engine can use to plan responses.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ToolDiscoveryEngine,
  IamPermissionChecker,
  AWS_ACTION_CATALOG,
  PERMISSION_TO_ACTIONS,
  CapabilitySummary,
} from './tool-discovery.js';
import { BlastRadius, AwsDataSource, ToolCapabilityProfile } from '../types/index.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMockChecker(allowedPermissions: string[]): IamPermissionChecker {
  return {
    getAllowedPermissions: vi.fn(async (_roleArn: string, toCheck: string[]) =>
      toCheck.filter((p) => allowedPermissions.includes(p))
    ),
  };
}

const FULL_PERMISSIONS = Object.keys(PERMISSION_TO_ACTIONS);

const MINIMAL_PERMISSIONS = [
  'iam:UpdateAccessKey',
  'iam:ListAccessKeys',
  'cloudtrail:LookupEvents',
  'guardduty:GetFindings',
  'guardduty:ListFindings',
];

const CONNECTOR_META = {
  connectorId: 'conn-001',
  tenantId: 'tenant-abc',
  accountId: '123456789012',
  region: 'us-east-1',
  roleArn: 'arn:aws:iam::123456789012:role/WatcherRole',
};

// ── AWS_ACTION_CATALOG integrity ──────────────────────────────────────────────

describe('AWS_ACTION_CATALOG', () => {
  it('every action has a unique action_id', () => {
    const ids = Object.values(AWS_ACTION_CATALOG).map((a) => a.action_id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('every action has required fields', () => {
    for (const [key, action] of Object.entries(AWS_ACTION_CATALOG)) {
      expect(action.action_id, `${key} missing action_id`).toBeTruthy();
      expect(action.description, `${key} missing description`).toBeTruthy();
      expect(action.aws_service, `${key} missing aws_service`).toBeTruthy();
      expect(action.aws_api_call, `${key} missing aws_api_call`).toBeTruthy();
      expect(action.blast_radius, `${key} missing blast_radius`).toBeDefined();
      expect(typeof action.reversible, `${key} reversible must be boolean`).toBe('boolean');
    }
  });

  it('reversible actions have a rollback_api_call', () => {
    for (const [key, action] of Object.entries(AWS_ACTION_CATALOG)) {
      if (action.reversible) {
        expect(action.rollback_api_call, `${key} is reversible but missing rollback_api_call`).toBeTruthy();
      }
    }
  });

  it('read-only actions (NONE blast radius) are not reversible', () => {
    for (const action of Object.values(AWS_ACTION_CATALOG)) {
      if (action.blast_radius === BlastRadius.NONE) {
        expect(action.reversible).toBe(false);
      }
    }
  });
});

// ── discoverCapabilities ──────────────────────────────────────────────────────

describe('ToolDiscoveryEngine.discoverCapabilities', () => {
  let engine: ToolDiscoveryEngine;

  describe('with full permissions', () => {
    beforeEach(() => {
      engine = new ToolDiscoveryEngine(makeMockChecker(FULL_PERMISSIONS));
    });

    it('returns a profile with correct metadata', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId,
        CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId,
        CONNECTOR_META.region,
        CONNECTOR_META.roleArn
      );

      expect(profile.connector_id).toBe('conn-001');
      expect(profile.tenant_id).toBe('tenant-abc');
      expect(profile.account_id).toBe('123456789012');
      expect(profile.region).toBe('us-east-1');
      expect(profile.tool_type).toBe('AWS');
      expect(profile.discovered_at).toBeDefined();
      expect(profile.last_updated).toBeDefined();
    });

    it('includes all expected writable actions when fully permissioned', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      const actionIds = profile.writable_actions.map((a) => a.action_id);

      // Core response actions should be present
      expect(actionIds).toContain('aws:iam:disable-access-key');
      expect(actionIds).toContain('aws:ec2:stop-instance');
      expect(actionIds).toContain('aws:s3:block-public-access');
      expect(actionIds).toContain('aws:ec2:revoke-sg-ingress');
      expect(actionIds).toContain('aws:cloudtrail:lookup-events');
      expect(actionIds).toContain('aws:guardduty:get-findings');
    });

    it('includes all readable data sources when fully permissioned', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      expect(profile.readable_sources).toContain(AwsDataSource.CLOUDTRAIL);
      expect(profile.readable_sources).toContain(AwsDataSource.GUARDDUTY);
      expect(profile.readable_sources).toContain(AwsDataSource.SECURITY_HUB);
    });

    it('calls the permission checker with the role ARN', async () => {
      const checker = makeMockChecker(FULL_PERMISSIONS);
      engine = new ToolDiscoveryEngine(checker);

      await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      expect(checker.getAllowedPermissions).toHaveBeenCalledWith(
        CONNECTOR_META.roleArn,
        expect.any(Array)
      );
    });
  });

  describe('with minimal permissions (read-only + key disable)', () => {
    beforeEach(() => {
      engine = new ToolDiscoveryEngine(makeMockChecker(MINIMAL_PERMISSIONS));
    });

    it('only includes actions for granted permissions', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      const actionIds = profile.writable_actions.map((a) => a.action_id);

      // Should have
      expect(actionIds).toContain('aws:iam:disable-access-key');
      expect(actionIds).toContain('aws:iam:list-access-keys');
      expect(actionIds).toContain('aws:cloudtrail:lookup-events');
      expect(actionIds).toContain('aws:guardduty:get-findings');

      // Should NOT have (no ec2 or s3 permissions)
      expect(actionIds).not.toContain('aws:ec2:stop-instance');
      expect(actionIds).not.toContain('aws:s3:block-public-access');
      expect(actionIds).not.toContain('aws:ec2:revoke-sg-ingress');
    });

    it('only includes data sources for granted permissions', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      expect(profile.readable_sources).toContain(AwsDataSource.CLOUDTRAIL);
      expect(profile.readable_sources).toContain(AwsDataSource.GUARDDUTY);
      expect(profile.readable_sources).not.toContain(AwsDataSource.SECURITY_HUB);
      expect(profile.readable_sources).not.toContain(AwsDataSource.CONFIG);
    });
  });

  describe('with no permissions', () => {
    beforeEach(() => {
      engine = new ToolDiscoveryEngine(makeMockChecker([]));
    });

    it('returns empty writable actions and readable sources', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      expect(profile.writable_actions).toHaveLength(0);
      expect(profile.readable_sources).toHaveLength(0);
    });

    it('still returns valid profile metadata', async () => {
      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      expect(profile.connector_id).toBe('conn-001');
      expect(profile.tool_type).toBe('AWS');
    });
  });

  describe('action properties are preserved from catalog', () => {
    it('writable actions include blast_radius and reversible from catalog', async () => {
      engine = new ToolDiscoveryEngine(makeMockChecker(['iam:UpdateAccessKey', 'ec2:TerminateInstances']));

      const profile = await engine.discoverCapabilities(
        CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
        CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
      );

      const disableKey = profile.writable_actions.find((a) => a.action_id === 'aws:iam:disable-access-key');
      expect(disableKey).toBeDefined();
      expect(disableKey!.blast_radius).toBe(BlastRadius.LOW);
      expect(disableKey!.reversible).toBe(true);
      expect(disableKey!.rollback_api_call).toBe('UpdateAccessKey');

      const terminate = profile.writable_actions.find((a) => a.action_id === 'aws:ec2:terminate-instance');
      expect(terminate).toBeDefined();
      expect(terminate!.blast_radius).toBe(BlastRadius.HIGH);
      expect(terminate!.reversible).toBe(false);
    });
  });
});

// ── hasCapability / getAction ─────────────────────────────────────────────────

describe('ToolDiscoveryEngine.hasCapability / getAction', () => {
  let engine: ToolDiscoveryEngine;
  let profile: ToolCapabilityProfile;

  beforeEach(async () => {
    engine = new ToolDiscoveryEngine(makeMockChecker(MINIMAL_PERMISSIONS));
    profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );
  });

  it('returns true for an available action', () => {
    expect(engine.hasCapability(profile, 'aws:iam:disable-access-key')).toBe(true);
    expect(engine.hasCapability(profile, 'aws:cloudtrail:lookup-events')).toBe(true);
  });

  it('returns false for an unavailable action', () => {
    expect(engine.hasCapability(profile, 'aws:ec2:stop-instance')).toBe(false);
    expect(engine.hasCapability(profile, 'aws:s3:block-public-access')).toBe(false);
  });

  it('returns false for a non-existent action_id', () => {
    expect(engine.hasCapability(profile, 'aws:nonexistent:action')).toBe(false);
  });

  it('getAction returns the ToolAction for an available action', () => {
    const action = engine.getAction(profile, 'aws:iam:disable-access-key');
    expect(action).not.toBeNull();
    expect(action!.action_id).toBe('aws:iam:disable-access-key');
    expect(action!.aws_service).toBe('iam');
    expect(action!.aws_api_call).toBe('UpdateAccessKey');
  });

  it('getAction returns null for an unavailable action', () => {
    expect(engine.getAction(profile, 'aws:ec2:stop-instance')).toBeNull();
  });
});

// ── summarizeCapabilities ─────────────────────────────────────────────────────

describe('ToolDiscoveryEngine.summarizeCapabilities', () => {
  let engine: ToolDiscoveryEngine;

  it('groups actions by blast radius correctly', async () => {
    engine = new ToolDiscoveryEngine(makeMockChecker(FULL_PERMISSIONS));
    const profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    const summary = engine.summarizeCapabilities(profile);

    // Read-only actions should be in NONE
    expect(summary.actions_by_blast_radius[BlastRadius.NONE].length).toBeGreaterThan(0);
    // Response actions should be in LOW or MEDIUM
    expect(summary.actions_by_blast_radius[BlastRadius.LOW].length).toBeGreaterThan(0);
    expect(summary.actions_by_blast_radius[BlastRadius.MEDIUM].length).toBeGreaterThan(0);
  });

  it('reports can_respond_autonomously as true when low-blast actions exist', async () => {
    engine = new ToolDiscoveryEngine(makeMockChecker(['iam:UpdateAccessKey']));
    const profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    const summary = engine.summarizeCapabilities(profile);
    expect(summary.can_respond_autonomously).toBe(true);
  });

  it('reports can_respond_autonomously as false when only high-blast actions exist', async () => {
    engine = new ToolDiscoveryEngine(makeMockChecker(['ec2:TerminateInstances', 'rds:StopDBInstance']));
    const profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    const summary = engine.summarizeCapabilities(profile);
    // HIGH blast actions don't count as autonomous
    expect(summary.can_respond_autonomously).toBe(false);
  });

  it('identifies capability gaps for missing critical permissions', async () => {
    // Only give read permissions — no response capabilities
    engine = new ToolDiscoveryEngine(makeMockChecker(['cloudtrail:LookupEvents']));
    const profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    const summary = engine.summarizeCapabilities(profile);

    expect(summary.capability_gaps.length).toBeGreaterThan(0);

    const gapIds = summary.capability_gaps.map((g) => g.missing_action_id);
    expect(gapIds).toContain('aws:iam:disable-access-key');
    expect(gapIds).toContain('aws:ec2:stop-instance');
    expect(gapIds).toContain('aws:s3:block-public-access');
    expect(gapIds).toContain('aws:ec2:revoke-sg-ingress');
  });

  it('reports no gaps when all critical capabilities are present', async () => {
    engine = new ToolDiscoveryEngine(makeMockChecker(FULL_PERMISSIONS));
    const profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    const summary = engine.summarizeCapabilities(profile);
    expect(summary.capability_gaps).toHaveLength(0);
  });

  it('includes correct total_actions count', async () => {
    engine = new ToolDiscoveryEngine(makeMockChecker(MINIMAL_PERMISSIONS));
    const profile = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    const summary = engine.summarizeCapabilities(profile);
    expect(summary.total_actions).toBe(profile.writable_actions.length);
  });
});

// ── refreshCapabilities ───────────────────────────────────────────────────────

describe('ToolDiscoveryEngine.refreshCapabilities', () => {
  it('preserves original discovered_at but updates last_updated', async () => {
    const engine = new ToolDiscoveryEngine(makeMockChecker(MINIMAL_PERMISSIONS));
    const original = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    // Wait a tick to ensure timestamps differ
    await new Promise((r) => setTimeout(r, 5));

    const refreshed = await engine.refreshCapabilities(original);

    expect(refreshed.discovered_at).toBe(original.discovered_at);
    expect(refreshed.last_updated).not.toBe(original.last_updated);
  });

  it('reflects new permissions after refresh', async () => {
    // Start with minimal permissions
    const engine = new ToolDiscoveryEngine(makeMockChecker(MINIMAL_PERMISSIONS));
    const original = await engine.discoverCapabilities(
      CONNECTOR_META.connectorId, CONNECTOR_META.tenantId,
      CONNECTOR_META.accountId, CONNECTOR_META.region, CONNECTOR_META.roleArn
    );

    expect(engine.hasCapability(original, 'aws:ec2:stop-instance')).toBe(false);

    // Now expand permissions and refresh
    const expandedEngine = new ToolDiscoveryEngine(
      makeMockChecker([...MINIMAL_PERMISSIONS, 'ec2:StopInstances'])
    );
    const refreshed = await expandedEngine.refreshCapabilities(original);

    expect(expandedEngine.hasCapability(refreshed, 'aws:ec2:stop-instance')).toBe(true);
  });
});
