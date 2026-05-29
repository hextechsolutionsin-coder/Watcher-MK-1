/**
 * Tool Discovery Engine
 *
 * When a customer connects their AWS account, this engine inspects the IAM
 * permissions granted to the connector's cross-account role and produces a
 * ToolCapabilityProfile — a structured description of what the AI can read
 * and what actions it can take in that environment.
 *
 * Design principle: The AI reads these profiles at reasoning time to know
 * what's possible. It never guesses — if a capability isn't in the profile,
 * the AI won't attempt it.
 */

import {
  ToolCapabilityProfile,
  ToolAction,
  BlastRadius,
  AwsDataSource,
} from '../types/index.js';

// ============================================================================
// AWS Action Catalog
// ============================================================================

/**
 * The complete catalog of AWS actions Watcher MK1 can perform.
 * Each entry maps an IAM permission to a ToolAction the AI can use.
 *
 * This catalog is the source of truth for:
 * - What the AI is allowed to plan
 * - What blast radius each action carries
 * - Whether the action is reversible and how to roll it back
 */
export const AWS_ACTION_CATALOG: Record<string, ToolAction> = {

  // ── IAM Actions ────────────────────────────────────────────────────────────

  'iam:UpdateAccessKey:disable': {
    action_id: 'aws:iam:disable-access-key',
    description: 'Disable an IAM access key (revoke without deleting)',
    aws_service: 'iam',
    aws_api_call: 'UpdateAccessKey',
    required_params: ['AccessKeyId', 'Status'],
    blast_radius: BlastRadius.LOW,
    reversible: true,
    rollback_api_call: 'UpdateAccessKey',
  },

  'iam:UpdateAccessKey:enable': {
    action_id: 'aws:iam:enable-access-key',
    description: 'Re-enable a previously disabled IAM access key',
    aws_service: 'iam',
    aws_api_call: 'UpdateAccessKey',
    required_params: ['AccessKeyId', 'Status'],
    blast_radius: BlastRadius.LOW,
    reversible: false,
  },

  'iam:DeleteAccessKey': {
    action_id: 'aws:iam:delete-access-key',
    description: 'Permanently delete an IAM access key',
    aws_service: 'iam',
    aws_api_call: 'DeleteAccessKey',
    required_params: ['AccessKeyId'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: false,
  },

  'iam:AttachUserPolicy': {
    action_id: 'aws:iam:attach-deny-policy',
    description: 'Attach an explicit deny policy to an IAM user to block all actions',
    aws_service: 'iam',
    aws_api_call: 'AttachUserPolicy',
    required_params: ['UserName', 'PolicyArn'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'DetachUserPolicy',
  },

  'iam:DetachUserPolicy': {
    action_id: 'aws:iam:detach-user-policy',
    description: 'Detach a policy from an IAM user',
    aws_service: 'iam',
    aws_api_call: 'DetachUserPolicy',
    required_params: ['UserName', 'PolicyArn'],
    blast_radius: BlastRadius.LOW,
    reversible: true,
    rollback_api_call: 'AttachUserPolicy',
  },

  'iam:GetUser': {
    action_id: 'aws:iam:get-user',
    description: 'Get details about an IAM user',
    aws_service: 'iam',
    aws_api_call: 'GetUser',
    required_params: ['UserName'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'iam:ListAccessKeys': {
    action_id: 'aws:iam:list-access-keys',
    description: 'List access keys for an IAM user',
    aws_service: 'iam',
    aws_api_call: 'ListAccessKeys',
    required_params: ['UserName'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'iam:ListAttachedUserPolicies': {
    action_id: 'aws:iam:list-attached-user-policies',
    description: 'List policies attached to an IAM user',
    aws_service: 'iam',
    aws_api_call: 'ListAttachedUserPolicies',
    required_params: ['UserName'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'iam:SimulatePrincipalPolicy': {
    action_id: 'aws:iam:simulate-principal-policy',
    description: 'Simulate what actions an IAM principal can perform',
    aws_service: 'iam',
    aws_api_call: 'SimulatePrincipalPolicy',
    required_params: ['PolicySourceArn', 'ActionNames'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  // ── EC2 Actions ────────────────────────────────────────────────────────────

  'ec2:StopInstances': {
    action_id: 'aws:ec2:stop-instance',
    description: 'Stop an EC2 instance (can be restarted)',
    aws_service: 'ec2',
    aws_api_call: 'StopInstances',
    required_params: ['InstanceIds'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'StartInstances',
  },

  'ec2:TerminateInstances': {
    action_id: 'aws:ec2:terminate-instance',
    description: 'Permanently terminate an EC2 instance',
    aws_service: 'ec2',
    aws_api_call: 'TerminateInstances',
    required_params: ['InstanceIds'],
    blast_radius: BlastRadius.HIGH,
    reversible: false,
  },

  'ec2:StartInstances': {
    action_id: 'aws:ec2:start-instance',
    description: 'Start a stopped EC2 instance',
    aws_service: 'ec2',
    aws_api_call: 'StartInstances',
    required_params: ['InstanceIds'],
    blast_radius: BlastRadius.LOW,
    reversible: true,
    rollback_api_call: 'StopInstances',
  },

  'ec2:RevokeSecurityGroupIngress': {
    action_id: 'aws:ec2:revoke-sg-ingress',
    description: 'Remove an inbound rule from a security group to block traffic',
    aws_service: 'ec2',
    aws_api_call: 'RevokeSecurityGroupIngress',
    required_params: ['GroupId', 'IpPermissions'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'AuthorizeSecurityGroupIngress',
  },

  'ec2:AuthorizeSecurityGroupIngress': {
    action_id: 'aws:ec2:authorize-sg-ingress',
    description: 'Add an inbound rule to a security group',
    aws_service: 'ec2',
    aws_api_call: 'AuthorizeSecurityGroupIngress',
    required_params: ['GroupId', 'IpPermissions'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'RevokeSecurityGroupIngress',
  },

  'ec2:RevokeSecurityGroupEgress': {
    action_id: 'aws:ec2:revoke-sg-egress',
    description: 'Remove an outbound rule from a security group (isolate instance)',
    aws_service: 'ec2',
    aws_api_call: 'RevokeSecurityGroupEgress',
    required_params: ['GroupId', 'IpPermissions'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'AuthorizeSecurityGroupEgress',
  },

  'ec2:DescribeInstances': {
    action_id: 'aws:ec2:describe-instances',
    description: 'Get details about EC2 instances',
    aws_service: 'ec2',
    aws_api_call: 'DescribeInstances',
    required_params: [],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'ec2:DescribeSecurityGroups': {
    action_id: 'aws:ec2:describe-security-groups',
    description: 'Get details about security groups',
    aws_service: 'ec2',
    aws_api_call: 'DescribeSecurityGroups',
    required_params: [],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'ec2:CreateSnapshot': {
    action_id: 'aws:ec2:create-snapshot',
    description: 'Create a snapshot of an EBS volume for forensic preservation',
    aws_service: 'ec2',
    aws_api_call: 'CreateSnapshot',
    required_params: ['VolumeId'],
    blast_radius: BlastRadius.LOW,
    reversible: false,
  },

  // ── S3 Actions ─────────────────────────────────────────────────────────────

  'S3:PutBucketPolicy': {
    action_id: 'aws:s3:put-bucket-policy',
    description: 'Update an S3 bucket policy (e.g. to block public access)',
    aws_service: 's3',
    aws_api_call: 'PutBucketPolicy',
    required_params: ['Bucket', 'Policy'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'PutBucketPolicy',
  },

  'S3:PutBucketAcl': {
    action_id: 'aws:s3:put-bucket-acl',
    description: 'Set an S3 bucket ACL to private',
    aws_service: 's3',
    aws_api_call: 'PutBucketAcl',
    required_params: ['Bucket', 'ACL'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'PutBucketAcl',
  },

  'S3:PutBucketPublicAccessBlock': {
    action_id: 'aws:s3:block-public-access',
    description: 'Enable S3 Block Public Access settings on a bucket',
    aws_service: 's3',
    aws_api_call: 'PutPublicAccessBlock',
    required_params: ['Bucket', 'PublicAccessBlockConfiguration'],
    blast_radius: BlastRadius.LOW,
    reversible: true,
    rollback_api_call: 'PutPublicAccessBlock',
  },

  'S3:GetBucketPolicy': {
    action_id: 'aws:s3:get-bucket-policy',
    description: 'Read the current S3 bucket policy',
    aws_service: 's3',
    aws_api_call: 'GetBucketPolicy',
    required_params: ['Bucket'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'S3:GetBucketAcl': {
    action_id: 'aws:s3:get-bucket-acl',
    description: 'Read the current S3 bucket ACL',
    aws_service: 's3',
    aws_api_call: 'GetBucketAcl',
    required_params: ['Bucket'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  // ── CloudTrail Actions ─────────────────────────────────────────────────────

  'cloudtrail:LookupEvents': {
    action_id: 'aws:cloudtrail:lookup-events',
    description: 'Query CloudTrail for recent API activity by a principal or resource',
    aws_service: 'cloudtrail',
    aws_api_call: 'LookupEvents',
    required_params: ['LookupAttributes'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'cloudtrail:GetTrailStatus': {
    action_id: 'aws:cloudtrail:get-trail-status',
    description: 'Check if CloudTrail logging is active',
    aws_service: 'cloudtrail',
    aws_api_call: 'GetTrailStatus',
    required_params: ['Name'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  // ── GuardDuty Actions ──────────────────────────────────────────────────────

  'guardduty:GetFindings': {
    action_id: 'aws:guardduty:get-findings',
    description: 'Retrieve GuardDuty finding details',
    aws_service: 'guardduty',
    aws_api_call: 'GetFindings',
    required_params: ['DetectorId', 'FindingIds'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'guardduty:ListFindings': {
    action_id: 'aws:guardduty:list-findings',
    description: 'List active GuardDuty findings',
    aws_service: 'guardduty',
    aws_api_call: 'ListFindings',
    required_params: ['DetectorId'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'guardduty:CreateIPSet': {
    action_id: 'aws:guardduty:create-ip-blocklist',
    description: 'Add IPs to a GuardDuty threat intelligence IP set for blocking',
    aws_service: 'guardduty',
    aws_api_call: 'CreateIPSet',
    required_params: ['DetectorId', 'Name', 'Format', 'Location', 'Activate'],
    blast_radius: BlastRadius.LOW,
    reversible: true,
    rollback_api_call: 'DeleteIPSet',
  },

  // ── Security Hub Actions ───────────────────────────────────────────────────

  'securityhub:GetFindings': {
    action_id: 'aws:securityhub:get-findings',
    description: 'Retrieve Security Hub findings',
    aws_service: 'securityhub',
    aws_api_call: 'GetFindings',
    required_params: ['Filters'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  'securityhub:UpdateFindings': {
    action_id: 'aws:securityhub:update-finding-workflow',
    description: 'Update the workflow status of a Security Hub finding',
    aws_service: 'securityhub',
    aws_api_call: 'UpdateFindings',
    required_params: ['Filters', 'Workflow'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  // ── Lambda Actions ─────────────────────────────────────────────────────────

  'lambda:PutFunctionConcurrency': {
    action_id: 'aws:lambda:throttle-function',
    description: 'Set Lambda function concurrency to 0 to disable execution',
    aws_service: 'lambda',
    aws_api_call: 'PutFunctionConcurrency',
    required_params: ['FunctionName', 'ReservedConcurrentExecutions'],
    blast_radius: BlastRadius.MEDIUM,
    reversible: true,
    rollback_api_call: 'DeleteFunctionConcurrency',
  },

  'lambda:GetFunction': {
    action_id: 'aws:lambda:get-function',
    description: 'Get details about a Lambda function',
    aws_service: 'lambda',
    aws_api_call: 'GetFunction',
    required_params: ['FunctionName'],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },

  // ── RDS Actions ────────────────────────────────────────────────────────────

  'rds:StopDBInstance': {
    action_id: 'aws:rds:stop-db-instance',
    description: 'Stop an RDS database instance',
    aws_service: 'rds',
    aws_api_call: 'StopDBInstance',
    required_params: ['DBInstanceIdentifier'],
    blast_radius: BlastRadius.HIGH,
    reversible: true,
    rollback_api_call: 'StartDBInstance',
  },

  'rds:ModifyDBInstance': {
    action_id: 'aws:rds:modify-db-instance',
    description: 'Modify RDS instance settings (e.g. restrict access)',
    aws_service: 'rds',
    aws_api_call: 'ModifyDBInstance',
    required_params: ['DBInstanceIdentifier'],
    blast_radius: BlastRadius.HIGH,
    reversible: true,
    rollback_api_call: 'ModifyDBInstance',
  },

  'rds:DescribeDBInstances': {
    action_id: 'aws:rds:describe-db-instances',
    description: 'Get details about RDS database instances',
    aws_service: 'rds',
    aws_api_call: 'DescribeDBInstances',
    required_params: [],
    blast_radius: BlastRadius.NONE,
    reversible: false,
  },
};

// ============================================================================
// Permission → Action Mapping
// ============================================================================

/**
 * Maps IAM permission strings to catalog action IDs.
 * When a connector's role has a permission, these actions become available.
 *
 * Key: IAM permission (e.g. "iam:UpdateAccessKey")
 * Value: array of action_ids from AWS_ACTION_CATALOG
 */
export const PERMISSION_TO_ACTIONS: Record<string, string[]> = {
  'iam:UpdateAccessKey':          ['aws:iam:disable-access-key', 'aws:iam:enable-access-key'],
  'iam:DeleteAccessKey':          ['aws:iam:delete-access-key'],
  'iam:AttachUserPolicy':         ['aws:iam:attach-deny-policy'],
  'iam:DetachUserPolicy':         ['aws:iam:detach-user-policy'],
  'iam:GetUser':                  ['aws:iam:get-user'],
  'iam:ListAccessKeys':           ['aws:iam:list-access-keys'],
  'iam:ListAttachedUserPolicies': ['aws:iam:list-attached-user-policies'],
  'iam:SimulatePrincipalPolicy':  ['aws:iam:simulate-principal-policy'],
  'ec2:StopInstances':            ['aws:ec2:stop-instance'],
  'ec2:TerminateInstances':       ['aws:ec2:terminate-instance'],
  'ec2:StartInstances':           ['aws:ec2:start-instance'],
  'ec2:RevokeSecurityGroupIngress':   ['aws:ec2:revoke-sg-ingress'],
  'ec2:AuthorizeSecurityGroupIngress':['aws:ec2:authorize-sg-ingress'],
  'ec2:RevokeSecurityGroupEgress':    ['aws:ec2:revoke-sg-egress'],
  'ec2:DescribeInstances':        ['aws:ec2:describe-instances'],
  'ec2:DescribeSecurityGroups':   ['aws:ec2:describe-security-groups'],
  'ec2:CreateSnapshot':           ['aws:ec2:create-snapshot'],
  's3:PutBucketPolicy':           ['aws:s3:put-bucket-policy'],
  's3:PutBucketAcl':              ['aws:s3:put-bucket-acl'],
  's3:PutBucketPublicAccessBlock':['aws:s3:block-public-access'],
  's3:GetBucketPolicy':           ['aws:s3:get-bucket-policy'],
  's3:GetBucketAcl':              ['aws:s3:get-bucket-acl'],
  'cloudtrail:LookupEvents':      ['aws:cloudtrail:lookup-events'],
  'cloudtrail:GetTrailStatus':    ['aws:cloudtrail:get-trail-status'],
  'guardduty:GetFindings':        ['aws:guardduty:get-findings'],
  'guardduty:ListFindings':       ['aws:guardduty:list-findings'],
  'guardduty:CreateIPSet':        ['aws:guardduty:create-ip-blocklist'],
  'securityhub:GetFindings':      ['aws:securityhub:get-findings'],
  'securityhub:UpdateFindings':   ['aws:securityhub:update-finding-workflow'],
  'lambda:PutFunctionConcurrency':['aws:lambda:throttle-function'],
  'lambda:GetFunction':           ['aws:lambda:get-function'],
  'rds:StopDBInstance':           ['aws:rds:stop-db-instance'],
  'rds:ModifyDBInstance':         ['aws:rds:modify-db-instance'],
  'rds:DescribeDBInstances':      ['aws:rds:describe-db-instances'],
};

/**
 * Maps IAM permissions to readable data sources.
 * When a connector has these permissions, it can ingest from these sources.
 */
export const PERMISSION_TO_DATA_SOURCES: Record<string, AwsDataSource> = {
  'cloudtrail:LookupEvents':      AwsDataSource.CLOUDTRAIL,
  'cloudtrail:GetTrailStatus':    AwsDataSource.CLOUDTRAIL,
  'guardduty:GetFindings':        AwsDataSource.GUARDDUTY,
  'guardduty:ListFindings':       AwsDataSource.GUARDDUTY,
  'securityhub:GetFindings':      AwsDataSource.SECURITY_HUB,
  'config:GetResourceConfigHistory': AwsDataSource.CONFIG,
  'config:DescribeConfigRules':   AwsDataSource.CONFIG,
};

// ============================================================================
// IAM Policy Simulator Interface
// ============================================================================

/**
 * Interface for checking what IAM permissions a role actually has.
 * In production this calls AWS IAM SimulatePrincipalPolicy.
 * In tests this is mocked.
 */
export interface IamPermissionChecker {
  /**
   * Returns the list of IAM permissions that are allowed for the given role ARN.
   * Only returns permissions from the provided list to check.
   */
  getAllowedPermissions(roleArn: string, permissionsToCheck: string[]): Promise<string[]>;
}

// ============================================================================
// Tool Discovery Engine
// ============================================================================

/**
 * Discovers what capabilities a connected AWS account has based on the
 * IAM permissions granted to the connector's cross-account role.
 *
 * Produces a ToolCapabilityProfile that the AI Reasoning Engine reads
 * at reasoning time to know what actions are available.
 */
export class ToolDiscoveryEngine {
  private readonly permissionChecker: IamPermissionChecker;

  /** All IAM permissions we know how to map to actions. */
  private static readonly ALL_KNOWN_PERMISSIONS = Object.keys(PERMISSION_TO_ACTIONS)
    .concat(Object.keys(PERMISSION_TO_DATA_SOURCES));

  constructor(permissionChecker: IamPermissionChecker) {
    this.permissionChecker = permissionChecker;
  }

  /**
   * Discovers capabilities for a connector by checking its IAM role permissions.
   * Returns a ToolCapabilityProfile ready to be stored and fed to the AI.
   */
  async discoverCapabilities(
    connectorId: string,
    tenantId: string,
    accountId: string,
    region: string,
    roleArn: string
  ): Promise<ToolCapabilityProfile> {
    const now = new Date().toISOString();

    // Ask AWS what permissions this role actually has
    const allowedPermissions = await this.permissionChecker.getAllowedPermissions(
      roleArn,
      ToolDiscoveryEngine.ALL_KNOWN_PERMISSIONS
    );

    const allowedSet = new Set(allowedPermissions);

    // Build writable actions from allowed permissions
    const writableActions = this.buildWritableActions(allowedSet);

    // Build readable data sources from allowed permissions
    const readableSources = this.buildReadableSources(allowedSet);

    return {
      connector_id: connectorId,
      tenant_id: tenantId,
      tool_type: 'AWS',
      account_id: accountId,
      region,
      readable_sources: readableSources,
      writable_actions: writableActions,
      discovered_at: now,
      last_updated: now,
    };
  }

  /**
   * Re-runs discovery for an existing profile (e.g. after permission changes).
   * Returns an updated profile with the same connector/tenant metadata.
   */
  async refreshCapabilities(existing: ToolCapabilityProfile): Promise<ToolCapabilityProfile> {
    const roleArn = this.inferRoleArn(existing);
    const updated = await this.discoverCapabilities(
      existing.connector_id,
      existing.tenant_id,
      existing.account_id,
      existing.region,
      roleArn
    );
    return {
      ...updated,
      discovered_at: existing.discovered_at, // preserve original discovery time
      last_updated: new Date().toISOString(),
    };
  }

  /**
   * Returns a human-readable summary of what the AI can do with this profile.
   * Useful for the UI "what can Watcher do in your account?" view.
   */
  summarizeCapabilities(profile: ToolCapabilityProfile): CapabilitySummary {
    const byBlastRadius = {
      [BlastRadius.NONE]: [] as string[],
      [BlastRadius.LOW]: [] as string[],
      [BlastRadius.MEDIUM]: [] as string[],
      [BlastRadius.HIGH]: [] as string[],
    };

    for (const action of profile.writable_actions) {
      byBlastRadius[action.blast_radius].push(action.description);
    }

    const gaps = this.identifyGaps(profile);

    return {
      connector_id: profile.connector_id,
      account_id: profile.account_id,
      total_actions: profile.writable_actions.length,
      data_sources: profile.readable_sources,
      actions_by_blast_radius: byBlastRadius,
      capability_gaps: gaps,
      can_respond_autonomously: profile.writable_actions.some(
        (a) => a.blast_radius === BlastRadius.LOW || a.blast_radius === BlastRadius.NONE
      ),
    };
  }

  /**
   * Checks whether a specific action_id is available in a profile.
   * Used by the Safety Gate to validate AI-generated action plans.
   */
  hasCapability(profile: ToolCapabilityProfile, actionId: string): boolean {
    return profile.writable_actions.some((a) => a.action_id === actionId);
  }

  /**
   * Returns the ToolAction for a given action_id, or null if not available.
   */
  getAction(profile: ToolCapabilityProfile, actionId: string): ToolAction | null {
    return profile.writable_actions.find((a) => a.action_id === actionId) ?? null;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private buildWritableActions(allowedPermissions: Set<string>): ToolAction[] {
    const actionIds = new Set<string>();

    for (const permission of allowedPermissions) {
      const mapped = PERMISSION_TO_ACTIONS[permission];
      if (mapped) {
        for (const id of mapped) actionIds.add(id);
      }
    }

    // Build action list from catalog, preserving catalog order
    const actions: ToolAction[] = [];
    for (const catalogEntry of Object.values(AWS_ACTION_CATALOG)) {
      if (actionIds.has(catalogEntry.action_id)) {
        actions.push(catalogEntry);
      }
    }

    return actions;
  }

  private buildReadableSources(allowedPermissions: Set<string>): AwsDataSource[] {
    const sources = new Set<AwsDataSource>();

    for (const permission of allowedPermissions) {
      const source = PERMISSION_TO_DATA_SOURCES[permission];
      if (source) sources.add(source);
    }

    return Array.from(sources);
  }

  private inferRoleArn(profile: ToolCapabilityProfile): string {
    // In a real implementation this would be stored on the connector record.
    // For refresh we reconstruct a placeholder — the real ARN comes from the connector.
    return `arn:aws:iam::${profile.account_id}:role/WatcherConnectorRole`;
  }

  /**
   * Identifies important capability gaps — things Watcher can't do because
   * the role wasn't granted the necessary permissions.
   */
  private identifyGaps(profile: ToolCapabilityProfile): CapabilityGap[] {
    const gaps: CapabilityGap[] = [];
    const availableIds = new Set(profile.writable_actions.map((a) => a.action_id));

    const criticalCapabilities: Array<{ id: string; description: string; impact: string }> = [
      {
        id: 'aws:iam:disable-access-key',
        description: 'Disable compromised IAM access keys',
        impact: 'Cannot automatically contain credential compromise incidents',
      },
      {
        id: 'aws:ec2:stop-instance',
        description: 'Stop compromised EC2 instances',
        impact: 'Cannot isolate compromised compute resources',
      },
      {
        id: 'aws:s3:block-public-access',
        description: 'Block public S3 access',
        impact: 'Cannot automatically remediate S3 data exposure',
      },
      {
        id: 'aws:cloudtrail:lookup-events',
        description: 'Query CloudTrail for investigation',
        impact: 'AI cannot investigate attack history — reduced reasoning quality',
      },
      {
        id: 'aws:ec2:revoke-sg-ingress',
        description: 'Block malicious IPs via security groups',
        impact: 'Cannot automatically block network-based attacks',
      },
    ];

    for (const cap of criticalCapabilities) {
      if (!availableIds.has(cap.id)) {
        gaps.push({
          missing_action_id: cap.id,
          description: cap.description,
          impact: cap.impact,
          required_iam_permission: this.getRequiredPermission(cap.id),
        });
      }
    }

    return gaps;
  }

  private getRequiredPermission(actionId: string): string {
    for (const [permission, actionIds] of Object.entries(PERMISSION_TO_ACTIONS)) {
      if (actionIds.includes(actionId)) return permission;
    }
    return 'unknown';
  }
}

// ============================================================================
// Supporting Types
// ============================================================================

/** Human-readable summary of what Watcher can do in an AWS account. */
export interface CapabilitySummary {
  connector_id: string;
  account_id: string;
  total_actions: number;
  data_sources: AwsDataSource[];
  actions_by_blast_radius: Record<BlastRadius, string[]>;
  capability_gaps: CapabilityGap[];
  can_respond_autonomously: boolean;
}

/** A missing capability that limits Watcher's effectiveness. */
export interface CapabilityGap {
  missing_action_id: string;
  description: string;
  impact: string;
  required_iam_permission: string;
}
