/**
 * AWS Connector (Task 15)
 *
 * Real AWS data ingestion using AWS SDK v3.
 * Polls CloudTrail, GuardDuty, Security Hub, and Config for events
 * and feeds them into the event pipeline.
 *
 * Authentication: cross-account IAM role assumption (AssumeRole).
 * Each tenant provides a role ARN that Watcher assumes to access their account.
 */

import {
  CloudTrailClient,
  LookupEventsCommand,
  LookupEventsCommandInput,
} from '@aws-sdk/client-cloudtrail';

import {
  GuardDutyClient,
  ListFindingsCommand,
  GetFindingsCommand,
} from '@aws-sdk/client-guardduty';

import {
  SecurityHubClient,
  GetFindingsCommand as SHGetFindingsCommand,
} from '@aws-sdk/client-securityhub';

import {
  STSClient,
  AssumeRoleCommand,
} from '@aws-sdk/client-sts';

import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';

import { RawAwsEvent, AwsDataSource } from '../types/index.js';

// ============================================================================
// Credential Helper
// ============================================================================

/**
 * Creates AWS SDK credentials by assuming a cross-account IAM role.
 * This is how Watcher accesses customer AWS accounts without storing
 * long-lived credentials.
 */
export function createAssumedRoleCredentials(roleArn: string, region: string) {
  return fromTemporaryCredentials({
    params: {
      RoleArn: roleArn,
      RoleSessionName: 'WatcherMK1-Session',
      DurationSeconds: 3600,
    },
    clientConfig: { region },
  });
}

// ============================================================================
// CloudTrail Poller
// ============================================================================

export interface CloudTrailPollerConfig {
  roleArn: string;
  region: string;
  tenantId: string;
  accountId: string;
  /** How far back to look on first poll (minutes). Default: 60. */
  lookbackMinutes: number;
}

export class CloudTrailPoller {
  private readonly config: CloudTrailPollerConfig;
  private lastPollTime: Date;

  constructor(config: CloudTrailPollerConfig) {
    this.config = config;
    this.lastPollTime = new Date(Date.now() - config.lookbackMinutes * 60 * 1000);
  }

  /**
   * Polls CloudTrail for events since the last poll.
   * Returns normalized raw events ready for the pipeline.
   */
  async poll(): Promise<RawAwsEvent[]> {
    const credentials = createAssumedRoleCredentials(this.config.roleArn, this.config.region);
    const client = new CloudTrailClient({ region: this.config.region, credentials });

    const startTime = this.lastPollTime;
    const endTime = new Date();

    const input: LookupEventsCommandInput = {
      StartTime: startTime,
      EndTime: endTime,
      MaxResults: 50,
    };

    const events: RawAwsEvent[] = [];

    try {
      const response = await client.send(new LookupEventsCommand(input));

      for (const event of response.Events ?? []) {
        if (!event.CloudTrailEvent) continue;

        let payload: Record<string, unknown>;
        try {
          payload = JSON.parse(event.CloudTrailEvent) as Record<string, unknown>;
        } catch {
          continue;
        }

        events.push({
          source: AwsDataSource.CLOUDTRAIL,
          connector_id: `cloudtrail-${this.config.accountId}`,
          tenant_id: this.config.tenantId,
          account_id: this.config.accountId,
          region: this.config.region,
          raw_payload: payload,
          received_at: new Date().toISOString(),
        });
      }

      this.lastPollTime = endTime;
    } catch (err) {
      // Log but don't throw — polling failures are non-fatal
      console.error(`[CloudTrailPoller] Poll failed for ${this.config.accountId}:`, err);
    }

    return events;
  }
}

// ============================================================================
// GuardDuty Poller
// ============================================================================

export interface GuardDutyPollerConfig {
  roleArn: string;
  region: string;
  tenantId: string;
  accountId: string;
  detectorId: string;
}

export class GuardDutyPoller {
  private readonly config: GuardDutyPollerConfig;
  private readonly processedFindingIds = new Set<string>();

  constructor(config: GuardDutyPollerConfig) {
    this.config = config;
  }

  /**
   * Polls GuardDuty for new findings.
   * Deduplicates against already-processed finding IDs.
   */
  async poll(): Promise<RawAwsEvent[]> {
    const credentials = createAssumedRoleCredentials(this.config.roleArn, this.config.region);
    const client = new GuardDutyClient({ region: this.config.region, credentials });

    const events: RawAwsEvent[] = [];

    try {
      // List active findings
      const listResponse = await client.send(new ListFindingsCommand({
        DetectorId: this.config.detectorId,
        FindingCriteria: {
          Criterion: {
            'service.archived': { Eq: ['false'] },
          },
        },
        MaxResults: 50,
      }));

      const findingIds = (listResponse.FindingIds ?? []).filter(
        (id) => !this.processedFindingIds.has(id)
      );

      if (findingIds.length === 0) return events;

      // Get full finding details
      const getResponse = await client.send(new GetFindingsCommand({
        DetectorId: this.config.detectorId,
        FindingIds: findingIds,
      }));

      for (const finding of getResponse.Findings ?? []) {
        if (!finding.Id) continue;

        events.push({
          source: AwsDataSource.GUARDDUTY,
          connector_id: `guardduty-${this.config.accountId}`,
          tenant_id: this.config.tenantId,
          account_id: this.config.accountId,
          region: this.config.region,
          raw_payload: finding as unknown as Record<string, unknown>,
          received_at: new Date().toISOString(),
        });

        this.processedFindingIds.add(finding.Id);
      }
    } catch (err) {
      console.error(`[GuardDutyPoller] Poll failed for ${this.config.accountId}:`, err);
    }

    return events;
  }
}

// ============================================================================
// Security Hub Poller
// ============================================================================

export interface SecurityHubPollerConfig {
  roleArn: string;
  region: string;
  tenantId: string;
  accountId: string;
}

export class SecurityHubPoller {
  private readonly config: SecurityHubPollerConfig;
  private lastPollTime: Date;

  constructor(config: SecurityHubPollerConfig) {
    this.config = config;
    this.lastPollTime = new Date(Date.now() - 60 * 60 * 1000); // 1 hour lookback
  }

  async poll(): Promise<RawAwsEvent[]> {
    const credentials = createAssumedRoleCredentials(this.config.roleArn, this.config.region);
    const client = new SecurityHubClient({ region: this.config.region, credentials });

    const events: RawAwsEvent[] = [];
    const endTime = new Date();

    try {
      const response = await client.send(new SHGetFindingsCommand({
        Filters: {
          UpdatedAt: [{
            Start: this.lastPollTime.toISOString(),
            End: endTime.toISOString(),
          }],
          WorkflowStatus: [{ Value: 'NEW', Comparison: 'EQUALS' }],
          RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
        },
        MaxResults: 50,
      }));

      for (const finding of response.Findings ?? []) {
        events.push({
          source: AwsDataSource.SECURITY_HUB,
          connector_id: `securityhub-${this.config.accountId}`,
          tenant_id: this.config.tenantId,
          account_id: this.config.accountId,
          region: this.config.region,
          raw_payload: finding as unknown as Record<string, unknown>,
          received_at: new Date().toISOString(),
        });
      }

      this.lastPollTime = endTime;
    } catch (err) {
      console.error(`[SecurityHubPoller] Poll failed for ${this.config.accountId}:`, err);
    }

    return events;
  }
}

// ============================================================================
// AWS Action Executor (real AWS API calls)
// ============================================================================

import {
  IAMClient,
  UpdateAccessKeyCommand,
  DeleteAccessKeyCommand,
  AttachUserPolicyCommand,
  DetachUserPolicyCommand,
  ListAccessKeysCommand,
} from '@aws-sdk/client-iam';

import {
  EC2Client,
  StopInstancesCommand,
  StartInstancesCommand,
  RevokeSecurityGroupIngressCommand,
  AuthorizeSecurityGroupIngressCommand,
  DescribeInstancesCommand,
} from '@aws-sdk/client-ec2';

import {
  S3Client,
  PutBucketPolicyCommand,
  PutPublicAccessBlockCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';

import type { AwsApiClient, AwsApiResult } from '../execution/action-executor.js';

/**
 * Real AWS API client that executes actions using assumed-role credentials.
 */
export class RealAwsApiClient implements AwsApiClient {
  async execute(
    service: string,
    apiCall: string,
    params: Record<string, unknown>,
    roleArn: string
  ): Promise<AwsApiResult> {
    // Infer region from role ARN or default to us-east-1
    const region = this.inferRegion(roleArn);
    const credentials = createAssumedRoleCredentials(roleArn, region);

    try {
      const response = await this.dispatch(service, apiCall, params, region, credentials);
      return {
        success: true,
        requestId: (response as any)?.$metadata?.requestId,
        response: response as Record<string, unknown>,
      };
    } catch (err: unknown) {
      const error = err as { name?: string; message?: string; $metadata?: { requestId?: string } };
      return {
        success: false,
        requestId: error.$metadata?.requestId,
        errorCode: error.name,
        errorMessage: error.message,
      };
    }
  }

  private async dispatch(
    service: string,
    apiCall: string,
    params: Record<string, unknown>,
    region: string,
    credentials: ReturnType<typeof createAssumedRoleCredentials>
  ): Promise<unknown> {
    switch (`${service}:${apiCall}`) {
      // IAM
      case 'iam:UpdateAccessKey':
        return new IAMClient({ region, credentials }).send(
          new UpdateAccessKeyCommand(params as any)
        );
      case 'iam:DeleteAccessKey':
        return new IAMClient({ region, credentials }).send(
          new DeleteAccessKeyCommand(params as any)
        );
      case 'iam:AttachUserPolicy':
        return new IAMClient({ region, credentials }).send(
          new AttachUserPolicyCommand(params as any)
        );
      case 'iam:DetachUserPolicy':
        return new IAMClient({ region, credentials }).send(
          new DetachUserPolicyCommand(params as any)
        );
      case 'iam:ListAccessKeys':
        return new IAMClient({ region, credentials }).send(
          new ListAccessKeysCommand(params as any)
        );

      // EC2
      case 'ec2:StopInstances':
        return new EC2Client({ region, credentials }).send(
          new StopInstancesCommand(params as any)
        );
      case 'ec2:StartInstances':
        return new EC2Client({ region, credentials }).send(
          new StartInstancesCommand(params as any)
        );
      case 'ec2:RevokeSecurityGroupIngress':
        return new EC2Client({ region, credentials }).send(
          new RevokeSecurityGroupIngressCommand(params as any)
        );
      case 'ec2:AuthorizeSecurityGroupIngress':
        return new EC2Client({ region, credentials }).send(
          new AuthorizeSecurityGroupIngressCommand(params as any)
        );
      case 'ec2:DescribeInstances':
        return new EC2Client({ region, credentials }).send(
          new DescribeInstancesCommand(params as any)
        );

      // S3
      case 's3:PutBucketPolicy':
        return new S3Client({ region, credentials }).send(
          new PutBucketPolicyCommand(params as any)
        );
      case 's3:PutPublicAccessBlock':
        return new S3Client({ region, credentials }).send(
          new PutPublicAccessBlockCommand(params as any)
        );
      case 's3:GetPublicAccessBlock':
        return new S3Client({ region, credentials }).send(
          new GetPublicAccessBlockCommand(params as any)
        );

      default:
        throw new Error(`Unsupported AWS API call: ${service}:${apiCall}`);
    }
  }

  private inferRegion(roleArn: string): string {
    // Role ARNs don't contain region — use environment variable or default
    return process.env['AWS_REGION'] ?? 'us-east-1';
  }
}
