/**
 * Tests for the AWS-Native Telemetry Normalizer.
 * Covers CloudTrail, GuardDuty, Security Hub, and AWS Config normalization.
 */

import { describe, it, expect } from 'vitest';
import {
  normalizeAwsEvent,
  normalizeCloudTrailEvent,
  normalizeGuardDutyFinding,
  normalizeSecurityHubFinding,
  normalizeAwsConfigEvent,
  inferAttackSurface,
  CloudTrailEvent,
  GuardDutyFinding,
  SecurityHubFinding,
  AwsConfigEvent,
} from './aws-normalizer.js';
import { AttackSurface, AwsDataSource, RawAwsEvent } from '../types/index.js';

// ── Fixtures ─────────────────────────────────────────────────────────────────

function makeRawEvent(source: AwsDataSource, payload: Record<string, unknown>): RawAwsEvent {
  return {
    source,
    connector_id: 'conn-aws-001',
    tenant_id: 'tenant-abc',
    account_id: '123456789012',
    region: 'us-east-1',
    raw_payload: payload,
    received_at: '2024-06-01T10:00:00Z',
  };
}

// ── inferAttackSurface ────────────────────────────────────────────────────────

describe('inferAttackSurface', () => {
  it('maps IAM resource types to CLOUD_IAM', () => {
    expect(inferAttackSurface('AWS::IAM::User')).toBe(AttackSurface.CLOUD_IAM);
    expect(inferAttackSurface('AWS::IAM::Role')).toBe(AttackSurface.CLOUD_IAM);
    expect(inferAttackSurface('AWS::IAM::Policy')).toBe(AttackSurface.CLOUD_IAM);
  });

  it('maps EC2 resource types to CLOUD_COMPUTE', () => {
    expect(inferAttackSurface('AWS::EC2::Instance')).toBe(AttackSurface.CLOUD_COMPUTE);
    expect(inferAttackSurface('AWS::AutoScaling::AutoScalingGroup')).toBe(AttackSurface.CLOUD_COMPUTE);
  });

  it('maps S3 resource types to CLOUD_STORAGE', () => {
    expect(inferAttackSurface('AWS::S3::Bucket')).toBe(AttackSurface.CLOUD_STORAGE);
  });

  it('maps VPC/network resource types to CLOUD_NETWORK', () => {
    expect(inferAttackSurface('AWS::EC2::VPC')).toBe(AttackSurface.CLOUD_NETWORK);
    expect(inferAttackSurface('AWS::ElasticLoadBalancing::LoadBalancer')).toBe(AttackSurface.CLOUD_NETWORK);
  });

  it('maps Lambda/serverless resource types to CLOUD_SERVERLESS', () => {
    expect(inferAttackSurface('AWS::Lambda::Function')).toBe(AttackSurface.CLOUD_SERVERLESS);
    expect(inferAttackSurface('AWS::ApiGateway::RestApi')).toBe(AttackSurface.CLOUD_SERVERLESS);
  });

  it('maps RDS/database resource types to CLOUD_DATABASE', () => {
    expect(inferAttackSurface('AWS::RDS::DBInstance')).toBe(AttackSurface.CLOUD_DATABASE);
    expect(inferAttackSurface('AWS::DynamoDB::Table')).toBe(AttackSurface.CLOUD_DATABASE);
  });

  it('maps EKS/container resource types to CLOUD_CONTAINER', () => {
    expect(inferAttackSurface('AWS::EKS::Cluster')).toBe(AttackSurface.CLOUD_CONTAINER);
    expect(inferAttackSurface('AWS::ECS::Cluster')).toBe(AttackSurface.CLOUD_CONTAINER);
  });

  it('maps CodePipeline/CI-CD resource types to CLOUD_CICD', () => {
    expect(inferAttackSurface('AWS::CodePipeline::Pipeline')).toBe(AttackSurface.CLOUD_CICD);
    expect(inferAttackSurface('AWS::CodeBuild::Project')).toBe(AttackSurface.CLOUD_CICD);
  });

  it('uses eventSource as fallback for surface inference', () => {
    expect(inferAttackSurface('Unknown', 'iam.amazonaws.com')).toBe(AttackSurface.CLOUD_IAM);
    expect(inferAttackSurface('Unknown', 's3.amazonaws.com')).toBe(AttackSurface.CLOUD_STORAGE);
    expect(inferAttackSurface('Unknown', 'lambda.amazonaws.com')).toBe(AttackSurface.CLOUD_SERVERLESS);
  });

  it('defaults to CLOUD_IAM for unknown resource types', () => {
    expect(inferAttackSurface('AWS::Unknown::Resource')).toBe(AttackSurface.CLOUD_IAM);
    expect(inferAttackSurface('')).toBe(AttackSurface.CLOUD_IAM);
  });
});

// ── CloudTrail Normalizer ─────────────────────────────────────────────────────

describe('normalizeCloudTrailEvent', () => {
  it('normalizes a basic IAM user API call', () => {
    const payload: CloudTrailEvent = {
      eventVersion: '1.08',
      userIdentity: {
        type: 'IAMUser',
        principalId: 'AIDAEXAMPLE',
        arn: 'arn:aws:iam::123456789012:user/alice',
        accountId: '123456789012',
        userName: 'alice',
      },
      eventTime: '2024-06-01T10:00:00Z',
      eventSource: 'iam.amazonaws.com',
      eventName: 'CreateAccessKey',
      awsRegion: 'us-east-1',
      sourceIPAddress: '203.0.113.42',
      userAgent: 'aws-cli/2.0',
      resources: [
        { ARN: 'arn:aws:iam::123456789012:user/alice', type: 'AWS::IAM::User' },
      ],
      recipientAccountId: '123456789012',
    };

    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeCloudTrailEvent(raw);

    expect(result.id).toBeDefined();
    expect(result.tenant_id).toBe('tenant-abc');
    expect(result.account_id).toBe('123456789012');
    expect(result.region).toBe('us-east-1');
    expect(result.source).toBe(AwsDataSource.CLOUDTRAIL);
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_IAM);
    expect(result.event_type).toBe('iam:CreateAccessKey');
    expect(result.actor.type).toBe('IAM_USER');
    expect(result.actor.identifier).toBe('arn:aws:iam::123456789012:user/alice');
    expect(result.actor.account_id).toBe('123456789012');
    expect(result.target.resource_type).toBe('AWS::IAM::User');
    expect(result.target.resource_id).toBe('arn:aws:iam::123456789012:user/alice');
    expect(result.source_ip).toBe('203.0.113.42');
    expect(result.user_agent).toBe('aws-cli/2.0');
    expect(result.ingestion_timestamp).toBe('2024-06-01T10:00:00Z');
  });

  it('normalizes an AssumedRole event', () => {
    const payload: CloudTrailEvent = {
      userIdentity: {
        type: 'AssumedRole',
        principalId: 'AROAEXAMPLE:session',
        arn: 'arn:aws:sts::123456789012:assumed-role/AdminRole/session',
        accountId: '123456789012',
        sessionContext: {
          sessionIssuer: {
            type: 'Role',
            arn: 'arn:aws:iam::123456789012:role/AdminRole',
          },
        },
      },
      eventSource: 'ec2.amazonaws.com',
      eventName: 'StopInstances',
      awsRegion: 'us-west-2',
      sourceIPAddress: '198.51.100.10',
      resources: [
        { ARN: 'arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123', type: 'AWS::EC2::Instance' },
      ],
      recipientAccountId: '123456789012',
    };

    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeCloudTrailEvent(raw);

    expect(result.actor.type).toBe('IAM_ROLE');
    expect(result.actor.identifier).toBe('arn:aws:sts::123456789012:assumed-role/AdminRole/session');
    expect(result.actor.session_context).toBe('arn:aws:iam::123456789012:role/AdminRole');
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_COMPUTE);
    expect(result.event_type).toBe('ec2:StopInstances');
    expect(result.region).toBe('us-west-2');
  });

  it('normalizes a Root account event', () => {
    const payload: CloudTrailEvent = {
      userIdentity: {
        type: 'Root',
        accountId: '123456789012',
      },
      eventSource: 'iam.amazonaws.com',
      eventName: 'DeleteAccountPasswordPolicy',
      awsRegion: 'us-east-1',
      sourceIPAddress: '10.0.0.1',
      recipientAccountId: '123456789012',
    };

    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeCloudTrailEvent(raw);

    expect(result.actor.type).toBe('IAM_USER');
    expect(result.actor.identifier).toBe('arn:aws:iam::123456789012:root');
  });

  it('normalizes an AWS service event (no user identity)', () => {
    const payload: CloudTrailEvent = {
      userIdentity: {
        type: 'AWSService',
        invokedBy: 'cloudformation.amazonaws.com',
        accountId: '123456789012',
      },
      eventSource: 's3.amazonaws.com',
      eventName: 'CreateBucket',
      awsRegion: 'eu-west-1',
      resources: [
        { ARN: 'arn:aws:s3:::my-bucket', type: 'AWS::S3::Bucket' },
      ],
      recipientAccountId: '123456789012',
    };

    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeCloudTrailEvent(raw);

    expect(result.actor.type).toBe('AWS_SERVICE');
    expect(result.actor.identifier).toBe('cloudformation.amazonaws.com');
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_STORAGE);
    expect(result.event_type).toBe('s3:CreateBucket');
  });

  it('handles missing sourceIPAddress gracefully (AWS internal calls)', () => {
    const payload: CloudTrailEvent = {
      userIdentity: { type: 'AWSService', invokedBy: 'lambda.amazonaws.com' },
      eventSource: 'iam.amazonaws.com',
      eventName: 'GetRole',
      awsRegion: 'us-east-1',
      sourceIPAddress: 'AWS Internal',
      recipientAccountId: '123456789012',
    };

    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeCloudTrailEvent(raw);

    // "AWS Internal" should not be returned as a source IP
    expect(result.source_ip).toBeUndefined();
  });

  it('handles missing resources array by falling back to eventSource', () => {
    const payload: CloudTrailEvent = {
      userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/bob', accountId: '123456789012' },
      eventSource: 'rds.amazonaws.com',
      eventName: 'CreateDBInstance',
      awsRegion: 'us-east-1',
      recipientAccountId: '123456789012',
    };

    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeCloudTrailEvent(raw);

    expect(result.target.resource_type).toBe('rds.amazonaws.com');
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_DATABASE);
  });

  it('generates unique IDs for each normalized event', () => {
    const payload: CloudTrailEvent = {
      userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/alice', accountId: '123456789012' },
      eventSource: 'iam.amazonaws.com',
      eventName: 'ListUsers',
      awsRegion: 'us-east-1',
      recipientAccountId: '123456789012',
    };
    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);

    const r1 = normalizeCloudTrailEvent(raw);
    const r2 = normalizeCloudTrailEvent(raw);

    expect(r1.id).not.toBe(r2.id);
  });
});

// ── GuardDuty Normalizer ──────────────────────────────────────────────────────

describe('normalizeGuardDutyFinding', () => {
  it('normalizes a credential compromise finding (IAM access key)', () => {
    const payload: GuardDutyFinding = {
      id: 'gd-finding-001',
      accountId: '123456789012',
      region: 'us-east-1',
      type: 'UnauthorizedAccess:IAMUser/MaliciousIPCaller',
      title: 'API call from a known malicious IP',
      severity: 8.0,
      createdAt: '2024-06-01T10:00:00Z',
      service: {
        action: {
          actionType: 'AWS_API_CALL',
          awsApiCallAction: {
            api: 'ListBuckets',
            serviceName: 's3.amazonaws.com',
            remoteIpDetails: {
              ipAddressV4: '198.51.100.99',
              country: { countryName: 'Russia' },
            },
          },
        },
      },
      resource: {
        resourceType: 'AccessKey',
        accessKeyDetails: {
          accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
          principalId: 'AIDAEXAMPLE',
          userType: 'IAMUser',
          userName: 'svc-account',
        },
      },
    };

    const raw = makeRawEvent(AwsDataSource.GUARDDUTY, payload as Record<string, unknown>);
    const result = normalizeGuardDutyFinding(raw);

    expect(result.source).toBe(AwsDataSource.GUARDDUTY);
    expect(result.event_type).toBe('UnauthorizedAccess:IAMUser/MaliciousIPCaller');
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_IAM);
    expect(result.actor.type).toBe('IAM_USER');
    expect(result.actor.identifier).toBe('AIDAEXAMPLE');
    expect(result.target.resource_type).toBe('AWS::IAM::AccessKey');
    expect(result.target.resource_name).toBe('AKIAIOSFODNN7EXAMPLE');
    expect(result.source_ip).toBe('198.51.100.99');
    expect(result.region).toBe('us-east-1');
  });

  it('normalizes an EC2 instance finding (crypto mining)', () => {
    const payload: GuardDutyFinding = {
      id: 'gd-finding-002',
      accountId: '123456789012',
      region: 'us-west-2',
      type: 'CryptoCurrency:EC2/BitcoinTool.B!DNS',
      title: 'EC2 instance querying a domain associated with cryptocurrency',
      severity: 5.0,
      service: {
        action: {
          actionType: 'DNS_REQUEST',
        },
      },
      resource: {
        resourceType: 'Instance',
        instanceDetails: {
          instanceId: 'i-0abc123def456',
          instanceType: 't3.medium',
          tags: [{ key: 'Name', value: 'prod-worker-01' }],
        },
      },
    };

    const raw = makeRawEvent(AwsDataSource.GUARDDUTY, payload as Record<string, unknown>);
    const result = normalizeGuardDutyFinding(raw);

    expect(result.attack_surface).toBe(AttackSurface.CLOUD_COMPUTE);
    expect(result.actor.type).toBe('AWS_SERVICE');
    expect(result.actor.identifier).toBe('ec2:i-0abc123def456');
    expect(result.target.resource_type).toBe('AWS::EC2::Instance');
    expect(result.target.resource_id).toContain('i-0abc123def456');
    expect(result.target.resource_name).toBe('i-0abc123def456');
  });

  it('normalizes an S3 bucket finding (data exfiltration)', () => {
    const payload: GuardDutyFinding = {
      id: 'gd-finding-003',
      accountId: '123456789012',
      region: 'us-east-1',
      type: 'Discovery:S3/MaliciousIPCaller',
      title: 'S3 API call from a known malicious IP',
      severity: 6.0,
      service: {
        action: {
          actionType: 'AWS_API_CALL',
          awsApiCallAction: {
            api: 'GetObject',
            serviceName: 's3.amazonaws.com',
            remoteIpDetails: { ipAddressV4: '203.0.113.5' },
          },
        },
      },
      resource: {
        resourceType: 'S3Bucket',
        s3BucketDetails: [
          { arn: 'arn:aws:s3:::sensitive-data-bucket', name: 'sensitive-data-bucket', type: 'Destination' },
        ],
      },
    };

    const raw = makeRawEvent(AwsDataSource.GUARDDUTY, payload as Record<string, unknown>);
    const result = normalizeGuardDutyFinding(raw);

    expect(result.attack_surface).toBe(AttackSurface.CLOUD_STORAGE);
    expect(result.target.resource_type).toBe('AWS::S3::Bucket');
    expect(result.target.resource_id).toBe('arn:aws:s3:::sensitive-data-bucket');
    expect(result.target.resource_name).toBe('sensitive-data-bucket');
    expect(result.source_ip).toBe('203.0.113.5');
  });

  it('normalizes an EKS finding', () => {
    const payload: GuardDutyFinding = {
      id: 'gd-finding-004',
      accountId: '123456789012',
      region: 'us-east-1',
      type: 'Execution:EKS/ExecInPod',
      title: 'Command executed in a pod',
      severity: 5.0,
      resource: {
        resourceType: 'EKSCluster',
        eksClusterDetails: {
          name: 'prod-cluster',
          arn: 'arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster',
        },
      },
    };

    const raw = makeRawEvent(AwsDataSource.GUARDDUTY, payload as Record<string, unknown>);
    const result = normalizeGuardDutyFinding(raw);

    expect(result.attack_surface).toBe(AttackSurface.CLOUD_CONTAINER);
    expect(result.target.resource_type).toBe('AWS::EKS::Cluster');
    expect(result.target.resource_name).toBe('prod-cluster');
  });

  it('extracts source IP from network connection action', () => {
    const payload: GuardDutyFinding = {
      accountId: '123456789012',
      region: 'us-east-1',
      type: 'Backdoor:EC2/C&CActivity.B',
      service: {
        action: {
          actionType: 'NETWORK_CONNECTION',
          networkConnectionAction: {
            remoteIpDetails: { ipAddressV4: '10.20.30.40' },
            remotePortDetails: { port: 4444 },
            protocol: 'TCP',
          },
        },
      },
      resource: {
        resourceType: 'Instance',
        instanceDetails: { instanceId: 'i-0xyz' },
      },
    };

    const raw = makeRawEvent(AwsDataSource.GUARDDUTY, payload as Record<string, unknown>);
    const result = normalizeGuardDutyFinding(raw);

    expect(result.source_ip).toBe('10.20.30.40');
  });
});

// ── Security Hub Normalizer ───────────────────────────────────────────────────

describe('normalizeSecurityHubFinding', () => {
  it('normalizes a Security Hub finding for an IAM misconfiguration', () => {
    const payload: SecurityHubFinding = {
      SchemaVersion: '2018-10-08',
      Id: 'arn:aws:securityhub:us-east-1:123456789012:finding/abc123',
      ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
      ProductName: 'Security Hub',
      CompanyName: 'AWS',
      AwsAccountId: '123456789012',
      Types: ['Software and Configuration Checks/AWS Security Best Practices/IAM'],
      Title: 'IAM root user access key should not exist',
      Description: 'The root account has an active access key.',
      Severity: { Label: 'CRITICAL', Normalized: 90 },
      Resources: [
        {
          Type: 'AwsIamUser',
          Id: 'arn:aws:iam::123456789012:root',
          Region: 'us-east-1',
        },
      ],
      Compliance: { Status: 'FAILED' },
      CreatedAt: '2024-06-01T10:00:00Z',
    };

    const raw = makeRawEvent(AwsDataSource.SECURITY_HUB, payload as Record<string, unknown>);
    const result = normalizeSecurityHubFinding(raw);

    expect(result.source).toBe(AwsDataSource.SECURITY_HUB);
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_IAM);
    expect(result.event_type).toBe('securityhub:IAM');
    expect(result.target.resource_type).toBe('AwsIamUser');
    expect(result.target.resource_id).toBe('arn:aws:iam::123456789012:root');
    expect(result.region).toBe('us-east-1');
    expect(result.tenant_id).toBe('tenant-abc');
  });

  it('normalizes a Security Hub finding for an EC2 vulnerability', () => {
    const payload: SecurityHubFinding = {
      AwsAccountId: '123456789012',
      Types: ['Software and Configuration Checks/Vulnerabilities/CVE'],
      Title: 'EC2 instance has critical CVE',
      Severity: { Label: 'HIGH', Normalized: 70 },
      Resources: [
        {
          Type: 'AwsEc2Instance',
          Id: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0abc',
          Region: 'us-east-1',
        },
      ],
      Network: { SourceIpV4: '192.0.2.1' },
    };

    const raw = makeRawEvent(AwsDataSource.SECURITY_HUB, payload as Record<string, unknown>);
    const result = normalizeSecurityHubFinding(raw);

    expect(result.attack_surface).toBe(AttackSurface.CLOUD_COMPUTE);
    expect(result.source_ip).toBe('192.0.2.1');
    expect(result.event_type).toBe('securityhub:CVE');
  });

  it('normalizes a Security Hub finding with no Types array', () => {
    const payload: SecurityHubFinding = {
      AwsAccountId: '123456789012',
      Title: 'S3 bucket is publicly accessible',
      Severity: { Label: 'HIGH' },
      Resources: [
        { Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::public-bucket', Region: 'us-east-1' },
      ],
    };

    const raw = makeRawEvent(AwsDataSource.SECURITY_HUB, payload as Record<string, unknown>);
    const result = normalizeSecurityHubFinding(raw);

    expect(result.attack_surface).toBe(AttackSurface.CLOUD_STORAGE);
    expect(result.event_type).toBe('securityhub:S3 bucket is publicly accessible');
  });

  it('handles missing Resources array gracefully', () => {
    const payload: SecurityHubFinding = {
      AwsAccountId: '123456789012',
      Types: ['TTPs/Initial Access'],
      Title: 'Suspicious login detected',
    };

    const raw = makeRawEvent(AwsDataSource.SECURITY_HUB, payload as Record<string, unknown>);
    const result = normalizeSecurityHubFinding(raw);

    expect(result.target.resource_type).toBe('Unknown');
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_IAM);
  });
});

// ── AWS Config Normalizer ─────────────────────────────────────────────────────

describe('normalizeAwsConfigEvent', () => {
  it('normalizes a Config configuration change for an IAM policy', () => {
    const payload: AwsConfigEvent = {
      configurationItemDiff: {
        changeType: 'UPDATE',
        changedProperties: {
          'PolicyDocument': {
            previousValue: '{"Version":"2012-10-17","Statement":[]}',
            updatedValue: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
          },
        },
      },
      configurationItem: {
        configurationItemStatus: 'OK',
        resourceType: 'AWS::IAM::Policy',
        resourceId: 'ANPAEXAMPLE',
        resourceName: 'AdminPolicy',
        arn: 'arn:aws:iam::123456789012:policy/AdminPolicy',
        awsRegion: 'us-east-1',
        awsAccountId: '123456789012',
        configurationItemCaptureTime: '2024-06-01T10:00:00Z',
      },
      messageType: 'ConfigurationItemChangeNotification',
    };

    const raw = makeRawEvent(AwsDataSource.CONFIG, payload as Record<string, unknown>);
    const result = normalizeAwsConfigEvent(raw);

    expect(result.source).toBe(AwsDataSource.CONFIG);
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_IAM);
    expect(result.event_type).toBe('config:UPDATE:AWS::IAM::Policy');
    expect(result.target.resource_type).toBe('AWS::IAM::Policy');
    expect(result.target.resource_id).toBe('arn:aws:iam::123456789012:policy/AdminPolicy');
    expect(result.target.resource_name).toBe('AdminPolicy');
    expect(result.actor.type).toBe('AWS_SERVICE');
    expect(result.actor.identifier).toBe('config.amazonaws.com');
    expect(result.region).toBe('us-east-1');
  });

  it('normalizes a Config CREATE event for an S3 bucket', () => {
    const payload: AwsConfigEvent = {
      configurationItemDiff: { changeType: 'CREATE' },
      configurationItem: {
        resourceType: 'AWS::S3::Bucket',
        resourceId: 'my-new-bucket',
        resourceName: 'my-new-bucket',
        arn: 'arn:aws:s3:::my-new-bucket',
        awsRegion: 'eu-west-1',
        awsAccountId: '123456789012',
      },
    };

    const raw = makeRawEvent(AwsDataSource.CONFIG, payload as Record<string, unknown>);
    const result = normalizeAwsConfigEvent(raw);

    expect(result.attack_surface).toBe(AttackSurface.CLOUD_STORAGE);
    expect(result.event_type).toBe('config:CREATE:AWS::S3::Bucket');
    expect(result.region).toBe('eu-west-1');
  });

  it('handles missing configurationItemDiff gracefully', () => {
    const payload: AwsConfigEvent = {
      configurationItem: {
        resourceType: 'AWS::EC2::SecurityGroup',
        resourceId: 'sg-0abc123',
        arn: 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123',
        awsRegion: 'us-east-1',
        awsAccountId: '123456789012',
      },
    };

    const raw = makeRawEvent(AwsDataSource.CONFIG, payload as Record<string, unknown>);
    const result = normalizeAwsConfigEvent(raw);

    // Should default changeType to UPDATE
    expect(result.event_type).toBe('config:UPDATE:AWS::EC2::SecurityGroup');
    expect(result.attack_surface).toBe(AttackSurface.CLOUD_COMPUTE);
  });
});

// ── Main Dispatcher ───────────────────────────────────────────────────────────

describe('normalizeAwsEvent (dispatcher)', () => {
  it('routes CloudTrail events to the CloudTrail normalizer', () => {
    const payload: CloudTrailEvent = {
      userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/alice', accountId: '123456789012' },
      eventSource: 'iam.amazonaws.com',
      eventName: 'ListUsers',
      awsRegion: 'us-east-1',
      recipientAccountId: '123456789012',
    };
    const raw = makeRawEvent(AwsDataSource.CLOUDTRAIL, payload as Record<string, unknown>);
    const result = normalizeAwsEvent(raw);

    expect(result.source).toBe(AwsDataSource.CLOUDTRAIL);
    expect(result.event_type).toBe('iam:ListUsers');
  });

  it('routes GuardDuty events to the GuardDuty normalizer', () => {
    const payload: GuardDutyFinding = {
      accountId: '123456789012',
      region: 'us-east-1',
      type: 'Recon:IAMUser/MaliciousIPCaller',
      resource: {
        resourceType: 'AccessKey',
        accessKeyDetails: { accessKeyId: 'AKIAEXAMPLE', userName: 'test-user', userType: 'IAMUser' },
      },
    };
    const raw = makeRawEvent(AwsDataSource.GUARDDUTY, payload as Record<string, unknown>);
    const result = normalizeAwsEvent(raw);

    expect(result.source).toBe(AwsDataSource.GUARDDUTY);
    expect(result.event_type).toBe('Recon:IAMUser/MaliciousIPCaller');
  });

  it('routes Security Hub events to the Security Hub normalizer', () => {
    const payload: SecurityHubFinding = {
      AwsAccountId: '123456789012',
      Types: ['TTPs/Privilege Escalation'],
      Title: 'Privilege escalation detected',
      Resources: [{ Type: 'AwsIamRole', Id: 'arn:aws:iam::123456789012:role/AdminRole', Region: 'us-east-1' }],
    };
    const raw = makeRawEvent(AwsDataSource.SECURITY_HUB, payload as Record<string, unknown>);
    const result = normalizeAwsEvent(raw);

    expect(result.source).toBe(AwsDataSource.SECURITY_HUB);
  });

  it('routes Config events to the Config normalizer', () => {
    const payload: AwsConfigEvent = {
      configurationItemDiff: { changeType: 'UPDATE' },
      configurationItem: {
        resourceType: 'AWS::IAM::Role',
        resourceId: 'AROAEXAMPLE',
        arn: 'arn:aws:iam::123456789012:role/MyRole',
        awsRegion: 'us-east-1',
        awsAccountId: '123456789012',
      },
    };
    const raw = makeRawEvent(AwsDataSource.CONFIG, payload as Record<string, unknown>);
    const result = normalizeAwsEvent(raw);

    expect(result.source).toBe(AwsDataSource.CONFIG);
    expect(result.event_type).toBe('config:UPDATE:AWS::IAM::Role');
  });

  it('throws for unsupported data sources', () => {
    const raw = makeRawEvent('VPC_FLOW_LOGS' as AwsDataSource, {});
    expect(() => normalizeAwsEvent(raw)).toThrow('Unsupported AWS data source');
  });

  it('produces a NormalizedEvent with all required fields for every source type', () => {
    const sources = [
      {
        source: AwsDataSource.CLOUDTRAIL,
        payload: {
          userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123456789012:user/u', accountId: '123456789012' },
          eventSource: 'iam.amazonaws.com', eventName: 'GetUser',
          awsRegion: 'us-east-1', recipientAccountId: '123456789012',
        },
      },
      {
        source: AwsDataSource.GUARDDUTY,
        payload: {
          accountId: '123456789012', region: 'us-east-1',
          type: 'Recon:IAMUser/MaliciousIPCaller',
          resource: { resourceType: 'AccessKey', accessKeyDetails: { accessKeyId: 'AKIA', userName: 'u', userType: 'IAMUser' } },
        },
      },
      {
        source: AwsDataSource.SECURITY_HUB,
        payload: {
          AwsAccountId: '123456789012', Types: ['TTPs/Test'],
          Resources: [{ Type: 'AwsIamUser', Id: 'arn:aws:iam::123456789012:user/u', Region: 'us-east-1' }],
        },
      },
      {
        source: AwsDataSource.CONFIG,
        payload: {
          configurationItemDiff: { changeType: 'UPDATE' },
          configurationItem: { resourceType: 'AWS::IAM::User', resourceId: 'u', arn: 'arn:aws:iam::123456789012:user/u', awsRegion: 'us-east-1', awsAccountId: '123456789012' },
        },
      },
    ];

    for (const { source, payload } of sources) {
      const raw = makeRawEvent(source, payload as Record<string, unknown>);
      const result = normalizeAwsEvent(raw);

      // All required fields must be present
      expect(result.id).toBeDefined();
      expect(result.tenant_id).toBe('tenant-abc');
      expect(result.connector_id).toBe('conn-aws-001');
      expect(result.account_id).toBe('123456789012');
      expect(result.region).toBeDefined();
      expect(result.source).toBe(source);
      expect(result.attack_surface).toBeDefined();
      expect(result.event_type).toBeDefined();
      expect(result.actor).toBeDefined();
      expect(result.actor.type).toBeDefined();
      expect(result.actor.identifier).toBeDefined();
      expect(result.target).toBeDefined();
      expect(result.target.resource_type).toBeDefined();
      expect(result.target.resource_id).toBeDefined();
      expect(result.raw_payload).toBeDefined();
      expect(result.ingestion_timestamp).toBe('2024-06-01T10:00:00Z');
    }
  });
});
