/**
 * AWS-Native Telemetry Normalizer
 *
 * Converts raw events from AWS data sources (CloudTrail, GuardDuty, Security Hub,
 * AWS Config) into the canonical NormalizedEvent schema consumed by the AI
 * Reasoning Engine.
 *
 * Design principle: This is pure data transformation — no detection logic,
 * no scoring, no rules. The AI reasons about the normalized events.
 */

import {
  NormalizedEvent,
  RawAwsEvent,
  EventActor,
  EventTarget,
  AttackSurface,
  AwsDataSource,
} from '../types/index.js';

// ============================================================================
// Helpers
// ============================================================================

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

/**
 * Maps an AWS resource type string to an AttackSurface enum value.
 * Used to classify what part of the AWS environment an event relates to.
 */
export function inferAttackSurface(resourceType: string, eventSource?: string): AttackSurface {
  const rt = (resourceType ?? '').toLowerCase();
  const es = (eventSource ?? '').toLowerCase();

  if (rt.includes('iam') || rt.includes('sts') || es.includes('iam') || es.includes('sts')) {
    return AttackSurface.CLOUD_IAM;
  }
  if (rt.includes('vpc') || rt.includes('elasticloadbalancing') || rt.includes('route53') ||
      rt.includes('cloudfront') || rt.includes('subnet') || rt.includes('networkacl') ||
      rt.includes('internetgateway') || es.includes('elasticloadbalancing') || es.includes('route53')) {
    return AttackSurface.CLOUD_NETWORK;
  }
  if (rt.includes('ec2') || rt.includes('autoscaling') || es.includes('ec2')) {
    return AttackSurface.CLOUD_COMPUTE;
  }
  if (rt.includes('s3') || rt.includes('glacier') || es.includes('s3')) {
    return AttackSurface.CLOUD_STORAGE;
  }
  if (rt.includes('lambda') || rt.includes('apigateway') || rt.includes('sqs') ||
      rt.includes('sns') || es.includes('lambda')) {
    return AttackSurface.CLOUD_SERVERLESS;
  }
  if (rt.includes('rds') || rt.includes('dynamodb') || rt.includes('redshift') ||
      rt.includes('elasticache') || es.includes('rds')) {
    return AttackSurface.CLOUD_DATABASE;
  }
  if (rt.includes('eks') || rt.includes('ecs') || rt.includes('ecr') ||
      rt.includes('container') || es.includes('eks')) {
    return AttackSurface.CLOUD_CONTAINER;
  }
  if (rt.includes('codepipeline') || rt.includes('codebuild') || rt.includes('codecommit') ||
      rt.includes('codedeploy') || es.includes('codepipeline')) {
    return AttackSurface.CLOUD_CICD;
  }

  // Default to IAM for unknown — most security-relevant events are identity-related
  return AttackSurface.CLOUD_IAM;
}

/**
 * Extracts the source IP from various CloudTrail sourceIPAddress formats.
 * CloudTrail sourceIPAddress can be an IP, "AWS Internal", or a service name.
 */
function extractSourceIp(sourceIPAddress?: string): string | undefined {
  if (!sourceIPAddress) return undefined;
  // Only return actual IP addresses, not service names like "cloudformation.amazonaws.com"
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(sourceIPAddress)) {
    return sourceIPAddress;
  }
  return undefined;
}

// ============================================================================
// CloudTrail Normalizer
// ============================================================================

/**
 * CloudTrail event structure (simplified — covers the fields we care about).
 * Full schema: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
 */
export interface CloudTrailEvent {
  eventVersion?: string;
  userIdentity?: {
    type?: string;
    principalId?: string;
    arn?: string;
    accountId?: string;
    userName?: string;
    sessionContext?: {
      sessionIssuer?: { type?: string; arn?: string; userName?: string };
      attributes?: { mfaAuthenticated?: string; creationDate?: string };
    };
    invokedBy?: string;
  };
  eventTime?: string;
  eventSource?: string;
  eventName?: string;
  awsRegion?: string;
  sourceIPAddress?: string;
  userAgent?: string;
  errorCode?: string;
  errorMessage?: string;
  requestParameters?: Record<string, unknown>;
  responseElements?: Record<string, unknown>;
  resources?: Array<{
    ARN?: string;
    accountId?: string;
    type?: string;
  }>;
  recipientAccountId?: string;
  managementEvent?: boolean;
  readOnly?: boolean;
}

/**
 * Normalizes a raw CloudTrail event into a NormalizedEvent.
 */
export function normalizeCloudTrailEvent(raw: RawAwsEvent): NormalizedEvent {
  const ct = raw.raw_payload as CloudTrailEvent;

  // Build actor from userIdentity
  const actor = buildCloudTrailActor(ct.userIdentity);

  // Build target from resources or eventSource
  const primaryResource = ct.resources?.[0];
  const resourceType = primaryResource?.type ?? ct.eventSource ?? 'Unknown';
  const resourceId = primaryResource?.ARN ?? `arn:aws:${ct.eventSource}:${ct.awsRegion}:${ct.recipientAccountId}:unknown`;

  const target: EventTarget = {
    resource_type: resourceType,
    resource_id: resourceId,
    attack_surface: inferAttackSurface(resourceType, ct.eventSource),
  };

  // Event type: combine eventSource + eventName for clarity
  // e.g. "iam.amazonaws.com:CreateUser" → "iam:CreateUser"
  const sourceName = (ct.eventSource ?? 'unknown').replace('.amazonaws.com', '');
  const eventType = `${sourceName}:${ct.eventName ?? 'Unknown'}`;

  return {
    id: generateId(),
    tenant_id: raw.tenant_id,
    connector_id: raw.connector_id,
    account_id: raw.account_id,
    region: ct.awsRegion ?? raw.region,
    source: AwsDataSource.CLOUDTRAIL,
    attack_surface: inferAttackSurface(resourceType, ct.eventSource),
    event_type: eventType,
    actor,
    target,
    source_ip: extractSourceIp(ct.sourceIPAddress),
    user_agent: ct.userAgent,
    raw_payload: raw.raw_payload,
    ingestion_timestamp: raw.received_at,
  };
}

function buildCloudTrailActor(userIdentity?: CloudTrailEvent['userIdentity']): EventActor {
  if (!userIdentity) {
    return { type: 'UNKNOWN', identifier: 'unknown' };
  }

  const type = userIdentity.type?.toUpperCase();

  switch (type) {
    case 'IAMUSER':
      return {
        type: 'IAM_USER',
        identifier: userIdentity.arn ?? userIdentity.userName ?? 'unknown',
        account_id: userIdentity.accountId,
        session_context: userIdentity.sessionContext?.attributes?.mfaAuthenticated
          ? `mfa:${userIdentity.sessionContext.attributes.mfaAuthenticated}`
          : undefined,
      };

    case 'ASSUMEDROLE':
    case 'ROLE':
      return {
        type: 'IAM_ROLE',
        identifier: userIdentity.arn ?? userIdentity.principalId ?? 'unknown',
        account_id: userIdentity.accountId,
        session_context: userIdentity.sessionContext?.sessionIssuer?.arn,
      };

    case 'AWSSERVICE':
      return {
        type: 'AWS_SERVICE',
        identifier: userIdentity.invokedBy ?? userIdentity.principalId ?? 'aws-service',
        account_id: userIdentity.accountId,
      };

    case 'FEDERATEDUSER':
      return {
        type: 'FEDERATED_USER',
        identifier: userIdentity.arn ?? userIdentity.principalId ?? 'unknown',
        account_id: userIdentity.accountId,
      };

    case 'ROOT':
      return {
        type: 'IAM_USER',
        identifier: `arn:aws:iam::${userIdentity.accountId}:root`,
        account_id: userIdentity.accountId,
      };

    default:
      return {
        type: 'UNKNOWN',
        identifier: userIdentity.arn ?? userIdentity.principalId ?? 'unknown',
        account_id: userIdentity.accountId,
      };
  }
}

// ============================================================================
// GuardDuty Normalizer
// ============================================================================

/**
 * GuardDuty finding structure.
 * Full schema: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html
 */
export interface GuardDutyFinding {
  id?: string;
  accountId?: string;
  region?: string;
  type?: string;           // e.g. "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
  title?: string;
  description?: string;
  severity?: number;       // 0.1–8.9
  createdAt?: string;
  updatedAt?: string;
  service?: {
    action?: {
      actionType?: string;
      awsApiCallAction?: {
        api?: string;
        serviceName?: string;
        callerType?: string;
        remoteIpDetails?: {
          ipAddressV4?: string;
          country?: { countryName?: string };
          city?: { cityName?: string };
          organization?: { asn?: string; asnOrg?: string; isp?: string };
        };
        errorCode?: string;
      };
      networkConnectionAction?: {
        connectionDirection?: string;
        remoteIpDetails?: { ipAddressV4?: string };
        remotePortDetails?: { port?: number; portName?: string };
        localPortDetails?: { port?: number };
        protocol?: string;
        blocked?: boolean;
      };
      portProbeAction?: {
        portProbeDetails?: Array<{
          localPortDetails?: { port?: number };
          remoteIpDetails?: { ipAddressV4?: string };
        }>;
      };
    };
    resourceRole?: string;
    additionalInfo?: Record<string, unknown>;
    count?: number;
    detectorId?: string;
    eventFirstSeen?: string;
    eventLastSeen?: string;
  };
  resource?: {
    resourceType?: string;  // "Instance", "AccessKey", "S3Bucket", etc.
    instanceDetails?: {
      instanceId?: string;
      instanceType?: string;
      tags?: Array<{ key?: string; value?: string }>;
    };
    accessKeyDetails?: {
      accessKeyId?: string;
      principalId?: string;
      userType?: string;
      userName?: string;
    };
    s3BucketDetails?: Array<{
      arn?: string;
      name?: string;
      type?: string;
    }>;
    eksClusterDetails?: { name?: string; arn?: string };
    ecsClusterDetails?: { name?: string };
  };
}

/**
 * Normalizes a raw GuardDuty finding into a NormalizedEvent.
 */
export function normalizeGuardDutyFinding(raw: RawAwsEvent): NormalizedEvent {
  const gd = raw.raw_payload as GuardDutyFinding;

  // Build actor from resource details
  const actor = buildGuardDutyActor(gd);

  // Build target from resource
  const target = buildGuardDutyTarget(gd, raw);

  // Extract source IP from action details
  const sourceIp = extractGuardDutySourceIp(gd);

  // Event type is the GuardDuty finding type
  // e.g. "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
  const eventType = gd.type ?? 'GuardDuty:UnknownFinding';

  return {
    id: generateId(),
    tenant_id: raw.tenant_id,
    connector_id: raw.connector_id,
    account_id: raw.account_id,
    region: gd.region ?? raw.region,
    source: AwsDataSource.GUARDDUTY,
    attack_surface: target.attack_surface,
    event_type: eventType,
    actor,
    target,
    source_ip: sourceIp,
    raw_payload: raw.raw_payload,
    ingestion_timestamp: raw.received_at,
  };
}

function buildGuardDutyActor(gd: GuardDutyFinding): EventActor {
  const accessKey = gd.resource?.accessKeyDetails;
  if (accessKey) {
    const userType = accessKey.userType?.toUpperCase();
    return {
      type: userType === 'IAMUSER' ? 'IAM_USER' : userType === 'ROLE' ? 'IAM_ROLE' : 'UNKNOWN',
      identifier: accessKey.principalId ?? accessKey.userName ?? accessKey.accessKeyId ?? 'unknown',
      account_id: gd.accountId,
    };
  }

  const instance = gd.resource?.instanceDetails;
  if (instance) {
    return {
      type: 'AWS_SERVICE',
      identifier: `ec2:${instance.instanceId ?? 'unknown'}`,
      account_id: gd.accountId,
    };
  }

  return { type: 'UNKNOWN', identifier: 'unknown', account_id: gd.accountId };
}

function buildGuardDutyTarget(gd: GuardDutyFinding, raw: RawAwsEvent): EventTarget {
  const resourceType = gd.resource?.resourceType ?? 'Unknown';

  if (resourceType === 'Instance' && gd.resource?.instanceDetails) {
    const inst = gd.resource.instanceDetails;
    return {
      resource_type: 'AWS::EC2::Instance',
      resource_id: `arn:aws:ec2:${raw.region}:${raw.account_id}:instance/${inst.instanceId ?? 'unknown'}`,
      resource_name: inst.instanceId,
      attack_surface: AttackSurface.CLOUD_COMPUTE,
    };
  }

  if (resourceType === 'AccessKey' && gd.resource?.accessKeyDetails) {
    const key = gd.resource.accessKeyDetails;
    return {
      resource_type: 'AWS::IAM::AccessKey',
      resource_id: `arn:aws:iam::${raw.account_id}:user/${key.userName ?? 'unknown'}`,
      resource_name: key.accessKeyId,
      attack_surface: AttackSurface.CLOUD_IAM,
    };
  }

  if (resourceType === 'S3Bucket' && gd.resource?.s3BucketDetails?.[0]) {
    const bucket = gd.resource.s3BucketDetails[0];
    return {
      resource_type: 'AWS::S3::Bucket',
      resource_id: bucket.arn ?? `arn:aws:s3:::${bucket.name ?? 'unknown'}`,
      resource_name: bucket.name,
      attack_surface: AttackSurface.CLOUD_STORAGE,
    };
  }

  if (resourceType === 'EKSCluster' && gd.resource?.eksClusterDetails) {
    const eks = gd.resource.eksClusterDetails;
    return {
      resource_type: 'AWS::EKS::Cluster',
      resource_id: eks.arn ?? `arn:aws:eks:${raw.region}:${raw.account_id}:cluster/${eks.name ?? 'unknown'}`,
      resource_name: eks.name,
      attack_surface: AttackSurface.CLOUD_CONTAINER,
    };
  }

  return {
    resource_type: `AWS::${resourceType}`,
    resource_id: `arn:aws:unknown:${raw.region}:${raw.account_id}:${resourceType.toLowerCase()}/unknown`,
    attack_surface: inferAttackSurface(resourceType),
  };
}

function extractGuardDutySourceIp(gd: GuardDutyFinding): string | undefined {
  const action = gd.service?.action;
  if (action?.awsApiCallAction?.remoteIpDetails?.ipAddressV4) {
    return action.awsApiCallAction.remoteIpDetails.ipAddressV4;
  }
  if (action?.networkConnectionAction?.remoteIpDetails?.ipAddressV4) {
    return action.networkConnectionAction.remoteIpDetails.ipAddressV4;
  }
  if (action?.portProbeAction?.portProbeDetails?.[0]?.remoteIpDetails?.ipAddressV4) {
    return action.portProbeAction.portProbeDetails[0].remoteIpDetails.ipAddressV4;
  }
  return undefined;
}

// ============================================================================
// Security Hub Normalizer
// ============================================================================

/**
 * AWS Security Finding Format (ASFF) — the schema Security Hub uses.
 * Full schema: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
 */
export interface SecurityHubFinding {
  SchemaVersion?: string;
  Id?: string;
  ProductArn?: string;
  ProductName?: string;
  CompanyName?: string;
  GeneratorId?: string;
  AwsAccountId?: string;
  Types?: string[];          // e.g. ["Software and Configuration Checks/AWS Security Best Practices"]
  FirstObservedAt?: string;
  LastObservedAt?: string;
  CreatedAt?: string;
  UpdatedAt?: string;
  Severity?: {
    Label?: string;          // INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    Normalized?: number;     // 0–100
    Original?: string;
  };
  Title?: string;
  Description?: string;
  Remediation?: {
    Recommendation?: { Text?: string; Url?: string };
  };
  SourceUrl?: string;
  Resources?: Array<{
    Type?: string;           // e.g. "AwsIamUser", "AwsEc2Instance"
    Id?: string;             // ARN
    Partition?: string;
    Region?: string;
    Details?: Record<string, unknown>;
    Tags?: Record<string, string>;
  }>;
  Compliance?: {
    Status?: string;         // PASSED, FAILED, WARNING, NOT_AVAILABLE
    RelatedRequirements?: string[];
  };
  WorkflowState?: string;
  RecordState?: string;
  FindingProviderFields?: {
    Severity?: { Label?: string; Original?: string };
    Types?: string[];
  };
  // Network details (if present)
  Network?: {
    Direction?: string;
    Protocol?: string;
    SourceIpV4?: string;
    SourcePort?: number;
    DestinationIpV4?: string;
    DestinationPort?: number;
  };
  // Actor details (if present)
  Action?: {
    ActionType?: string;
    AwsApiCallAction?: {
      Api?: string;
      ServiceName?: string;
      CallerType?: string;
      RemoteIpDetails?: { IpAddressV4?: string };
    };
  };
}

/**
 * Normalizes a raw Security Hub finding (ASFF format) into a NormalizedEvent.
 */
export function normalizeSecurityHubFinding(raw: RawAwsEvent): NormalizedEvent {
  const sh = raw.raw_payload as SecurityHubFinding;

  // Primary resource
  const primaryResource = sh.Resources?.[0];
  const resourceType = primaryResource?.Type ?? 'Unknown';
  const resourceId = primaryResource?.Id ?? `arn:aws:unknown:${raw.region}:${raw.account_id}:unknown`;

  const target: EventTarget = {
    resource_type: resourceType,
    resource_id: resourceId,
    attack_surface: inferAttackSurface(resourceType),
  };

  // Actor — Security Hub findings don't always have actor info
  // Try to extract from Action field or infer from resource
  const actor = buildSecurityHubActor(sh, raw);

  // Event type: use the finding type or title
  // Types array: ["Software and Configuration Checks/AWS Security Best Practices/Network Reachability"]
  const findingType = sh.Types?.[0] ?? sh.Title ?? 'SecurityHub:UnknownFinding';
  // Shorten to last segment for readability
  const eventType = `securityhub:${findingType.split('/').pop() ?? findingType}`;

  return {
    id: generateId(),
    tenant_id: raw.tenant_id,
    connector_id: raw.connector_id,
    account_id: raw.account_id,
    region: primaryResource?.Region ?? raw.region,
    source: AwsDataSource.SECURITY_HUB,
    attack_surface: target.attack_surface,
    event_type: eventType,
    actor,
    target,
    source_ip: sh.Network?.SourceIpV4 ?? sh.Action?.AwsApiCallAction?.RemoteIpDetails?.IpAddressV4,
    raw_payload: raw.raw_payload,
    ingestion_timestamp: raw.received_at,
  };
}

function buildSecurityHubActor(sh: SecurityHubFinding, raw: RawAwsEvent): EventActor {
  // If there's API call action info, extract actor from there
  if (sh.Action?.AwsApiCallAction) {
    return {
      type: 'IAM_USER',
      identifier: sh.Action.AwsApiCallAction.ServiceName ?? 'unknown',
      account_id: raw.account_id,
    };
  }

  // Otherwise, actor is the AWS account itself (configuration finding)
  return {
    type: 'AWS_SERVICE',
    identifier: `arn:aws:iam::${raw.account_id}:root`,
    account_id: raw.account_id,
  };
}

// ============================================================================
// AWS Config Normalizer
// ============================================================================

/**
 * AWS Config configuration change event structure.
 */
export interface AwsConfigEvent {
  configurationItemDiff?: {
    changeType?: string;     // CREATE, UPDATE, DELETE
    changedProperties?: Record<string, { previousValue?: unknown; updatedValue?: unknown }>;
  };
  configurationItem?: {
    configurationItemStatus?: string;
    resourceType?: string;   // e.g. "AWS::IAM::Policy"
    resourceId?: string;
    resourceName?: string;
    arn?: string;
    awsRegion?: string;
    awsAccountId?: string;
    configurationItemCaptureTime?: string;
    tags?: Record<string, string>;
    configuration?: Record<string, unknown>;
    relationships?: Array<{ resourceType?: string; resourceId?: string; name?: string }>;
  };
  notificationCreationTime?: string;
  messageType?: string;      // ConfigurationItemChangeNotification, ComplianceChangeNotification
  recordVersion?: string;
}

/**
 * Normalizes a raw AWS Config event into a NormalizedEvent.
 */
export function normalizeAwsConfigEvent(raw: RawAwsEvent): NormalizedEvent {
  const cfg = raw.raw_payload as AwsConfigEvent;
  const item = cfg.configurationItem;

  const resourceType = item?.resourceType ?? 'Unknown';
  const resourceId = item?.arn ?? item?.resourceId ?? 'unknown';
  const changeType = cfg.configurationItemDiff?.changeType ?? 'UPDATE';

  const target: EventTarget = {
    resource_type: resourceType,
    resource_id: resourceId,
    resource_name: item?.resourceName,
    attack_surface: inferAttackSurface(resourceType),
  };

  // Config events are always from the AWS Config service itself
  const actor: EventActor = {
    type: 'AWS_SERVICE',
    identifier: 'config.amazonaws.com',
    account_id: item?.awsAccountId ?? raw.account_id,
  };

  const eventType = `config:${changeType}:${resourceType}`;

  return {
    id: generateId(),
    tenant_id: raw.tenant_id,
    connector_id: raw.connector_id,
    account_id: raw.account_id,
    region: item?.awsRegion ?? raw.region,
    source: AwsDataSource.CONFIG,
    attack_surface: target.attack_surface,
    event_type: eventType,
    actor,
    target,
    raw_payload: raw.raw_payload,
    ingestion_timestamp: raw.received_at,
  };
}

// ============================================================================
// Main Dispatcher
// ============================================================================

/**
 * Dispatches a raw AWS event to the appropriate normalizer based on its source.
 * Returns a NormalizedEvent ready for the AI Reasoning Engine.
 */
export function normalizeAwsEvent(raw: RawAwsEvent): NormalizedEvent {
  switch (raw.source) {
    case AwsDataSource.CLOUDTRAIL:
      return normalizeCloudTrailEvent(raw);
    case AwsDataSource.GUARDDUTY:
      return normalizeGuardDutyFinding(raw);
    case AwsDataSource.SECURITY_HUB:
      return normalizeSecurityHubFinding(raw);
    case AwsDataSource.CONFIG:
      return normalizeAwsConfigEvent(raw);
    default:
      throw new Error(`Unsupported AWS data source: ${raw.source}`);
  }
}
