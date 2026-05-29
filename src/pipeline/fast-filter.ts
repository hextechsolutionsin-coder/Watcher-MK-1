/**
 * Fast Filter (Task 10)
 *
 * Lightweight event triage — decides if an event is worth sending to the
 * full AI Reasoning Engine. Runs on every event (potentially millions/day).
 *
 * Strategy: rule-assisted heuristics + configurable sensitivity.
 * In production this would be a fine-tuned small model. For the prototype
 * we use deterministic heuristics that mirror what a trained model would do.
 *
 * Returns: interesting (true/false) + urgency + reason
 */

import { NormalizedEvent, AwsDataSource } from '../types/index.js';

export interface FilterResult {
  interesting: boolean;
  urgency: 'IMMEDIATE' | 'QUEUE' | 'DROP';
  reason: string;
  confidence: number;
}

export interface FastFilter {
  evaluate(event: NormalizedEvent): Promise<FilterResult>;
}

// ============================================================================
// High-signal event types — always interesting
// ============================================================================

/** GuardDuty finding types that are always high-priority. */
const HIGH_PRIORITY_GUARDDUTY = new Set([
  'UnauthorizedAccess:IAMUser/MaliciousIPCaller',
  'UnauthorizedAccess:IAMUser/TorIPCaller',
  'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B',
  'Recon:IAMUser/MaliciousIPCaller',
  'CredentialAccess:IAMUser/AnomalousBehavior',
  'Persistence:IAMUser/AnomalousBehavior',
  'PrivilegeEscalation:IAMUser/AnomalousBehavior',
  'Impact:S3/MaliciousIPCaller',
  'Exfiltration:S3/MaliciousIPCaller',
  'CryptoCurrency:EC2/BitcoinTool.B',
  'Backdoor:EC2/C&CActivity.B',
  'Trojan:EC2/BlackholeTraffic',
  'UnauthorizedAccess:EC2/TorIPCaller',
  'Execution:EKS/ExecInPod',
  'PrivilegeEscalation:EKS/PrivilegedContainer',
]);

/** CloudTrail event names that are always interesting. */
const HIGH_PRIORITY_CLOUDTRAIL = new Set([
  // IAM — credential and privilege changes
  'iam:CreateAccessKey',
  'iam:DeleteAccessKey',
  'iam:UpdateAccessKey',
  'iam:CreateUser',
  'iam:DeleteUser',
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:CreateLoginProfile',
  'iam:UpdateLoginProfile',
  'iam:CreateRole',
  'iam:UpdateAssumeRolePolicy',
  'iam:PassRole',
  // Root account activity
  'sts:GetCallerIdentity',
  // S3 — public exposure
  's3:PutBucketPolicy',
  's3:PutBucketAcl',
  's3:DeleteBucketPolicy',
  's3:PutBucketPublicAccessBlock',
  // EC2 — security group changes
  'ec2:AuthorizeSecurityGroupIngress',
  'ec2:RevokeSecurityGroupIngress',
  'ec2:CreateSecurityGroup',
  'ec2:DeleteSecurityGroup',
  // CloudTrail — logging changes
  'cloudtrail:StopLogging',
  'cloudtrail:DeleteTrail',
  'cloudtrail:UpdateTrail',
  // GuardDuty — detector changes
  'guardduty:DeleteDetector',
  'guardduty:DisassociateFromMasterAccount',
  // Config — compliance changes
  'config:DeleteConfigRule',
  'config:StopConfigurationRecorder',
  // Console login
  'signin:ConsoleLogin',
]);

/** Security Hub finding types that are always interesting. */
const HIGH_PRIORITY_SECURITYHUB_TYPES = [
  'TTPs/',
  'Effects/',
  'Unusual Behaviors/',
  'Software and Configuration Checks/Vulnerabilities/CVE',
];

// ============================================================================
// Heuristic Fast Filter Implementation
// ============================================================================

export class HeuristicFastFilter implements FastFilter {
  private readonly sensitivity: 'LOW' | 'MEDIUM' | 'HIGH';

  constructor(sensitivity: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM') {
    this.sensitivity = sensitivity;
  }

  async evaluate(event: NormalizedEvent): Promise<FilterResult> {
    // GuardDuty findings are always interesting
    if (event.source === AwsDataSource.GUARDDUTY) {
      return this.evaluateGuardDuty(event);
    }

    // Security Hub findings are always interesting
    if (event.source === AwsDataSource.SECURITY_HUB) {
      return this.evaluateSecurityHub(event);
    }

    // CloudTrail events — check against high-priority list
    if (event.source === AwsDataSource.CLOUDTRAIL) {
      return this.evaluateCloudTrail(event);
    }

    // Config changes — always interesting (configuration drift)
    if (event.source === AwsDataSource.CONFIG) {
      return {
        interesting: true,
        urgency: 'QUEUE',
        reason: 'AWS Config configuration change detected',
        confidence: 70,
      };
    }

    // Default: queue for review on MEDIUM/HIGH sensitivity
    if (this.sensitivity !== 'LOW') {
      return {
        interesting: true,
        urgency: 'QUEUE',
        reason: `Unknown source ${event.source} — queued for review`,
        confidence: 50,
      };
    }

    return { interesting: false, urgency: 'DROP', reason: 'Unknown source', confidence: 90 };
  }

  private evaluateGuardDuty(event: NormalizedEvent): FilterResult {
    if (HIGH_PRIORITY_GUARDDUTY.has(event.event_type)) {
      return {
        interesting: true,
        urgency: 'IMMEDIATE',
        reason: `High-priority GuardDuty finding: ${event.event_type}`,
        confidence: 95,
      };
    }
    // All GuardDuty findings are interesting
    return {
      interesting: true,
      urgency: 'QUEUE',
      reason: `GuardDuty finding: ${event.event_type}`,
      confidence: 85,
    };
  }

  private evaluateSecurityHub(event: NormalizedEvent): FilterResult {
    const isHighPriority = HIGH_PRIORITY_SECURITYHUB_TYPES.some(
      (t) => event.event_type.includes(t)
    );

    return {
      interesting: true,
      urgency: isHighPriority ? 'IMMEDIATE' : 'QUEUE',
      reason: `Security Hub finding: ${event.event_type}`,
      confidence: isHighPriority ? 90 : 75,
    };
  }

  private evaluateCloudTrail(event: NormalizedEvent): FilterResult {
    // Check high-priority list
    if (HIGH_PRIORITY_CLOUDTRAIL.has(event.event_type)) {
      // Root account activity is always immediate
      const isRoot = event.actor.identifier.includes(':root');
      const urgency = isRoot ? 'IMMEDIATE' : 'QUEUE';

      return {
        interesting: true,
        urgency,
        reason: `High-priority CloudTrail event: ${event.event_type}${isRoot ? ' (root account)' : ''}`,
        confidence: 90,
      };
    }

    // New source IP on sensitive operations
    if (event.source_ip && this.isSensitiveOperation(event.event_type)) {
      return {
        interesting: true,
        urgency: 'QUEUE',
        reason: `Sensitive operation from external IP: ${event.event_type}`,
        confidence: 70,
      };
    }

    // On HIGH sensitivity, queue everything
    if (this.sensitivity === 'HIGH') {
      return {
        interesting: true,
        urgency: 'QUEUE',
        reason: `All events queued (HIGH sensitivity): ${event.event_type}`,
        confidence: 60,
      };
    }

    // Drop routine read-only operations on LOW/MEDIUM
    if (this.isRoutineReadOnly(event.event_type)) {
      return {
        interesting: false,
        urgency: 'DROP',
        reason: `Routine read-only operation: ${event.event_type}`,
        confidence: 85,
      };
    }

    // Queue everything else on MEDIUM
    if (this.sensitivity === 'MEDIUM') {
      return {
        interesting: true,
        urgency: 'QUEUE',
        reason: `Queued for review: ${event.event_type}`,
        confidence: 60,
      };
    }

    return { interesting: false, urgency: 'DROP', reason: `Low-priority: ${event.event_type}`, confidence: 75 };
  }

  private isSensitiveOperation(eventType: string): boolean {
    const sensitive = ['iam:', 's3:Put', 'ec2:Authorize', 'ec2:Revoke', 'kms:', 'secretsmanager:'];
    return sensitive.some((s) => eventType.includes(s));
  }

  private isRoutineReadOnly(eventType: string): boolean {
    const routine = [
      'ec2:Describe', 'iam:Get', 'iam:List', 's3:Get', 's3:List',
      'cloudwatch:Get', 'cloudwatch:List', 'cloudwatch:Describe',
      'logs:Get', 'logs:Describe', 'logs:Filter',
      'sts:GetCallerIdentity', 'sts:GetSessionToken',
    ];
    return routine.some((r) => eventType.includes(r));
  }
}
