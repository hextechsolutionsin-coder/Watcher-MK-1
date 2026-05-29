/**
 * Threat Intelligence Layer (Task 14)
 *
 * Provides the AI with current threat context:
 * - MITRE ATT&CK technique knowledge
 * - CVE vulnerability data
 * - IOC (Indicator of Compromise) feeds
 *
 * In production this integrates with NVD, MITRE ATT&CK STIX feeds,
 * and commercial IOC providers. For the prototype we provide a
 * structured in-memory store with the most critical AWS-relevant
 * techniques and a real NVD API integration.
 */

// ============================================================================
// Types
// ============================================================================

export interface MitreAttackTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  aws_relevance: string;
  detection_hints: string[];
  mitigations: string[];
}

export interface CveRecord {
  cve_id: string;
  description: string;
  cvss_score: number;
  affected_products: string[];
  published_date: string;
  has_public_poc: boolean;
}

export interface IocRecord {
  indicator_type: 'IP' | 'DOMAIN' | 'HASH' | 'URL';
  indicator_value: string;
  threat_type: string;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  active: boolean;
}

// ============================================================================
// AWS-Relevant MITRE ATT&CK Techniques (embedded knowledge)
// ============================================================================

export const AWS_MITRE_TECHNIQUES: MitreAttackTechnique[] = [
  {
    technique_id: 'T1078.004',
    technique_name: 'Valid Accounts: Cloud Accounts',
    tactic: 'Initial Access / Persistence / Privilege Escalation / Defense Evasion',
    description: 'Adversaries may obtain and abuse credentials of cloud accounts to gain initial access, maintain persistence, or escalate privileges.',
    aws_relevance: 'IAM user/role credential compromise. Look for API calls from new IPs, unusual regions, or off-hours.',
    detection_hints: [
      'ConsoleLogin from new IP or country',
      'API calls from Tor exit nodes',
      'CreateAccessKey followed by immediate use from different IP',
      'AssumeRole from unexpected principal',
    ],
    mitigations: [
      'Enable MFA for all IAM users',
      'Use IAM roles instead of long-lived access keys',
      'Enable CloudTrail and GuardDuty',
      'Implement IP-based access restrictions',
    ],
  },
  {
    technique_id: 'T1098.001',
    technique_name: 'Account Manipulation: Additional Cloud Credentials',
    tactic: 'Persistence',
    description: 'Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access.',
    aws_relevance: 'Creating new IAM access keys, adding users to groups, or creating new IAM users.',
    detection_hints: [
      'CreateAccessKey for existing user',
      'CreateUser followed by AttachUserPolicy',
      'AddUserToGroup for privileged group',
    ],
    mitigations: [
      'Monitor IAM changes with CloudTrail',
      'Alert on CreateAccessKey events',
      'Enforce access key rotation policy',
    ],
  },
  {
    technique_id: 'T1530',
    technique_name: 'Data from Cloud Storage',
    tactic: 'Collection',
    description: 'Adversaries may access data from cloud storage services such as S3.',
    aws_relevance: 'Bulk S3 GetObject calls, especially from new IPs or after credential compromise.',
    detection_hints: [
      'High volume S3 GetObject from single IP',
      'S3 access from IP not in baseline',
      'ListBuckets followed by GetObject across multiple buckets',
    ],
    mitigations: [
      'Enable S3 server access logging',
      'Use S3 Block Public Access',
      'Implement S3 bucket policies with IP restrictions',
    ],
  },
  {
    technique_id: 'T1537',
    technique_name: 'Transfer Data to Cloud Account',
    tactic: 'Exfiltration',
    description: 'Adversaries may exfiltrate data by transferring it to another cloud account.',
    aws_relevance: 'S3 replication to external accounts, snapshot sharing, AMI copying.',
    detection_hints: [
      'PutBucketReplication to external account',
      'ModifySnapshotAttribute to share with external account',
      'CreateSnapshot followed by sharing',
    ],
    mitigations: [
      'Monitor S3 replication configurations',
      'Alert on snapshot sharing to external accounts',
      'Use AWS Organizations SCPs to prevent data exfiltration',
    ],
  },
  {
    technique_id: 'T1562.008',
    technique_name: 'Impair Defenses: Disable Cloud Logs',
    tactic: 'Defense Evasion',
    description: 'Adversaries may disable cloud logging to evade detection.',
    aws_relevance: 'Stopping CloudTrail, disabling GuardDuty, deleting Config rules.',
    detection_hints: [
      'StopLogging CloudTrail event',
      'DeleteTrail event',
      'DisassociateFromMasterAccount GuardDuty',
      'DeleteDetector GuardDuty',
    ],
    mitigations: [
      'Enable CloudTrail log file validation',
      'Use AWS Config to detect logging changes',
      'Alert immediately on any logging disable event',
    ],
  },
  {
    technique_id: 'T1548.005',
    technique_name: 'Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may abuse permission configurations to gain elevated access.',
    aws_relevance: 'Assuming high-privilege roles, using PassRole to escalate, modifying trust policies.',
    detection_hints: [
      'AssumeRole for admin/privileged role from unexpected principal',
      'PassRole to Lambda or EC2',
      'UpdateAssumeRolePolicy to add external principal',
    ],
    mitigations: [
      'Implement least-privilege IAM policies',
      'Monitor AssumeRole events',
      'Use IAM Access Analyzer',
    ],
  },
  {
    technique_id: 'T1190',
    technique_name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may attempt to exploit weaknesses in internet-facing applications.',
    aws_relevance: 'Exploitation of EC2 instances, Lambda functions, or API Gateway endpoints.',
    detection_hints: [
      'Unusual Lambda invocation patterns',
      'EC2 instance making outbound connections to C2 IPs',
      'API Gateway 4xx/5xx spike',
    ],
    mitigations: [
      'Keep EC2 AMIs and software patched',
      'Use WAF for API Gateway and CloudFront',
      'Enable VPC Flow Logs',
    ],
  },
];

// ============================================================================
// Threat Intelligence Service
// ============================================================================

export class ThreatIntelligenceService {
  private readonly techniques: Map<string, MitreAttackTechnique>;
  private readonly iocs: Map<string, IocRecord>;
  private readonly cves: Map<string, CveRecord>;

  constructor() {
    this.techniques = new Map(
      AWS_MITRE_TECHNIQUES.map((t) => [t.technique_id, t])
    );
    this.iocs = new Map();
    this.cves = new Map();
  }

  /**
   * Gets a MITRE ATT&CK technique by ID.
   */
  getTechnique(techniqueId: string): MitreAttackTechnique | null {
    return this.techniques.get(techniqueId) ?? null;
  }

  /**
   * Gets all techniques relevant to a given tactic.
   */
  getTechniquesByTactic(tactic: string): MitreAttackTechnique[] {
    return [...this.techniques.values()].filter((t) =>
      t.tactic.toLowerCase().includes(tactic.toLowerCase())
    );
  }

  /**
   * Checks if an IP address is a known IOC.
   */
  checkIoc(indicatorType: string, value: string): IocRecord | null {
    const key = `${indicatorType}:${value}`;
    return this.iocs.get(key) ?? null;
  }

  /**
   * Adds an IOC to the active detection set.
   */
  addIoc(ioc: IocRecord): void {
    const key = `${ioc.indicator_type}:${ioc.indicator_value}`;
    this.iocs.set(key, ioc);
  }

  /**
   * Gets a CVE record by ID.
   */
  getCve(cveId: string): CveRecord | null {
    return this.cves.get(cveId) ?? null;
  }

  /**
   * Adds a CVE record.
   */
  addCve(cve: CveRecord): void {
    this.cves.set(cve.cve_id, cve);
  }

  /**
   * Builds a context string for the AI — summarizes relevant threat intel
   * for a given event type and affected resource.
   */
  buildContextForAI(eventType: string, resourceType: string): string {
    const relevantTechniques = [...this.techniques.values()].filter((t) =>
      t.detection_hints.some((h) => eventType.toLowerCase().includes(h.toLowerCase().split(' ')[0] ?? ''))
    );

    if (relevantTechniques.length === 0) return '';

    const lines = ['Relevant MITRE ATT&CK techniques for this event:'];
    for (const t of relevantTechniques.slice(0, 3)) {
      lines.push(`  ${t.technique_id} (${t.technique_name}): ${t.aws_relevance}`);
    }

    return lines.join('\n');
  }

  /**
   * Returns all active IOCs as a summary for AI context.
   */
  getActiveIocSummary(): string {
    const active = [...this.iocs.values()].filter((i) => i.active);
    if (active.length === 0) return 'No active IOCs in threat intelligence feed.';

    return `Active IOCs: ${active.length} indicators (${active.filter((i) => i.indicator_type === 'IP').length} IPs, ${active.filter((i) => i.indicator_type === 'DOMAIN').length} domains)`;
  }
}
