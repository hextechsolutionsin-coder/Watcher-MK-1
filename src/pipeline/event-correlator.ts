/**
 * Event Correlator — v3
 *
 * Handles three decisions for every incoming event:
 *
 *   SKIP      — duplicate, service noise, or suppressed
 *   CORRELATE — same actor has an open incident; append as evidence
 *   PROCESS   — send to AI for full reasoning
 *
 * Key improvements over v2:
 * - High-risk events check existing incident first and pass it to AI as context
 *   so the AI can decide "new step in same attack" vs "new incident"
 * - actorIncidentMap tracks a LIST of active incidents per actor (not just last)
 * - Rate limiting uses event timestamp, not processing time
 * - False positive feedback auto-creates suppression rules
 * - Re-analysis triggered after N correlated events accumulate
 */

import type { RawAwsEvent } from '../types/index.js';
import { store, getIncidentById } from '../server/store.js';
import { shouldSuppress, addSuppression } from './suppressions.js';

// ============================================================================
// Configuration
// ============================================================================

const ACTOR_INCIDENT_TTL_MS = 30 * 60 * 1000;       // 30 min actor→incident mapping
const LOW_SIGNAL_RATE_LIMIT_MS = 3 * 60 * 1000;     // 3 min rate limit for low-signal
const REANALYSIS_THRESHOLD = 5;                       // re-analyze after 5 correlated events
const MAX_TRACKED_IDS = 100_000;

/**
 * High-risk events — always sent to AI.
 * If actor has an open incident, the existing incident ID is passed as context
 * so the AI can decide whether this is a new step or a new incident.
 */
const HIGH_RISK_EVENTS = new Set([
  'CreateUser', 'DeleteUser',
  'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
  'AttachUserPolicy', 'AttachRolePolicy', 'DetachUserPolicy', 'DetachRolePolicy',
  'PutUserPolicy', 'PutRolePolicy', 'DeleteUserPolicy', 'DeleteRolePolicy',
  'CreateLoginProfile', 'UpdateLoginProfile', 'DeleteLoginProfile',
  'CreateRole', 'UpdateAssumeRolePolicy',
  'AddUserToGroup', 'RemoveUserFromGroup',
  'DeactivateMFADevice', 'DeleteVirtualMFADevice',
  'DeleteAccountPasswordPolicy', 'UpdateAccountPasswordPolicy',
  'StopLogging', 'DeleteTrail', 'UpdateTrail', 'CreateTrail',
  'CreateBucket', 'DeleteBucket',
  'PutBucketPolicy', 'DeleteBucketPolicy',
  'PutBucketPublicAccessBlock', 'PutBucketAcl',
  'AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
  'CreateSecurityGroup', 'DeleteSecurityGroup',
  'RunInstances', 'TerminateInstances',
  'GetSecretValue', 'CreateSecret', 'DeleteSecret',
  'ConsoleLogin',
  'AssumeRole', 'AssumeRoleWithWebIdentity', 'AssumeRoleWithSAML',
]);

// ============================================================================
// State
// ============================================================================

const processedEventIds = new Set<string>();

/**
 * Maps actor ARN → list of active incident IDs (most recent first).
 * Tracks multiple incidents per actor so all get correlated correctly.
 */
const actorIncidentMap = new Map<string, Array<{ incident_id: string; created_at: number; correlated_count: number }>>();

/** Rate limit: last time a low-signal event from this actor was sent to AI */
const lowSignalLastSent = new Map<string, number>();

// ============================================================================
// Decision Types
// ============================================================================

export type EventDecision =
  | { action: 'SKIP'; reason: string }
  | { action: 'CORRELATE'; incident_id: string; reason: string }
  | { action: 'PROCESS'; reason: string; existing_incident_id?: string };

// ============================================================================
// Main Decision Function
// ============================================================================

export function decideEventAction(event: RawAwsEvent): EventDecision {
  const payload = event.raw_payload as Record<string, unknown>;
  const userIdentity = payload['userIdentity'] as Record<string, unknown> | undefined;
  const eventName = String(payload['eventName'] ?? 'unknown');
  const eventId = String(payload['eventID'] ?? '');
  const eventTime = String(payload['eventTime'] ?? '');

  // ── Step 0: Suppression rules ───────────────────────────────────────────
  const suppression = shouldSuppress(event);
  if (suppression.suppressed) {
    if (eventId) markProcessed(eventId);
    return { action: 'SKIP', reason: `Suppressed: ${suppression.reason}` };
  }

  // ── Step 1: Deduplication ───────────────────────────────────────────────
  if (eventId && processedEventIds.has(eventId)) {
    return { action: 'SKIP', reason: 'Already processed (duplicate eventID)' };
  }

  // ── Step 2: Service noise ───────────────────────────────────────────────
  if (isServiceNoise(payload, userIdentity)) {
    if (eventId) markProcessed(eventId);
    return { action: 'SKIP', reason: 'AWS service noise (automated activity)' };
  }

  const actorArn = getActorArn(userIdentity);

  // ── Step 3: High-risk events ────────────────────────────────────────────
  // Always go to AI. Pass existing incident ID as context if one exists,
  // so the AI can decide "new step in same attack" vs "new incident".
  if (HIGH_RISK_EVENTS.has(eventName)) {
    if (eventId) markProcessed(eventId);
    const existingIncident = getMostRecentActiveIncident(actorArn);
    return {
      action: 'PROCESS',
      reason: `High-risk event: ${eventName}`,
      existing_incident_id: existingIncident ?? undefined,
    };
  }

  // ── Step 4: Correlate to existing incident ──────────────────────────────
  const existingIncident = getMostRecentActiveIncident(actorArn);
  if (existingIncident) {
    if (eventId) markProcessed(eventId);
    // Increment correlated count — may trigger re-analysis
    incrementCorrelatedCount(actorArn, existingIncident);
    const count = getCorrelatedCount(actorArn, existingIncident);

    // Re-analyze if enough evidence has accumulated
    if (count > 0 && count % REANALYSIS_THRESHOLD === 0) {
      return {
        action: 'PROCESS',
        reason: `Re-analysis triggered: ${count} correlated events accumulated`,
        existing_incident_id: existingIncident,
      };
    }

    return {
      action: 'CORRELATE',
      incident_id: existingIncident,
      reason: `Actor ${actorArn.split('/').pop()} has open incident (${count} correlated so far)`,
    };
  }

  // ── Step 5: Rate limit low-signal events ────────────────────────────────
  // Use event timestamp for rate limiting, not processing time
  const eventTs = eventTime ? new Date(eventTime).getTime() : Date.now();
  const lastSent = lowSignalLastSent.get(actorArn);
  if (lastSent && (eventTs - lastSent) < LOW_SIGNAL_RATE_LIMIT_MS) {
    if (eventId) markProcessed(eventId);
    return { action: 'SKIP', reason: `Rate limited (low-signal): ${actorArn.split('/').pop()}` };
  }

  // ── Step 6: Process ─────────────────────────────────────────────────────
  if (eventId) markProcessed(eventId);
  lowSignalLastSent.set(actorArn, eventTs);
  return { action: 'PROCESS', reason: `New event from ${actorArn.split('/').pop()}: ${eventName}` };
}

// ============================================================================
// Actor→Incident Registration
// ============================================================================

export function registerActorIncident(actorArn: string, incidentId: string): void {
  if (!actorArn || actorArn === 'unknown') return;

  const existing = actorIncidentMap.get(actorArn) ?? [];

  // Don't add duplicates
  if (existing.some((e) => e.incident_id === incidentId)) return;

  // Add to front (most recent first)
  existing.unshift({ incident_id: incidentId, created_at: Date.now(), correlated_count: 0 });

  // Keep max 5 incidents per actor
  actorIncidentMap.set(actorArn, existing.slice(0, 5));
}

function getMostRecentActiveIncident(actorArn: string): string | null {
  if (!actorArn || actorArn === 'unknown') return null;

  const entries = actorIncidentMap.get(actorArn);
  if (!entries || entries.length === 0) return null;

  const now = Date.now();

  // Find the most recent active incident
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;

    // Check TTL
    if (now - entry.created_at > ACTOR_INCIDENT_TTL_MS) continue;

    // Verify incident still exists and is open — O(1) via index
    const incident = getIncidentById(entry.incident_id);
    if (!incident || incident.status === 'RESOLVED' || incident.status === 'FALSE_POSITIVE') continue;

    return entry.incident_id;
  }

  // All expired or resolved — clean up
  actorIncidentMap.delete(actorArn);
  return null;
}

function incrementCorrelatedCount(actorArn: string, incidentId: string): void {
  const entries = actorIncidentMap.get(actorArn);
  if (!entries) return;
  const entry = entries.find((e) => e.incident_id === incidentId);
  if (entry) entry.correlated_count++;
}

function getCorrelatedCount(actorArn: string, incidentId: string): number {
  const entries = actorIncidentMap.get(actorArn);
  if (!entries) return 0;
  return entries.find((e) => e.incident_id === incidentId)?.correlated_count ?? 0;
}

// ============================================================================
// False Positive → Auto Suppression
// ============================================================================

/**
 * When an analyst marks an incident as false positive, automatically create
 * a suppression rule so the AI doesn't repeat the same mistake.
 * Called from the incidents feedback route.
 */
export function handleFalsePositiveFeedback(
  incidentId: string,
  actorArn: string,
  notes?: string
): void {
  if (!actorArn || actorArn === 'unknown') return;

  // Determine suppression type from ARN
  if (actorArn.includes(':user/')) {
    const userName = actorArn.split(':user/').pop()!;
    addSuppression({
      type: 'ROLE_ARN',
      value: actorArn,
      reason: `Auto-suppressed: analyst marked incident ${incidentId.slice(0, 8)} as false positive${notes ? ` — ${notes}` : ''}`,
      created_by: 'system:false-positive-feedback',
    });
    console.log(`[Correlator] Auto-suppressed IAM user ${userName} after false positive feedback`);
  } else if (actorArn.includes(':assumed-role/')) {
    addSuppression({
      type: 'ROLE_ARN',
      value: actorArn,
      reason: `Auto-suppressed: analyst marked incident ${incidentId.slice(0, 8)} as false positive${notes ? ` — ${notes}` : ''}`,
      created_by: 'system:false-positive-feedback',
    });
  }

  // Remove from actor→incident map so future events aren't correlated to this incident
  actorIncidentMap.delete(actorArn);
}

// ============================================================================
// Service Noise Detection
// ============================================================================

function isServiceNoise(
  payload: Record<string, unknown>,
  userIdentity: Record<string, unknown> | undefined
): boolean {
  if (!userIdentity) return false;

  const userType = String(userIdentity['type'] ?? '');
  const arn = String(userIdentity['arn'] ?? '');
  const sourceIp = String(payload['sourceIPAddress'] ?? '');

  // Human identities — NEVER filter
  if (userType === 'IAMUser' || userType === 'Root' || userType === 'FederatedUser') {
    return false;
  }

  // AWSService / AWSAccount — always automated
  if (userType === 'AWSService' || userType === 'AWSAccount') return true;

  // AssumedRole — only filter service-linked roles
  if (userType === 'AssumedRole') {
    if (arn.includes('/aws-service-role/')) return true;
    return false;
  }

  // Service-linked role ARN
  if (arn.includes('/aws-service-role/')) return true;

  // AWS service endpoint as source IP
  if (sourceIp.endsWith('.amazonaws.com')) return true;

  return false;
}

// ============================================================================
// Helpers
// ============================================================================

function getActorArn(userIdentity: Record<string, unknown> | undefined): string {
  if (!userIdentity) return 'unknown';
  return String(userIdentity['arn'] ?? userIdentity['principalId'] ?? 'unknown');
}

function markProcessed(eventId: string): void {
  processedEventIds.add(eventId);
  if (processedEventIds.size > MAX_TRACKED_IDS) {
    const iter = processedEventIds.values();
    for (let i = 0; i < 10_000; i++) {
      const val = iter.next().value;
      if (val) processedEventIds.delete(val);
    }
  }
}

// ============================================================================
// Correlation: Append evidence to existing incident
// ============================================================================

export function appendToIncident(incidentId: string, event: RawAwsEvent): void {
  const payload = event.raw_payload as Record<string, unknown>;
  const eventName = String(payload['eventName'] ?? 'unknown');
  const eventTime = String(payload['eventTime'] ?? new Date().toISOString());
  const eventId = String(payload['eventID'] ?? `evt-${Date.now()}`);

  // O(1) lookup via index instead of O(n) findIndex
  const incident = getIncidentById(incidentId);
  if (!incident) return;

  // push is O(1) — spread was creating a new array copy every time
  if (!incident.evidence) incident.evidence = [];
  incident.evidence.push({
    connector_id: event.connector_id,
    attack_surface: 'CLOUD_IAM',
    raw_event_id: eventId,
    description: `${eventName} at ${eventTime}`,
    timestamp: eventTime,
  });
  incident.updated_at = new Date().toISOString();
}

// ============================================================================
// Stats
// ============================================================================

export function getCorrelatorStats() {
  return {
    processed_event_ids: processedEventIds.size,
    actor_incident_mappings: actorIncidentMap.size,
    open_incidents: store.incidents.filter((i) => i.status === 'OPEN').length,
  };
}
