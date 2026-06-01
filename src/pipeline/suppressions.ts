/**
 * Suppressions System
 *
 * Maintains an in-memory list of suppression rules that prevent
 * known-benign events from reaching the AI reasoning engine.
 *
 * Rules can suppress by:
 * - ACCOUNT: Skip all events from a specific AWS account
 * - ROLE_ARN: Skip events from a specific IAM role ARN
 * - EVENT_NAME: Skip specific CloudTrail event names
 * - IP: Skip events from a specific source IP
 */

import type { RawAwsEvent } from '../types/index.js';

// ============================================================================
// Types
// ============================================================================

export type SuppressionType = 'ACCOUNT' | 'ROLE_ARN' | 'EVENT_NAME' | 'IP';

export interface SuppressionRule {
  id: string;
  type: SuppressionType;
  value: string;
  reason: string;
  created_by: string;
  created_at: string;
}

export interface SuppressionResult {
  suppressed: boolean;
  rule_id?: string;
  reason?: string;
}

// ============================================================================
// State
// ============================================================================

const suppressions: SuppressionRule[] = [];
let watcherAccountId: string | null = null;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Sets the Watcher platform account ID.
 * All events originating from this account will be suppressed.
 */
export function setWatcherAccountId(accountId: string): void {
  watcherAccountId = accountId;

  // Remove any existing watcher account suppression
  const existingIdx = suppressions.findIndex(
    (r) => r.type === 'ACCOUNT' && r.reason === 'Watcher MK1 platform account'
  );
  if (existingIdx !== -1) {
    suppressions.splice(existingIdx, 1);
  }

  // Add the new watcher account suppression
  suppressions.push({
    id: 'suppression-watcher-account',
    type: 'ACCOUNT',
    value: accountId,
    reason: 'Watcher MK1 platform account',
    created_by: 'system',
    created_at: new Date().toISOString(),
  });

  console.log(`[Suppressions] Watcher account suppression set: ${accountId}`);
}

// Pre-load default suppressions
suppressions.push({
  id: 'suppression-service-linked-roles',
  type: 'ROLE_ARN',
  value: '/aws-service-role/',
  reason: 'AssumeRole events targeting service-linked roles are automated AWS activity',
  created_by: 'system',
  created_at: new Date().toISOString(),
});

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Checks whether an event should be suppressed based on active rules.
 * Called BEFORE the correlator's decideEventAction.
 */
export function shouldSuppress(event: RawAwsEvent): SuppressionResult {
  const payload = event.raw_payload as Record<string, unknown>;
  const userIdentity = payload['userIdentity'] as Record<string, unknown> | undefined;
  const eventName = String(payload['eventName'] ?? '');
  const sourceIp = String(payload['sourceIPAddress'] ?? '');

  for (const rule of suppressions) {
    switch (rule.type) {
      case 'ACCOUNT': {
        // Check event's account_id field
        if (event.account_id === rule.value) {
          return { suppressed: true, rule_id: rule.id, reason: rule.reason };
        }
        // Check userIdentity accountId (source account for cross-account calls)
        const sourceAccount = String(userIdentity?.['accountId'] ?? '');
        if (sourceAccount === rule.value) {
          return { suppressed: true, rule_id: rule.id, reason: rule.reason };
        }
        // Check session issuer for assumed roles from the watcher account
        const sessionContext = userIdentity?.['sessionContext'] as Record<string, unknown> | undefined;
        const sessionIssuer = sessionContext?.['sessionIssuer'] as Record<string, unknown> | undefined;
        const issuerArn = String(sessionIssuer?.['arn'] ?? '');
        if (issuerArn.includes('WatcherMK1')) {
          return { suppressed: true, rule_id: rule.id, reason: rule.reason };
        }
        // Check if the actor ARN contains WatcherMK1
        const arn = String(userIdentity?.['arn'] ?? '');
        if (arn.includes('WatcherMK1') && rule.reason === 'Watcher MK1 platform account') {
          return { suppressed: true, rule_id: rule.id, reason: rule.reason };
        }
        break;
      }

      case 'ROLE_ARN': {
        const arn = String(userIdentity?.['arn'] ?? '');
        // Support partial matching (e.g., '/aws-service-role/' matches any service-linked role)
        if (arn.includes(rule.value)) {
          // For service-linked role suppression, only suppress AssumeRole events
          if (rule.id === 'suppression-service-linked-roles') {
            if (eventName === 'AssumeRole' || eventName === 'AssumeRoleWithSAML' || eventName === 'AssumeRoleWithWebIdentity') {
              return { suppressed: true, rule_id: rule.id, reason: rule.reason };
            }
          } else {
            return { suppressed: true, rule_id: rule.id, reason: rule.reason };
          }
        }
        break;
      }

      case 'EVENT_NAME': {
        if (eventName === rule.value) {
          return { suppressed: true, rule_id: rule.id, reason: rule.reason };
        }
        break;
      }

      case 'IP': {
        if (sourceIp === rule.value) {
          return { suppressed: true, rule_id: rule.id, reason: rule.reason };
        }
        break;
      }
    }
  }

  return { suppressed: false };
}

// ============================================================================
// CRUD Operations
// ============================================================================

/**
 * Adds a new suppression rule.
 */
export function addSuppression(rule: Omit<SuppressionRule, 'id' | 'created_at'>): SuppressionRule {
  const newRule: SuppressionRule = {
    id: `suppression-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type: rule.type,
    value: rule.value,
    reason: rule.reason,
    created_by: rule.created_by ?? 'system',
    created_at: new Date().toISOString(),
  };
  suppressions.push(newRule);
  console.log(`[Suppressions] Added rule: ${newRule.type} = ${newRule.value} (${newRule.reason})`);
  return newRule;
}

/**
 * Removes a suppression rule by ID.
 * Returns true if the rule was found and removed.
 */
export function removeSuppression(id: string): boolean {
  const idx = suppressions.findIndex((r) => r.id === id);
  if (idx === -1) return false;
  const removed = suppressions.splice(idx, 1)[0]!;
  console.log(`[Suppressions] Removed rule: ${removed.type} = ${removed.value}`);
  return true;
}

/**
 * Returns all active suppression rules.
 */
export function getSuppressions(): SuppressionRule[] {
  return [...suppressions];
}
