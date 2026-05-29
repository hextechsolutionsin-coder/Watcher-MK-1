/**
 * Safety Gate
 *
 * Validates every AI-generated action before execution.
 * This is the critical guardrail that makes autonomous AI safe for
 * production infrastructure.
 *
 * Validation pipeline (in order):
 *   1. Tool permission check — is this action in the tenant's capability profile?
 *   2. Blast radius check — how much damage if wrong?
 *   3. Reversibility check — does the action have a rollback spec?
 *   4. Confidence check — is the AI confident enough to act at this blast radius?
 *   5. Trust level check — has the AI earned enough trust to act autonomously?
 *   6. Rate limit check — is the AI acting too fast?
 *
 * Output:
 *   APPROVED    → send to Action Executor immediately
 *   HUMAN_REVIEW → send to Approval Workflow with full AI reasoning
 *   REJECTED    → block — policy violation (log and notify AI)
 */

import {
  PlannedAction,
  ActionPlan,
  SafetyGateResult,
  SafetyDecision,
  BlastRadius,
  TrustLevel,
  ToolCapabilityProfile,
  TenantConfig,
} from '../types/index.js';

import { canActAutonomously } from './trust-level.js';

// ============================================================================
// Rate Limiter Interface
// ============================================================================

export interface RateLimiter {
  /** Returns true if the action is within rate limits, false if exceeded. */
  checkAndIncrement(tenantId: string): Promise<boolean>;
  /** Returns current action count in the window. */
  getCurrentCount(tenantId: string): Promise<number>;
}

// ============================================================================
// Safety Gate Configuration
// ============================================================================

export interface SafetyGateConfig {
  /** Minimum confidence for auto-approving LOW blast radius actions. */
  minConfidenceLow: number;
  /** Minimum confidence for auto-approving MEDIUM blast radius actions. */
  minConfidenceMedium: number;
  /** Max write actions per minute per tenant (prevents runaway AI). */
  maxActionsPerMinute: number;
}

export const DEFAULT_SAFETY_CONFIG: SafetyGateConfig = {
  minConfidenceLow: 70,
  minConfidenceMedium: 85,
  maxActionsPerMinute: 10,
};

// ============================================================================
// Validation Result
// ============================================================================

export interface ValidationResult {
  passed: boolean;
  reason: string;
}

// ============================================================================
// Individual Validators
// ============================================================================

/**
 * Check 1: Is this action available in the tenant's tool capability profile?
 */
export function validateToolPermission(
  action: PlannedAction,
  profiles: ToolCapabilityProfile[]
): ValidationResult {
  if (profiles.length === 0) {
    return { passed: false, reason: 'No tool capability profiles available for this tenant' };
  }

  const allActions = profiles.flatMap((p) => p.writable_actions);
  const available = allActions.find((a) => a.action_id === action.tool_action_id);

  if (!available) {
    return {
      passed: false,
      reason: `Action '${action.tool_action_id}' is not in the tenant's capability profile. Available: ${allActions.map((a) => a.action_id).join(', ')}`,
    };
  }

  return { passed: true, reason: `Action '${action.tool_action_id}' is available` };
}

/**
 * Check 2: Does the action have a rollback spec if it's a write action?
 * Read-only (NONE blast radius) actions don't need rollback.
 */
export function validateReversibility(action: PlannedAction): ValidationResult {
  if (action.blast_radius === BlastRadius.NONE) {
    return { passed: true, reason: 'Read-only action — no rollback required' };
  }

  if (!action.rollback_spec) {
    return {
      passed: false,
      reason: `Write action '${action.tool_action_id}' (blast: ${action.blast_radius}) has no rollback specification. Rollback is required for all write actions.`,
    };
  }

  if (!action.rollback_spec.aws_api_call || !action.rollback_spec.aws_service) {
    return {
      passed: false,
      reason: `Rollback spec for '${action.tool_action_id}' is incomplete — missing aws_service or aws_api_call`,
    };
  }

  return { passed: true, reason: 'Valid rollback specification present' };
}

/**
 * Check 3: Is the AI's confidence high enough for this blast radius?
 */
export function validateConfidence(
  action: PlannedAction,
  config: SafetyGateConfig,
  tenantConfig: TenantConfig
): ValidationResult {
  // Use tenant-specific thresholds if configured, fall back to gate defaults
  const thresholdLow = tenantConfig.confidence_threshold_low ?? config.minConfidenceLow;
  const thresholdMedium = tenantConfig.confidence_threshold_medium ?? config.minConfidenceMedium;

  switch (action.blast_radius) {
    case BlastRadius.NONE:
      return { passed: true, reason: 'Read-only action — no confidence threshold' };

    case BlastRadius.LOW:
      if (action.confidence >= thresholdLow) {
        return { passed: true, reason: `Confidence ${action.confidence}% meets LOW threshold (${thresholdLow}%)` };
      }
      return {
        passed: false,
        reason: `Confidence ${action.confidence}% below LOW threshold (${thresholdLow}%) — routing to human review`,
      };

    case BlastRadius.MEDIUM:
      if (action.confidence >= thresholdMedium) {
        return { passed: true, reason: `Confidence ${action.confidence}% meets MEDIUM threshold (${thresholdMedium}%)` };
      }
      return {
        passed: false,
        reason: `Confidence ${action.confidence}% below MEDIUM threshold (${thresholdMedium}%) — routing to human review`,
      };

    case BlastRadius.HIGH:
      // HIGH always requires human review — confidence doesn't matter
      return {
        passed: false,
        reason: 'HIGH blast radius actions always require human approval regardless of confidence',
      };

    default:
      return { passed: false, reason: `Unknown blast radius: ${action.blast_radius}` };
  }
}

/**
 * Check 4: Has the AI earned enough trust to act autonomously at this blast radius?
 */
export function validateTrustLevel(
  action: PlannedAction,
  trustLevel: TrustLevel
): ValidationResult {
  if (action.blast_radius === BlastRadius.HIGH) {
    return {
      passed: false,
      reason: 'HIGH blast radius always requires human approval — trust level does not override this',
    };
  }

  if (canActAutonomously(trustLevel, action.blast_radius)) {
    return {
      passed: true,
      reason: `Trust level ${trustLevel} permits autonomous ${action.blast_radius} blast radius actions`,
    };
  }

  return {
    passed: false,
    reason: `Trust level ${trustLevel} does not permit autonomous ${action.blast_radius} blast radius actions — routing to human review`,
  };
}

// ============================================================================
// Safety Gate
// ============================================================================

/**
 * The Safety Gate validates every AI-planned action before execution.
 *
 * For each action in a plan, it runs all validation checks and returns
 * a SafetyGateResult with the routing decision (APPROVED / HUMAN_REVIEW / REJECTED).
 */
export class SafetyGate {
  private readonly rateLimiter: RateLimiter;
  private readonly config: SafetyGateConfig;

  constructor(rateLimiter: RateLimiter, config: Partial<SafetyGateConfig> = {}) {
    this.rateLimiter = rateLimiter;
    this.config = { ...DEFAULT_SAFETY_CONFIG, ...config };
  }

  /**
   * Validates a single planned action.
   * Returns a SafetyGateResult with the routing decision and reasons.
   */
  async validateAction(
    action: PlannedAction,
    trustLevel: TrustLevel,
    profiles: ToolCapabilityProfile[],
    tenantConfig: TenantConfig
  ): Promise<SafetyGateResult> {
    const now = new Date().toISOString();
    const reasons: string[] = [];

    // Check 1: Tool permission
    const permCheck = validateToolPermission(action, profiles);
    if (!permCheck.passed) {
      return {
        action_id: action.id,
        decision: SafetyDecision.REJECTED,
        blast_radius: action.blast_radius,
        trust_level: trustLevel,
        confidence: action.confidence,
        reasons: [permCheck.reason],
        evaluated_at: now,
      };
    }
    reasons.push(permCheck.reason);

    // Check 2: Reversibility
    const revCheck = validateReversibility(action);
    if (!revCheck.passed) {
      return {
        action_id: action.id,
        decision: SafetyDecision.REJECTED,
        blast_radius: action.blast_radius,
        trust_level: trustLevel,
        confidence: action.confidence,
        reasons: [revCheck.reason],
        evaluated_at: now,
      };
    }
    reasons.push(revCheck.reason);

    // Check 3: Rate limit (only for write actions)
    if (action.blast_radius !== BlastRadius.NONE) {
      const withinLimit = await this.rateLimiter.checkAndIncrement(tenantConfig.tenant_id);
      if (!withinLimit) {
        return {
          action_id: action.id,
          decision: SafetyDecision.REJECTED,
          blast_radius: action.blast_radius,
          trust_level: trustLevel,
          confidence: action.confidence,
          reasons: [`Rate limit exceeded — max ${this.config.maxActionsPerMinute} write actions/minute`],
          evaluated_at: now,
        };
      }
      reasons.push('Within rate limits');
    }

    // Check 4: Confidence threshold
    const confCheck = validateConfidence(action, this.config, tenantConfig);
    reasons.push(confCheck.reason);

    // Check 5: Trust level
    const trustCheck = validateTrustLevel(action, trustLevel);
    reasons.push(trustCheck.reason);

    // Routing decision:
    // - NONE blast radius → always APPROVED (read-only, safe)
    // - HIGH blast radius → always HUMAN_REVIEW
    // - LOW/MEDIUM → APPROVED if confidence + trust pass, else HUMAN_REVIEW
    let decision: SafetyDecision;

    if (action.blast_radius === BlastRadius.NONE) {
      decision = SafetyDecision.APPROVED;
    } else if (action.blast_radius === BlastRadius.HIGH) {
      decision = SafetyDecision.HUMAN_REVIEW;
    } else if (confCheck.passed && trustCheck.passed) {
      decision = SafetyDecision.APPROVED;
    } else {
      decision = SafetyDecision.HUMAN_REVIEW;
    }

    return {
      action_id: action.id,
      decision,
      blast_radius: action.blast_radius,
      trust_level: trustLevel,
      confidence: action.confidence,
      reasons,
      evaluated_at: now,
    };
  }

  /**
   * Validates all actions in a plan.
   * Returns results for each action and a summary of the overall plan routing.
   */
  async validatePlan(
    plan: ActionPlan,
    trustLevel: TrustLevel,
    profiles: ToolCapabilityProfile[],
    tenantConfig: TenantConfig
  ): Promise<PlanValidationResult> {
    const results: SafetyGateResult[] = [];

    for (const action of plan.actions) {
      const result = await this.validateAction(action, trustLevel, profiles, tenantConfig);
      results.push(result);
    }

    const approved = results.filter((r) => r.decision === SafetyDecision.APPROVED);
    const humanReview = results.filter((r) => r.decision === SafetyDecision.HUMAN_REVIEW);
    const rejected = results.filter((r) => r.decision === SafetyDecision.REJECTED);

    return {
      plan_id: plan.id,
      action_results: results,
      approved_count: approved.length,
      human_review_count: humanReview.length,
      rejected_count: rejected.length,
      has_rejections: rejected.length > 0,
      requires_human_review: humanReview.length > 0,
      fully_autonomous: rejected.length === 0 && humanReview.length === 0,
    };
  }
}

export interface PlanValidationResult {
  plan_id: string;
  action_results: SafetyGateResult[];
  approved_count: number;
  human_review_count: number;
  rejected_count: number;
  has_rejections: boolean;
  requires_human_review: boolean;
  fully_autonomous: boolean;
}
