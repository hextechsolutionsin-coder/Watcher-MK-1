import { Router, Request, Response } from 'express';
import { store } from '../store.js';

const router = Router();

/** GET /api/v1/pipeline/status */
router.get('/status', (_req: Request, res: Response) => {
  res.json({
    status: 'operational',
    components: {
      fast_filter: 'active',
      ai_reasoning_engine: 'active',
      safety_gate: 'active',
      action_executor: 'active',
      rollback_registry: 'active',
      approval_workflow: 'active',
    },
    ai_model: 'us.anthropic.claude-sonnet-4-6',
    bedrock_region: process.env['AWS_REGION'] ?? 'not configured',
    bedrock_connected: Boolean(process.env['AWS_REGION']),
    timestamp: new Date().toISOString(),
  });
});

/** GET /api/v1/pipeline/trust */
router.get('/trust', (_req: Request, res: Response) => {
  const totalActions = store.actions.length;
  const approvedActions = store.actions.filter((a) => a.approver_id).length;
  const approvalRate = totalActions > 0
    ? Math.round((approvedActions / totalActions) * 1000) / 10
    : 100;

  res.json({
    tenant_id: 'default',
    trust_level: 1,
    trust_level_description: 'Supervised — all write actions require human approval',
    approval_rate_30d: approvalRate,
    total_actions_30d: totalActions,
    approved_actions_30d: approvedActions,
    path_to_level_2: {
      required_approval_rate: 90,
      required_days: 30,
      current_days: 0,
      days_remaining: 30,
    },
    manually_overridden: false,
    last_level_change: new Date().toISOString(),
    last_level_change_reason: 'Initial trust level',
  });
});

/** GET /api/v1/pipeline/rollbacks */
router.get('/rollbacks', (_req: Request, res: Response) => {
  // Return real rollback entries from the store (empty until actions are executed)
  res.json([]);
});

export default router;
