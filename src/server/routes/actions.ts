import { Router, Request, Response } from 'express';
import { getActions } from '../store.js';

const router = Router();

/**
 * GET /api/v1/actions
 * Returns all executed actions. Supports filters: ?type=BLOCK_IP&outcome=SUCCESS
 */
router.get('/', (req: Request, res: Response) => {
  const { type, outcome } = req.query;
  const actions = getActions({
    type: type as string | undefined,
    outcome: outcome as string | undefined,
  });
  res.json(actions);
});

export default router;
