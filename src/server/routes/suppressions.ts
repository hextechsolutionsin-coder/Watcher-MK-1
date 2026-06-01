import { Router, Request, Response } from 'express';
import { getSuppressions, addSuppression, removeSuppression } from '../../pipeline/suppressions.js';
import type { SuppressionType } from '../../pipeline/suppressions.js';

const router = Router();

/** GET /api/v1/suppressions — list all active suppressions */
router.get('/', (_req: Request, res: Response) => {
  res.json(getSuppressions());
});

/** POST /api/v1/suppressions — add a new suppression */
router.post('/', (req: Request, res: Response) => {
  const { type, value, reason, created_by } = req.body as { type?: SuppressionType; value?: string; reason?: string; created_by?: string };

  if (!type || !value || !reason) {
    return res.status(400).json({ error: 'type, value, and reason are required' });
  }

  const validTypes: SuppressionType[] = ['ACCOUNT', 'ROLE_ARN', 'EVENT_NAME', 'IP'];
  if (!validTypes.includes(type)) {
    return res.status(400).json({ error: `Invalid type. Must be one of: ${validTypes.join(', ')}` });
  }

  const rule = addSuppression({ type, value, reason, created_by: created_by ?? 'analyst' });
  res.status(201).json(rule);
});

/** DELETE /api/v1/suppressions/:id — remove a suppression */
router.delete('/:id', (req: Request, res: Response) => {
  const id = String(req.params['id']);
  const removed = removeSuppression(id);

  if (!removed) {
    return res.status(404).json({ error: 'Suppression rule not found' });
  }

  res.json({ success: true, id });
});

export default router;
