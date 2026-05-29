import { Router, Request, Response } from 'express';
import { getPendingApprovals, getActionById, updateAction, addTimelineEvent } from '../store.js';

const router = Router();

/** GET /api/v1/approvals — all pending approval requests */
router.get('/', (_req: Request, res: Response) => {
  res.json(getPendingApprovals());
});

/** POST /api/v1/approvals/:action_id/approve */
router.post('/:action_id/approve', (req: Request, res: Response) => {
  const action_id = String(req.params['action_id']);
  const { approver_id } = req.body as { approver_id?: string };

  if (!approver_id) return res.status(400).json({ error: 'approver_id is required' });

  const action = getActionById(action_id);
  if (!action) return res.status(404).json({ error: 'Action not found' });
  if (action.status !== 'PENDING_APPROVAL') {
    return res.status(409).json({ error: `Action is not pending approval (status: ${action.status})` });
  }

  const now = new Date().toISOString();
  const updated = updateAction(action_id, { status: 'APPROVED', approver_id, updated_at: now });

  addTimelineEvent({
    id: `tl-${Date.now()}`,
    incident_id: action.incident_id,
    timestamp: now,
    type: 'approval',
    title: 'Action Approved',
    description: `${action.action_type} approved by ${approver_id}`,
    actor: approver_id,
  });

  res.json(updated);
});

/** POST /api/v1/approvals/:action_id/reject */
router.post('/:action_id/reject', (req: Request, res: Response) => {
  const action_id = String(req.params['action_id']);
  const { approver_id, reason } = req.body as { approver_id?: string; reason?: string };

  if (!approver_id) return res.status(400).json({ error: 'approver_id is required' });
  if (!reason) return res.status(400).json({ error: 'reason is required' });

  const action = getActionById(action_id);
  if (!action) return res.status(404).json({ error: 'Action not found' });
  if (action.status !== 'PENDING_APPROVAL') {
    return res.status(409).json({ error: `Action is not pending approval (status: ${action.status})` });
  }

  const now = new Date().toISOString();
  const updated = updateAction(action_id, {
    status: 'REJECTED', approver_id, rejection_reason: reason, updated_at: now,
  });

  addTimelineEvent({
    id: `tl-${Date.now()}`,
    incident_id: action.incident_id,
    timestamp: now,
    type: 'approval',
    title: 'Action Rejected',
    description: `${action.action_type} rejected by ${approver_id}: ${reason}`,
    actor: approver_id,
  });

  res.json(updated);
});

export default router;
