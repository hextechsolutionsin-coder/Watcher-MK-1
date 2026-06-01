/**
 * Polled Events API
 *
 * Exposes every event that Watcher has polled from CloudTrail/GuardDuty/SecurityHub,
 * along with the decision made (PROCESSED, CORRELATED, SKIPPED) and the reason.
 * Used by the UI's "Polled Events" page for real-time visibility.
 */

import { Router, Request, Response } from 'express';
import { getPolledEvents, getPolledEventById, type PolledEventStatus } from '../store.js';

const router = Router();

/**
 * GET /api/v1/events
 * Returns polled events with optional filters.
 *
 * Query params:
 *   status    — PROCESSED | CORRELATED | SKIPPED
 *   source    — CLOUDTRAIL | GUARDDUTY | SECURITY_HUB
 *   incident_id — filter to events correlated/linked to a specific incident
 *   event_id  — filter to a specific CloudTrail eventID
 *   limit     — max results (default 500)
 */
router.get('/', (req: Request, res: Response) => {
  const { status, source, incident_id, event_id, limit } = req.query;

  const events = getPolledEvents({
    status: status ? (String(status).toUpperCase() as PolledEventStatus) : undefined,
    source: source ? String(source) : undefined,
    incident_id: incident_id ? String(incident_id) : undefined,
    event_id: event_id ? String(event_id) : undefined,
    limit: limit ? parseInt(String(limit), 10) : 500,
  });

  res.json(events);
});

/**
 * GET /api/v1/events/stats
 * Returns summary counts by status and source.
 */
router.get('/stats', (_req: Request, res: Response) => {
  const all = getPolledEvents({ limit: 2000 });

  const byStatus = {
    PROCESSED: all.filter((e) => e.status === 'PROCESSED').length,
    CORRELATED: all.filter((e) => e.status === 'CORRELATED').length,
    SKIPPED: all.filter((e) => e.status === 'SKIPPED').length,
  };

  const bySource: Record<string, number> = {};
  for (const e of all) {
    bySource[e.source] = (bySource[e.source] ?? 0) + 1;
  }

  res.json({
    total: all.length,
    by_status: byStatus,
    by_source: bySource,
  });
});

/**
 * GET /api/v1/events/:event_id
 * Returns a single polled event by its CloudTrail eventID.
 */
router.get('/:event_id', (req: Request, res: Response) => {
  const event = getPolledEventById(String(req.params['event_id']));
  if (!event) return res.status(404).json({ error: 'Event not found' });
  res.json(event);
});

export default router;
