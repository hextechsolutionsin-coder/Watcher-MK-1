import { Router, Request, Response } from 'express';
import { getIncidents, getIncidentById, getTimelineForIncident } from '../store.js';

const router = Router();

/** GET /api/v1/incidents — list all incidents with optional filters */
router.get('/', (req: Request, res: Response) => {
  const { severity, status } = req.query;
  const incidents = getIncidents({
    severity: severity ? String(severity) : undefined,
    status: status ? String(status) : undefined,
  });
  res.json(incidents);
});

/** GET /api/v1/incidents/:id — single incident */
router.get('/:id', (req: Request, res: Response) => {
  const incident = getIncidentById(String(req.params['id']));
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  res.json(incident);
});

/** GET /api/v1/incidents/:id/timeline — timeline events for an incident */
router.get('/:id/timeline', (req: Request, res: Response) => {
  const incident = getIncidentById(String(req.params['id']));
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  res.json(getTimelineForIncident(String(req.params['id'])));
});

export default router;
