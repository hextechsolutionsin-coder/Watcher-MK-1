import { Router, Request, Response } from 'express';
import { getIncidents, getIncidentById, getTimelineForIncident, addTimelineEvent, store } from '../store.js';
import { addEnvironmentFact } from '../../pipeline/environment-config.js';
import { handleFalsePositiveFeedback } from '../../pipeline/event-correlator.js';

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

/** POST /api/v1/incidents/:id/feedback — analyst feedback on an incident */
router.post('/:id/feedback', (req: Request, res: Response) => {
  const incidentId = String(req.params['id']);
  const incident = getIncidentById(incidentId);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });

  const { verdict, correct_severity, notes, analyst_id } = req.body as {
    verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'SEVERITY_WRONG';
    correct_severity?: string;
    notes?: string;
    analyst_id?: string;
  };

  if (!verdict || !['TRUE_POSITIVE', 'FALSE_POSITIVE', 'SEVERITY_WRONG'].includes(verdict)) {
    return res.status(400).json({ error: 'verdict must be TRUE_POSITIVE, FALSE_POSITIVE, or SEVERITY_WRONG' });
  }

  const now = new Date().toISOString();
  const actor = analyst_id ?? 'analyst-001';

  // Update incident status based on feedback
  const idx = store.incidents.findIndex((i) => i.id === incidentId);
  if (idx !== -1) {
    if (verdict === 'FALSE_POSITIVE') {
      store.incidents[idx] = { ...store.incidents[idx], status: 'FALSE_POSITIVE', updated_at: now };

      // Auto-create suppression rule so AI doesn't repeat this mistake
      const incident = store.incidents[idx]!;
      const actorArn = (incident.affected_assets as any[])?.[0]?.identifier ?? '';
      handleFalsePositiveFeedback(incidentId, actorArn, notes);

      // Also add as environment fact for AI context
      if (notes) {
        addEnvironmentFact(`Analyst marked incident ${incidentId.slice(0, 8)} as FALSE POSITIVE: ${notes}`);
      }
    } else if (verdict === 'SEVERITY_WRONG' && correct_severity) {
      store.incidents[idx] = { ...store.incidents[idx], severity_level: correct_severity.toUpperCase(), updated_at: now };
    } else if (verdict === 'TRUE_POSITIVE') {
      store.incidents[idx] = { ...store.incidents[idx], status: 'IN_PROGRESS', updated_at: now };
    }
  }

  // Add timeline event for audit trail
  addTimelineEvent({
    id: `tl-${Date.now()}-feedback`,
    incident_id: incidentId,
    timestamp: now,
    type: 'escalation',
    title: `Analyst Feedback: ${verdict.replace(/_/g, ' ')}`,
    description: notes ?? `Verdict: ${verdict}${correct_severity ? ` (correct severity: ${correct_severity})` : ''}`,
    actor,
  });

  console.log(`[Feedback] ${actor} → ${incidentId.slice(0, 8)}: ${verdict}${notes ? ` — ${notes}` : ''}`);

  res.json({ success: true, verdict, incident_id: incidentId });
});

export default router;
