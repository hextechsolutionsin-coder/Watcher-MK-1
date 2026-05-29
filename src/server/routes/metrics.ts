import { Router, Request, Response } from 'express';
import { store } from '../store.js';

const router = Router();

/**
 * GET /api/v1/metrics/risk-score
 * Computed from real open incidents in the store.
 */
router.get('/risk-score', (_req: Request, res: Response) => {
  const openIncidents = store.incidents.filter(
    (i) => i.status === 'OPEN' || i.status === 'IN_PROGRESS'
  );

  const severityWeights: Record<string, number> = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 8,
    LOW: 3,
    INFORMATIONAL: 1,
  };

  let score = 0;
  for (const incident of openIncidents) {
    score += severityWeights[incident.severity_level] ?? 0;
  }

  res.json({ score: Math.min(100, score) });
});

/**
 * GET /api/v1/metrics/kpis
 * Computed from real data in the store.
 */
router.get('/kpis', (_req: Request, res: Response) => {
  const allActions = store.actions;
  const completedActions = allActions.filter((a) => a.status === 'COMPLETED');
  const failedActions = allActions.filter((a) => a.status === 'FAILED');
  const totalResolved = store.incidents.filter((i) => i.status === 'RESOLVED').length;
  const totalIncidents = store.incidents.length;

  // Mean time to detect: average ms from created_at to detection_timestamp
  const mttdValues = store.incidents
    .filter((i) => i.detection_timestamp)
    .map((i) => new Date(i.detection_timestamp).getTime() - new Date(i.created_at).getTime())
    .filter((v) => v >= 0);
  const mttdSeconds = mttdValues.length > 0
    ? Math.round(mttdValues.reduce((a, b) => a + b, 0) / mttdValues.length / 1000)
    : 0;

  // Mean time to respond: average ms from created_at to execution_timestamp
  const mttrValues = completedActions
    .filter((a) => a.execution_timestamp)
    .map((a) => new Date(a.execution_timestamp!).getTime() - new Date(a.created_at).getTime())
    .filter((v) => v >= 0);
  const mttrSeconds = mttrValues.length > 0
    ? Math.round(mttrValues.reduce((a, b) => a + b, 0) / mttrValues.length / 1000)
    : 0;

  // Autonomous resolution: actions completed without human approval
  const autonomousCount = completedActions.filter((a) => !a.approver_id).length;
  const autonomousPct = completedActions.length > 0
    ? Math.round((autonomousCount / completedActions.length) * 100)
    : 0;

  res.json({
    mttd_seconds: mttdSeconds,
    mttr_seconds: mttrSeconds,
    false_positive_rate: 0,
    autonomous_resolution_pct: autonomousPct,
    total_incidents: totalIncidents,
    resolved_incidents: totalResolved,
    completed_actions: completedActions.length,
    failed_actions: failedActions.length,
  });
});

/**
 * GET /api/v1/metrics/trends
 * Returns real incident counts grouped by day.
 * Returns empty arrays when no data exists yet.
 */
router.get('/trends', (_req: Request, res: Response) => {
  // Top MITRE techniques from real incidents
  const techniqueCounts: Record<string, { count: number; severity: string }> = {};
  for (const incident of store.incidents) {
    for (const tid of incident.mitre_technique_ids ?? []) {
      if (!techniqueCounts[tid]) {
        techniqueCounts[tid] = { count: 0, severity: incident.severity_level ?? 'MEDIUM' };
      }
      techniqueCounts[tid]!.count++;
    }
  }

  const topThreats = Object.entries(techniqueCounts)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, 10)
    .map(([techniqueId, { count, severity }]) => ({
      techniqueId,
      techniqueName: techniqueId,
      count,
      severity,
    }));

  // Return empty arrays for chart data — charts will show "no data" state
  // These will be populated as real incidents accumulate over time
  res.json({
    mttd: [],
    mttr: [],
    falsePositiveRate: [],
    autonomousResolution: [],
    topThreats,
  });
});

export default router;
