import { Router, Request, Response } from 'express';
import { store } from '../store.js';
import { getCorrelatorStats } from '../../pipeline/event-correlator.js';
import { getConnectors } from '../../pipeline/polling-loop.js';
import {
  getKnownIps, addKnownIp, removeKnownIp,
  getEnvironmentFacts, addEnvironmentFact, removeEnvironmentFact,
} from '../../pipeline/environment-config.js';
import { memoryLayer } from '../memory-layer-instance.js';

const router = Router();

/** GET /api/v1/pipeline/status */
router.get('/status', (_req: Request, res: Response) => {
  const connectors = getConnectors();
  const stats = getCorrelatorStats();

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
    connectors: connectors.map((c) => ({
      id: c.id,
      account_id: c.account_id,
      status: c.status,
      last_poll_at: c.last_poll_at,
      regions: c.regions,
      data_sources: c.data_sources,
    })),
    correlator: stats,
    store_summary: {
      incidents: store.incidents.length,
      open_incidents: store.incidents.filter((i) => i.status === 'OPEN').length,
      pending_approvals: store.actions.filter((a) => a.status === 'PENDING_APPROVAL').length,
      total_actions: store.actions.length,
    },
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
  res.json([]);
});

/**
 * GET /api/v1/pipeline/debug
 * Fetches the last 50 CloudTrail events and shows what decision the correlator
 * would make for each one — without actually processing them.
 * Use this to diagnose why events are being skipped.
 */
router.get('/debug', async (_req: Request, res: Response) => {
  const connectors = getConnectors().filter((c) => c.status === 'ACTIVE');
  if (connectors.length === 0) {
    return res.json({ error: 'No active connectors', events: [] });
  }

  const connector = connectors[0]!;

  try {
    const { CloudTrailClient, LookupEventsCommand } = await import('@aws-sdk/client-cloudtrail');
    const { createAssumedRoleCredentials } = await import('../../connectors/aws-connector.js');
    const { shouldSuppress } = await import('../../pipeline/suppressions.js');

    const region = connector.regions[0] ?? 'us-east-1';
    const credentials = createAssumedRoleCredentials(connector.role_arn, region);
    const client = new CloudTrailClient({ region, credentials });

    const startTime = new Date(Date.now() - 2 * 60 * 60 * 1000); // last 2 hours
    const response = await client.send(new LookupEventsCommand({
      StartTime: startTime,
      EndTime: new Date(),
      MaxResults: 50,
      // Match the poller's filter — write events only
      LookupAttributes: [
        { AttributeKey: 'ReadOnly', AttributeValue: 'false' },
      ],
    }));

    const results = [];
    for (const event of response.Events ?? []) {
      if (!event.CloudTrailEvent) continue;
      let payload: Record<string, unknown>;
      try { payload = JSON.parse(event.CloudTrailEvent); } catch { continue; }

      const userIdentity = payload['userIdentity'] as any;
      const eventName = String(payload['eventName'] ?? '');
      const eventId = String(payload['eventID'] ?? '');
      const sourceIp = String(payload['sourceIPAddress'] ?? '');
      const actorArn = String(userIdentity?.arn ?? userIdentity?.principalId ?? 'unknown');
      const actorType = String(userIdentity?.type ?? 'unknown');

      // Check suppression
      const rawEvent = {
        source: 'CLOUDTRAIL' as any,
        connector_id: connector.id,
        tenant_id: connector.tenant_id,
        account_id: connector.account_id,
        region,
        raw_payload: payload,
        received_at: new Date().toISOString(),
      };
      const suppression = shouldSuppress(rawEvent);

      results.push({
        eventName,
        eventId: eventId.slice(0, 8),
        eventTime: payload['eventTime'],
        actorType,
        actorArn: actorArn.split('/').pop(),
        sourceIp,
        suppressed: suppression.suppressed,
        suppressReason: suppression.reason,
        errorCode: payload['errorCode'] ?? null,
      });
    }

    return res.json({
      connector_account: connector.account_id,
      lookback: '2 hours',
      total_events: results.length,
      events: results,
    });
  } catch (err) {
    return res.status(500).json({ error: String(err) });
  }
});

export default router;

// ============================================================================
// Known IPs API
// ============================================================================

/** GET /api/v1/pipeline/known-ips */
router.get('/known-ips', (_req: Request, res: Response) => {
  res.json(getKnownIps());
});

/** POST /api/v1/pipeline/known-ips */
router.post('/known-ips', (req: Request, res: Response) => {
  const { ip, label, owner, notes, created_by } = req.body as {
    ip?: string; label?: string; owner?: string; notes?: string; created_by?: string;
  };

  if (!ip) return res.status(400).json({ error: 'ip is required' });
  if (!label) return res.status(400).json({ error: 'label is required' });
  if (!owner) return res.status(400).json({ error: 'owner is required' });

  // Basic IP validation
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  const entry = addKnownIp({ ip, label, owner, notes, created_by: created_by ?? 'analyst' });

  // Sync to Supermemory for semantic recall during threat analysis
  const tenantId = (req as unknown as { user?: { tenant_id?: string } }).user?.tenant_id ?? process.env['DEFAULT_TENANT_ID'] ?? 'tenant-001';
  memoryLayer.storeKnownIp(tenantId, ip, label, owner, notes).catch((err) => {
    console.warn('[Pipeline] Failed to store known IP in Supermemory:', err instanceof Error ? err.message : err);
  });

  res.status(201).json(entry);
});

/** DELETE /api/v1/pipeline/known-ips/:id */
router.delete('/known-ips/:id', (req: Request, res: Response) => {
  // Get the IP before removing (for Supermemory cleanup)
  const allIps = getKnownIps();
  const target = allIps.find((k) => k.id === String(req.params['id']));

  const removed = removeKnownIp(String(req.params['id']));
  if (!removed) return res.status(404).json({ error: 'Known IP not found' });

  // Remove from Supermemory
  if (target) {
    const tenantId = (req as unknown as { user?: { tenant_id?: string } }).user?.tenant_id ?? process.env['DEFAULT_TENANT_ID'] ?? 'tenant-001';
    memoryLayer.removeKnownIp(tenantId, target.ip).catch((err) => {
      console.warn('[Pipeline] Failed to remove known IP from Supermemory:', err instanceof Error ? err.message : err);
    });
  }

  res.json({ success: true });
});

// ============================================================================
// Environment Facts API
// ============================================================================

/** GET /api/v1/pipeline/facts */
router.get('/facts', (_req: Request, res: Response) => {
  res.json(getEnvironmentFacts().map((fact, index) => ({ index, fact })));
});

/** POST /api/v1/pipeline/facts */
router.post('/facts', (req: Request, res: Response) => {
  const { fact } = req.body as { fact?: string };
  if (!fact || fact.trim().length === 0) {
    return res.status(400).json({ error: 'fact is required' });
  }
  addEnvironmentFact(fact.trim());

  // Sync to Supermemory
  const tenantId = (req as unknown as { user?: { tenant_id?: string } }).user?.tenant_id ?? process.env['DEFAULT_TENANT_ID'] ?? 'tenant-001';
  const facts = getEnvironmentFacts();
  memoryLayer.storeEnvironmentFact(tenantId, fact.trim(), facts.length - 1).catch((err) => {
    console.warn('[Pipeline] Failed to store environment fact in Supermemory:', err instanceof Error ? err.message : err);
  });

  res.status(201).json({ success: true, fact: fact.trim() });
});

/** DELETE /api/v1/pipeline/facts/:index */
router.delete('/facts/:index', (req: Request, res: Response) => {
  const index = parseInt(String(req.params['index']), 10);
  if (isNaN(index)) return res.status(400).json({ error: 'Invalid index' });
  const removed = removeEnvironmentFact(index);
  if (!removed) return res.status(404).json({ error: 'Fact not found at that index' });
  res.json({ success: true });
});
