import { Router, Request, Response } from 'express';
import { pipeline, incidentStore, approvalWorkflow } from '../pipeline-instance.js';
import { addIncident, addTimelineEvent, addAction, store } from '../store.js';
import {
  AttackSurface,
  AwsDataSource,
  type NormalizedEvent,
} from '../../types/index.js';

const router = Router();

/**
 * POST /api/v1/webhooks/:tenant_id/ingest
 *
 * Accepts a security event, runs it through the full AI reasoning pipeline:
 *   Normalize → Fast Filter → Context Assembly → Claude AI → Safety Gate
 *   → Approved actions execute / Human-review actions queue for approval
 */
router.post('/:tenant_id/ingest', async (req: Request, res: Response) => {
  const tenant_id = String(req.params['tenant_id']);
  const payload = req.body as Record<string, unknown>;

  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ success: false, error: 'Invalid payload: expected JSON object' });
  }

  if (!payload['event_type']) {
    return res.status(400).json({ success: false, error: 'Missing required field: event_type' });
  }

  const now = new Date().toISOString();

  // Build a NormalizedEvent from the webhook payload
  const event: NormalizedEvent = {
    id: `evt-${Date.now()}`,
    tenant_id,
    connector_id: `webhook-${tenant_id}`,
    account_id: String(payload['account_id'] ?? '000000000000'),
    region: String(payload['region'] ?? 'us-east-1'),
    source: AwsDataSource.CLOUDTRAIL,
    attack_surface: resolveAttackSurface(payload['attack_surface']),
    event_type: String(payload['event_type']),
    actor: {
      type: 'IAM_USER',
      identifier: String(payload['actor'] ?? 'unknown'),
      account_id: String(payload['account_id'] ?? '000000000000'),
    },
    target: {
      resource_type: String(payload['resource_type'] ?? 'AWS::IAM::User'),
      resource_id: String(payload['actor'] ?? 'unknown'),
      attack_surface: resolveAttackSurface(payload['attack_surface']),
    },
    source_ip: payload['source_ip'] ? String(payload['source_ip']) : undefined,
    user_agent: payload['user_agent'] ? String(payload['user_agent']) : undefined,
    raw_payload: payload,
    ingestion_timestamp: now,
  };

  try {
    console.log(`\n[Pipeline] Processing event: ${event.event_type} from ${event.source_ip ?? 'unknown IP'}`);

    // Run through the full AI reasoning pipeline
    const result = await pipeline.processNormalizedEvent(event);

    console.log(`[Pipeline] Done in ${result.processing_ms}ms | threat: ${result.reasoning_response?.is_threat ?? false} | incident: ${result.incident_id ?? 'none'}`);

    // If the AI created an incident, also add it to the legacy store so the UI shows it
    if (result.incident_id) {
      const aiIncident = await incidentStore.getById(result.incident_id, tenant_id);
      if (aiIncident) {
        // Add to legacy store for UI compatibility
        addIncident({
          id: aiIncident.id,
          tenant_id: aiIncident.tenant_id,
          severity_level: aiIncident.severity ?? 'MEDIUM',
          confidence_score: aiIncident.confidence ?? 50,
          review_required: aiIncident.severity === 'CRITICAL' || aiIncident.severity === 'HIGH',
          status: aiIncident.status,
          affected_assets: (aiIncident.affected_assets ?? []).map((a, i) => ({
            id: `asset-${i}`,
            class: 'CLOUD_RESOURCE',
            identifier: typeof a === 'string' ? a : String(a),
            criticality: 7,
          })),
          attack_surface: aiIncident.attack_surface ?? 'CLOUD_IAM',
          detection_timestamp: aiIncident.detection_timestamp,
          evidence: [],
          mitre_technique_ids: (aiIncident.mitre_techniques ?? []).map((t) => t.technique_id),
          recommended_actions: [],
          created_at: aiIncident.created_at,
          updated_at: aiIncident.updated_at,
        });

        // Add AI explanation as timeline event
        addTimelineEvent({
          id: `tl-${Date.now()}`,
          incident_id: aiIncident.id,
          timestamp: now,
          type: 'detection',
          title: `AI: ${aiIncident.threat_type ?? 'Threat Detected'}`,
          description: aiIncident.explanation ?? 'AI reasoning completed.',
          actor: 'Claude Sonnet 4.6',
        });

        // Add approval queue items for human-review actions
        const pending = await approvalWorkflow.getPendingByTenant(tenant_id);
        for (const req of pending) {
          if (req.incident_id === result.incident_id) {
            for (const action of req.actions) {
              addAction({
                id: action.id,
                incident_id: aiIncident.id,
                tenant_id,
                action_type: action.tool_action_id.split(':').pop()?.toUpperCase() ?? action.description.toUpperCase(),
                status: 'PENDING_APPROVAL',
                severity_level: aiIncident.severity ?? 'MEDIUM',
                retry_count: 0,
                affected_asset: {
                  id: 'asset-ai',
                  class: 'CLOUD_RESOURCE',
                  identifier: action.api_params['AccessKeyId']?.toString()
                    ?? action.api_params['InstanceIds']?.toString()
                    ?? action.api_params['Bucket']?.toString()
                    ?? event.target.resource_id,
                  criticality: 7,
                },
                created_at: now,
                updated_at: now,
              });
            }
          }
        }
      }
    }

    return res.status(200).json({
      success: true,
      event_id: result.incident_id ?? event.id,
      ai_reasoning: result.reasoning_response ? {
        is_threat: result.reasoning_response.is_threat,
        threat_type: result.reasoning_response.assessment?.threat_type,
        severity: result.reasoning_response.assessment?.severity,
        confidence: result.reasoning_response.assessment?.confidence,
        explanation: result.reasoning_response.explanation,
        actions_approved: result.actions_approved,
        actions_human_review: result.actions_human_review,
        processing_ms: result.processing_ms,
      } : null,
    });

  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[Pipeline] Error:', message);
    return res.status(500).json({ success: false, error: message });
  }
});

function resolveAttackSurface(value: unknown): AttackSurface {
  if (typeof value === 'string' && value in AttackSurface) {
    return AttackSurface[value as keyof typeof AttackSurface];
  }
  return AttackSurface.CLOUD_IAM;
}

export default router;
