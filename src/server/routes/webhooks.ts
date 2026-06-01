import { Router, Request, Response } from 'express';
import { pipeline } from '../pipeline-instance.js';
import { addIncident, addTimelineEvent, addAction } from '../store.js';
import {
  AttackSurface,
  AwsDataSource,
  type NormalizedEvent,
  type RawAwsEvent,
} from '../../types/index.js';

const router = Router();

/**
 * POST /api/v1/webhooks/:tenant_id/ingest
 *
 * Accepts a raw security event and runs it through the full AI reasoning pipeline.
 * This is the same path as the polling loop — normalize → AI → incident → approvals.
 *
 * Use this for:
 * - Testing without waiting for the polling cycle
 * - Integrating external event sources (SIEM, custom scripts)
 * - Sending pre-formatted CloudTrail events directly
 */
router.post('/:tenant_id/ingest', async (req: Request, res: Response) => {
  const tenant_id = String(req.params['tenant_id']);
  const payload = req.body as Record<string, unknown>;

  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ success: false, error: 'Invalid payload: expected JSON object' });
  }

  if (!payload['event_type'] && !payload['eventName']) {
    return res.status(400).json({ success: false, error: 'Missing required field: event_type or eventName' });
  }

  const now = new Date().toISOString();

  try {
    let result;

    // If payload looks like a raw CloudTrail event (has eventName, userIdentity),
    // wrap it as a RawAwsEvent and let the normalizer handle it
    if (payload['eventName'] && payload['userIdentity']) {
      const raw: RawAwsEvent = {
        source: AwsDataSource.CLOUDTRAIL,
        connector_id: `webhook-${tenant_id}`,
        tenant_id,
        account_id: String(payload['recipientAccountId'] ?? payload['account_id'] ?? '000000000000'),
        region: String(payload['awsRegion'] ?? payload['region'] ?? 'us-east-1'),
        raw_payload: payload,
        received_at: now,
      };

      console.log(`[Webhook] Processing raw CloudTrail event: ${payload['eventName']} from ${tenant_id}`);
      result = await pipeline.processRawEvent(raw);
    } else {
      // Normalized event format
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
          resource_id: String(payload['resource_id'] ?? payload['actor'] ?? 'unknown'),
          attack_surface: resolveAttackSurface(payload['attack_surface']),
        },
        source_ip: payload['source_ip'] ? String(payload['source_ip']) : undefined,
        user_agent: payload['user_agent'] ? String(payload['user_agent']) : undefined,
        raw_payload: payload,
        ingestion_timestamp: now,
      };

      console.log(`[Webhook] Processing normalized event: ${event.event_type} from ${event.source_ip ?? 'unknown IP'}`);
      result = await pipeline.processNormalizedEvent(event);
    }

    console.log(`[Webhook] Done in ${result.processing_ms}ms | threat: ${result.reasoning_response?.is_threat ?? false} | incident: ${result.incident_id ?? 'none'}`);

    // Write result to the UI store (same as polling loop does)
    if (result.incident_id && result.reasoning_response?.assessment) {
      const resp = result.reasoning_response;
      const assessment = resp.assessment!;

      // Only add if not already in store (webhook may be called multiple times)
      const { store } = await import('../store.js');
      const alreadyExists = store.incidents.some((i) => i.id === result.incident_id);

      if (!alreadyExists) {
        addIncident({
          id: result.incident_id,
          tenant_id,
          severity_level: assessment.severity ?? 'MEDIUM',
          confidence_score: assessment.confidence ?? 50,
          review_required: assessment.severity === 'CRITICAL' || assessment.severity === 'HIGH',
          status: 'OPEN',
          affected_assets: (assessment.affected_assets ?? []).map((a, i) => ({
            id: `asset-${i}`, class: 'CLOUD_RESOURCE',
            identifier: typeof a === 'string' ? a : String(a), criticality: 7,
          })),
          attack_surface: 'CLOUD_IAM',
          detection_timestamp: now,
          evidence: [],
          mitre_technique_ids: (assessment.mitre_techniques ?? []).map((t) => t.technique_id),
          recommended_actions: [],
          created_at: now,
          updated_at: now,
        });

        addTimelineEvent({
          id: `tl-${Date.now()}`,
          incident_id: result.incident_id,
          timestamp: now,
          type: 'detection',
          title: `AI: ${assessment.threat_type}`,
          description: resp.explanation ?? 'AI reasoning completed.',
          actor: 'Claude Sonnet 4.6',
        });

        if (resp.action_plan) {
          for (const action of resp.action_plan.actions) {
            const targetIdentifier =
              String(action.api_params?.['UserName'] ?? '') ||
              String((action.api_params?.['InstanceIds'] as string[] | undefined)?.[0] ?? '') ||
              (assessment.affected_assets[0] ?? 'unknown');

            addAction({
              id: action.id,
              incident_id: result.incident_id,
              tenant_id,
              action_type: action.tool_action_id ?? action.description,
              status: 'PENDING_APPROVAL',
              severity_level: assessment.severity ?? 'MEDIUM',
              retry_count: 0,
              affected_asset: { id: `asset-${action.sequence}`, class: 'CLOUD_RESOURCE', identifier: targetIdentifier, criticality: 7 },
              ai_reasoning: action.reasoning,
              ai_params: action.api_params,
              blast_radius: action.blast_radius,
              rollback_description: action.rollback_spec?.description,
              created_at: now,
              updated_at: now,
            });
          }
        }
      }
    }

    return res.status(200).json({
      success: true,
      incident_id: result.incident_id ?? null,
      filtered_out: result.filtered_out,
      filter_reason: result.filter_reason ?? null,
      ai_reasoning: result.reasoning_response ? {
        is_threat: result.reasoning_response.is_threat,
        threat_type: result.reasoning_response.assessment?.threat_type,
        severity: result.reasoning_response.assessment?.severity,
        confidence: result.reasoning_response.assessment?.confidence,
        explanation: result.reasoning_response.explanation,
        actions_pending_approval: result.actions_human_review,
        processing_ms: result.processing_ms,
      } : null,
    });

  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[Webhook] Error:', message);
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
