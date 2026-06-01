/**
 * Polling Loop
 *
 * Continuously polls registered AWS connectors for new security events
 * and feeds them into the AI reasoning pipeline automatically.
 *
 * Runs every 60 seconds per connector. Each poll:
 *   CloudTrail  → new API events since last poll
 *   GuardDuty   → new/updated findings
 *   Security Hub → new findings
 *
 * This is what makes the system fully autonomous — no manual event
 * submission needed once a connector is registered.
 */

import { CloudTrailPoller, GuardDutyPoller, SecurityHubPoller } from '../connectors/aws-connector.js';
import { EventPipeline } from './event-pipeline.js';
import { addIncident, addTimelineEvent, addAction, addPolledEvent, store, getIncidentById } from '../server/store.js';
import { AwsDataSource, type RawAwsEvent } from '../types/index.js';
import type { PipelineResult } from './event-pipeline.js';
import {
  decideEventAction,
  appendToIncident,
  registerActorIncident,
  getCorrelatorStats,
} from './event-correlator.js';
import { setWatcherAccountId } from './suppressions.js';
import { DiscordNotificationChannel } from '../response/discord-notifier.js';
import { NotificationDispatcher } from '../response/notification-dispatcher.js';

// ============================================================================
// Write pipeline results to the UI store
// ============================================================================

/** Writes AI reasoning results to the legacy store so the UI shows them */
function writeResultToStore(result: PipelineResult, tenantId: string, actorArn?: string): void {
  if (!result.incident_id || !result.reasoning_response?.assessment) return;

  const resp = result.reasoning_response;
  const assessment = resp.assessment!;

  addIncident({
    id: result.incident_id,
    tenant_id: tenantId,
    severity_level: assessment.severity ?? 'MEDIUM',
    confidence_score: assessment.confidence ?? 50,
    review_required: assessment.severity === 'CRITICAL' || assessment.severity === 'HIGH',
    status: 'OPEN',
    affected_assets: (assessment.affected_assets ?? []).map((a, i) => ({
      id: `asset-${i}`, class: 'CLOUD_RESOURCE', identifier: typeof a === 'string' ? a : String(a), criticality: 7,
    })),
    attack_surface: 'CLOUD_IAM',
    detection_timestamp: new Date().toISOString(),
    evidence: [],
    mitre_technique_ids: (assessment.mitre_techniques ?? []).map((t) => t.technique_id),
    recommended_actions: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  addTimelineEvent({
    id: `tl-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    incident_id: result.incident_id,
    timestamp: new Date().toISOString(),
    type: 'detection',
    title: `AI: ${assessment.threat_type}`,
    description: resp.explanation ?? 'AI reasoning completed.',
    actor: 'Claude Sonnet 4.6',
  });

  // Register actor→incident so subsequent events from same actor get correlated
  if (actorArn && actorArn !== 'unknown') {
    registerActorIncident(actorArn, result.incident_id);
  }

  if (resp.action_plan) {
    for (const action of resp.action_plan.actions) {
      // Use the UserName from api_params if available — the AI puts the correct
      // target there (e.g. shadow-ops-2), not just the first affected asset
      const targetIdentifier =
        String(action.api_params?.['UserName'] ?? '') ||
        String(action.api_params?.['InstanceId'] ?? '') ||
        String(action.api_params?.['InstanceIds']?.[0] ?? '') ||
        (assessment.affected_assets[action.sequence - 1] ?? assessment.affected_assets[0] ?? 'unknown');

      addAction({
        id: action.id,
        incident_id: result.incident_id,
        tenant_id: tenantId,
        action_type: action.tool_action_id ?? action.description,
        status: 'PENDING_APPROVAL',
        severity_level: assessment.severity ?? 'MEDIUM',
        retry_count: 0,
        affected_asset: { id: `asset-${action.sequence}`, class: 'CLOUD_RESOURCE', identifier: targetIdentifier, criticality: 7 },
        ai_reasoning: action.reasoning,
        ai_params: action.api_params,
        blast_radius: action.blast_radius,
        rollback_description: action.rollback_spec?.description,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
    }

    // Send Discord notification if webhook is configured
    sendDiscordAlert(result.incident_id, tenantId, assessment, resp.explanation ?? '');
  }
}

/** Sends a Discord alert for new incidents requiring approval */
async function sendDiscordAlert(
  incidentId: string,
  tenantId: string,
  assessment: NonNullable<PipelineResult['reasoning_response']>['assessment'],
  explanation: string
): Promise<void> {
  const webhookUrl = process.env['DISCORD_WEBHOOK_URL'];
  if (!webhookUrl || !assessment) return;

  try {
    const channel = new DiscordNotificationChannel(
      webhookUrl,
      process.env['DASHBOARD_URL'] ?? 'http://localhost:5173'
    );

    const dispatcher = new NotificationDispatcher({
      writeEntry: async () => {},
    });

    await dispatcher.dispatch(
      {
        tenant_id: tenantId,
        incident_id: incidentId,
        severity: assessment.severity as any,
        message: assessment.threat_type ?? 'Threat detected',
        ai_explanation: explanation,
        recipients: [],
        timestamp: new Date().toISOString(),
      },
      [channel]
    );
  } catch (err) {
    console.error('[Discord] Notification error:', err);
  }
}

export { setWatcherAccountId, getCorrelatorStats };

// ============================================================================
// Event Filtering — skip noise and self-generated events
// ============================================================================

// ============================================================================
// Registered Connector State
// ============================================================================

export interface RegisteredConnector {
  id: string;
  tenant_id: string;
  account_id: string;
  role_arn: string;
  regions: string[];
  data_sources: AwsDataSource[];
  registered_at: string;
  last_poll_at: string | null;
  status: 'ACTIVE' | 'ERROR' | 'PAUSED';
  error_message?: string;
}

// ============================================================================
// In-memory connector registry (replace with DB in production)
// ============================================================================

const connectors = new Map<string, RegisteredConnector>();

export function registerConnector(connector: RegisteredConnector): void {
  connectors.set(connector.id, connector);
  console.log(`[Polling] Registered connector: ${connector.id} → account ${connector.account_id}`);
}

export function getConnectors(): RegisteredConnector[] {
  return [...connectors.values()];
}

export function getConnectorById(id: string): RegisteredConnector | null {
  return connectors.get(id) ?? null;
}

export function updateConnectorStatus(
  id: string,
  status: RegisteredConnector['status'],
  errorMessage?: string
): void {
  const c = connectors.get(id);
  if (c) {
    connectors.set(id, {
      ...c,
      status,
      last_poll_at: new Date().toISOString(),
      error_message: errorMessage,
    });
  }
}

// ============================================================================
// GuardDuty Detector Discovery
// ============================================================================

/** Cache of GuardDuty detector IDs per account+region */
const detectorCache = new Map<string, string>();
/** Track services that are not subscribed — stop retrying */
const unavailableServices = new Set<string>();

async function getGuardDutyDetectorId(
  accountId: string,
  region: string,
  roleArn: string
): Promise<string | null> {
  const key = `${accountId}:${region}`;
  if (detectorCache.has(key)) return detectorCache.get(key)!;

  try {
    const { GuardDutyClient, ListDetectorsCommand } = await import('@aws-sdk/client-guardduty');
    const { fromTemporaryCredentials } = await import('@aws-sdk/credential-providers');

    const credentials = fromTemporaryCredentials({
      params: { RoleArn: roleArn, RoleSessionName: 'WatcherMK1-DetectorDiscovery' },
      clientConfig: { region },
    });

    const client = new GuardDutyClient({ region, credentials });
    const response = await client.send(new ListDetectorsCommand({}));
    const detectorId = response.DetectorIds?.[0];

    if (detectorId) {
      detectorCache.set(key, detectorId);
      return detectorId;
    }
  } catch (err) {
    console.error(`[Polling] Failed to discover GuardDuty detector for ${accountId}/${region}:`, err);
  }

  return null;
}

// ============================================================================
// Polling Loop
// ============================================================================

/** Tracks pollers per connector+region */
const cloudTrailPollers = new Map<string, CloudTrailPoller>();
const guardDutyPollers = new Map<string, GuardDutyPoller>();
const securityHubPollers = new Map<string, SecurityHubPoller>();

let pollingInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Polls a single connector across all its regions.
 * Returns the total number of events processed.
 */
async function pollConnector(
  connector: RegisteredConnector,
  pipeline: EventPipeline
): Promise<number> {
  // Double-check pause status (in case paused mid-cycle)
  const current = connectors.get(connector.id);
  if (current?.status === 'PAUSED') return 0;

  let totalEvents = 0;

  for (const region of connector.regions) {
    const pollerKey = `${connector.id}:${region}`;

    try {
      // ── CloudTrail ──────────────────────────────────────────────────────
      if (connector.data_sources.includes(AwsDataSource.CLOUDTRAIL)) {
        if (!cloudTrailPollers.has(pollerKey)) {
          cloudTrailPollers.set(pollerKey, new CloudTrailPoller({
            roleArn: connector.role_arn,
            region,
            tenantId: connector.tenant_id,
            accountId: connector.account_id,
            // Default: 90 days (CloudTrail max) for full catch-up on first connection.
            // Override with POLL_LOOKBACK_MINUTES env var for faster testing.
            lookbackMinutes: parseInt(process.env['POLL_LOOKBACK_MINUTES'] ?? String(90 * 24 * 60), 10),
          }));
        }
        const ctEvents = await cloudTrailPollers.get(pollerKey)!.poll();

        let processed = 0;
        let skipped = 0;
        let correlated = 0;

        for (const event of ctEvents) {
          const decision = decideEventAction(event);
          const payload = event.raw_payload as Record<string, unknown>;
          const evtName = String(payload['eventName'] ?? '');
          const actor = String((event.raw_payload as any)?.userIdentity?.arn ?? 'unknown');
          const actorShort = actor.split('/').pop() ?? actor.split(':').pop() ?? 'unknown';
          const sourceIp = String((event.raw_payload as any)?.sourceIPAddress ?? 'unknown');
          const eventIdStr = String((event.raw_payload as any)?.eventID ?? `gen-${Date.now()}`);
          const eventTime = String((event.raw_payload as any)?.eventTime ?? new Date().toISOString());
          const actorType = String((event.raw_payload as any)?.userIdentity?.type ?? 'unknown');
          const errorCode = (event.raw_payload as any)?.errorCode ?? null;

          // Record this event in the polled events store for UI visibility
          const polledEventBase = {
            id: eventIdStr,
            event_name: evtName,
            event_time: eventTime,
            received_at: new Date().toISOString(),
            source: 'CLOUDTRAIL',
            account_id: event.account_id,
            region: event.region,
            actor_arn: actor,
            actor_type: actorType,
            actor_short: actorShort,
            source_ip: /^\d+\.\d+\.\d+\.\d+$/.test(sourceIp) ? sourceIp : null,
            error_code: errorCode,
            raw_payload: event.raw_payload,
          };

          switch (decision.action) {
            case 'SKIP':
              console.log(`[Correlator] SKIP: ${evtName} | actor: ${actorShort} | ip: ${sourceIp} | reason: ${decision.reason}`);
              addPolledEvent({ ...polledEventBase, status: 'SKIPPED', reason: decision.reason, incident_id: null });
              skipped++;
              break;

            case 'CORRELATE':
              appendToIncident(decision.incident_id, event);
              console.log(`[Correlator] CORRELATED: ${evtName} | actor: ${actorShort} | eventID: ${eventIdStr.slice(0, 8)} → incident ${decision.incident_id.slice(0, 8)}... | ${decision.reason}`);
              addPolledEvent({ ...polledEventBase, status: 'CORRELATED', reason: decision.reason, incident_id: decision.incident_id });
              correlated++;
              break;

            case 'PROCESS': {
              const contextNote = decision.existing_incident_id
                ? ` [re-analysis of incident ${decision.existing_incident_id.slice(0, 8)}]`
                : '';
              console.log(`[Correlator] PROCESS: ${evtName} | actor: ${actorShort} | ip: ${sourceIp} | eventID: ${eventIdStr.slice(0, 8)}${contextNote}`);

              // Inject existing incident context into the raw event so the AI knows about it
              if (decision.existing_incident_id) {
                const existingIncident = getIncidentById(decision.existing_incident_id);
                if (existingIncident) {
                  (event.raw_payload as any)['_watcher_existing_incident'] = {
                    id: existingIncident.id,
                    threat_type: existingIncident.severity_level,
                    evidence_count: (existingIncident.evidence ?? []).length,
                    created_at: existingIncident.created_at,
                  };
                }
              }

              const result = await pipeline.processRawEvent(event);
              const incidentId = result.incident_id ?? decision.existing_incident_id ?? null;
              addPolledEvent({ ...polledEventBase, status: 'PROCESSED', reason: decision.reason, incident_id: incidentId });
              writeResultToStore(result, connector.tenant_id, actor);
              processed++;
              totalEvents++;
              break;
            }
          }
        }

        if (ctEvents.length > 0) {
          console.log(`[Polling] CloudTrail: ${ctEvents.length} events → ${processed} processed, ${correlated} correlated, ${skipped} skipped`);
        }
      }

      // ── GuardDuty ───────────────────────────────────────────────────────
      if (connector.data_sources.includes(AwsDataSource.GUARDDUTY)) {
        const gdKey = `guardduty:${connector.account_id}:${region}`;
        if (!unavailableServices.has(gdKey)) {
          const detectorId = await getGuardDutyDetectorId(
            connector.account_id,
            region,
            connector.role_arn
          );

          if (detectorId === null) {
            unavailableServices.add(gdKey);
            console.log(`[Polling] GuardDuty not available for ${connector.account_id}/${region} — will not retry`);
          } else {
            if (!guardDutyPollers.has(pollerKey)) {
              guardDutyPollers.set(pollerKey, new GuardDutyPoller({
                roleArn: connector.role_arn,
                region,
                tenantId: connector.tenant_id,
                accountId: connector.account_id,
                detectorId,
              }));
            }

            const gdEvents = await guardDutyPollers.get(pollerKey)!.poll();
            for (const event of gdEvents) {
              const decision = decideEventAction(event);
              if (decision.action === 'PROCESS') {
                const result = await pipeline.processRawEvent(event);
                writeResultToStore(result, connector.tenant_id);
                totalEvents++;
              } else if (decision.action === 'CORRELATE') {
                appendToIncident(decision.incident_id, event);
              }
            }

            if (gdEvents.length > 0) {
              console.log(`[Polling] GuardDuty: ${gdEvents.length} findings from ${connector.account_id}/${region}`);
            }
          }
        }
      }

      // ── Security Hub ────────────────────────────────────────────────────
      if (connector.data_sources.includes(AwsDataSource.SECURITY_HUB)) {
        const shKey = `securityhub:${connector.account_id}:${region}`;
        if (!unavailableServices.has(shKey)) {
          if (!securityHubPollers.has(pollerKey)) {
            securityHubPollers.set(pollerKey, new SecurityHubPoller({
              roleArn: connector.role_arn,
              region,
              tenantId: connector.tenant_id,
              accountId: connector.account_id,
            }));
          }

          try {
            const shEvents = await securityHubPollers.get(pollerKey)!.poll();
            for (const event of shEvents) {
              const decision = decideEventAction(event);
              if (decision.action === 'PROCESS') {
                const result = await pipeline.processRawEvent(event);
                writeResultToStore(result, connector.tenant_id);
                totalEvents++;
              } else if (decision.action === 'CORRELATE') {
                appendToIncident(decision.incident_id, event);
              }
            }

            if (shEvents.length > 0) {
              console.log(`[Polling] SecurityHub: ${shEvents.length} findings from ${connector.account_id}/${region}`);
            }
          } catch (shErr: unknown) {
            const msg = shErr instanceof Error ? shErr.message : String(shErr);
            if (msg.includes('SubscriptionRequired')) {
              unavailableServices.add(shKey);
              console.log(`[Polling] SecurityHub not available for ${connector.account_id}/${region} — will not retry`);
            } else {
              console.error(`[Polling] SecurityHub error: ${msg}`);
            }
          }
        }
      }

    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[Polling] Error polling ${connector.id}/${region}: ${message}`);
      updateConnectorStatus(connector.id, 'ERROR', message);
      return totalEvents;
    }
  }

  updateConnectorStatus(connector.id, 'ACTIVE');
  return totalEvents;
}

/**
 * Starts the polling loop. Polls all registered connectors every 60 seconds.
 * Call this once when the server starts.
 */
export function startPollingLoop(pipeline: EventPipeline, intervalMs = 60_000): void {
  if (pollingInterval) {
    console.log('[Polling] Loop already running');
    return;
  }

  console.log(`[Polling] Starting polling loop (interval: ${intervalMs / 1000}s)`);

  const runPoll = async () => {
    const active = getConnectors().filter((c) => c.status !== 'PAUSED');
    if (active.length === 0) return;

    console.log(`[Polling] Polling ${active.length} connector(s)...`);
    let total = 0;
    for (const connector of active) {
      total += await pollConnector(connector, pipeline);
    }
    if (total > 0) {
      console.log(`[Polling] Processed ${total} event(s) this cycle`);
    }
  };

  // Run immediately on start, then on interval
  runPoll().catch(console.error);
  pollingInterval = setInterval(() => runPoll().catch(console.error), intervalMs);
}

/**
 * Stops the polling loop.
 */
export function stopPollingLoop(): void {
  if (pollingInterval) {
    clearInterval(pollingInterval);
    pollingInterval = null;
    console.log('[Polling] Loop stopped');
  }
}
