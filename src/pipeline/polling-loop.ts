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
import { AwsDataSource, type RawAwsEvent } from '../types/index.js';

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
            lookbackMinutes: 60,
          }));
        }

        const ctEvents = await cloudTrailPollers.get(pollerKey)!.poll();
        for (const event of ctEvents) {
          await pipeline.processRawEvent(event);
          totalEvents++;
        }

        if (ctEvents.length > 0) {
          console.log(`[Polling] CloudTrail: ${ctEvents.length} events from ${connector.account_id}/${region}`);
        }
      }

      // ── GuardDuty ───────────────────────────────────────────────────────
      if (connector.data_sources.includes(AwsDataSource.GUARDDUTY)) {
        const detectorId = await getGuardDutyDetectorId(
          connector.account_id,
          region,
          connector.role_arn
        );

        if (detectorId) {
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
            await pipeline.processRawEvent(event);
            totalEvents++;
          }

          if (gdEvents.length > 0) {
            console.log(`[Polling] GuardDuty: ${gdEvents.length} findings from ${connector.account_id}/${region}`);
          }
        }
      }

      // ── Security Hub ────────────────────────────────────────────────────
      if (connector.data_sources.includes(AwsDataSource.SECURITY_HUB)) {
        if (!securityHubPollers.has(pollerKey)) {
          securityHubPollers.set(pollerKey, new SecurityHubPoller({
            roleArn: connector.role_arn,
            region,
            tenantId: connector.tenant_id,
            accountId: connector.account_id,
          }));
        }

        const shEvents = await securityHubPollers.get(pollerKey)!.poll();
        for (const event of shEvents) {
          await pipeline.processRawEvent(event);
          totalEvents++;
        }

        if (shEvents.length > 0) {
          console.log(`[Polling] SecurityHub: ${shEvents.length} findings from ${connector.account_id}/${region}`);
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
