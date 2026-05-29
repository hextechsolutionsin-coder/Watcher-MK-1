/**
 * Connector Registration API
 *
 * Customers register their AWS account here after deploying the
 * CloudFormation template. Once registered, the polling loop
 * automatically starts monitoring their account.
 */

import { Router, Request, Response } from 'express';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';
import {
  registerConnector,
  getConnectors,
  getConnectorById,
  updateConnectorStatus,
  type RegisteredConnector,
} from '../../pipeline/polling-loop.js';
import { AwsDataSource } from '../../types/index.js';

const router = Router();

function generateId(): string {
  return `conn-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * POST /api/v1/connectors
 * Register a new AWS account connector.
 *
 * Body:
 * {
 *   "tenant_id": "tenant-001",
 *   "role_arn": "arn:aws:iam::123456789012:role/WatcherMK1-ConnectorRole",
 *   "account_id": "123456789012",
 *   "regions": ["us-east-1"],
 *   "data_sources": ["CLOUDTRAIL", "GUARDDUTY", "SECURITY_HUB"]  // optional, defaults to all
 * }
 */
router.post('/', async (req: Request, res: Response) => {
  const { tenant_id, role_arn, account_id, regions, data_sources } = req.body as {
    tenant_id?: string;
    role_arn?: string;
    account_id?: string;
    regions?: string[];
    data_sources?: string[];
  };

  // Validate required fields
  if (!role_arn) return res.status(400).json({ error: 'role_arn is required' });
  if (!account_id) return res.status(400).json({ error: 'account_id is required' });
  if (!tenant_id) return res.status(400).json({ error: 'tenant_id is required' });

  const resolvedRegions = regions && regions.length > 0 ? regions : ['us-east-1'];
  const resolvedSources = (data_sources ?? ['CLOUDTRAIL', 'GUARDDUTY', 'SECURITY_HUB'])
    .map((s) => s.toUpperCase())
    .filter((s) => s in AwsDataSource) as AwsDataSource[];

  // Verify the role is assumable before registering
  console.log(`[Connector] Verifying role: ${role_arn}`);
  try {
    const region = resolvedRegions[0]!;
    const credentials = fromTemporaryCredentials({
      params: {
        RoleArn: role_arn,
        RoleSessionName: 'WatcherMK1-Verification',
        DurationSeconds: 900,
      },
      clientConfig: { region },
    });

    // Try to get caller identity — proves the role is assumable
    const stsClient = new STSClient({ region, credentials });
    const identity = await stsClient.send(new GetCallerIdentityCommand({}));

    console.log(`[Connector] Role verified. Account: ${identity.Account}, ARN: ${identity.Arn}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[Connector] Role verification failed: ${message}`);
    return res.status(400).json({
      error: 'Failed to assume the provided role. Verify the role ARN and trust policy.',
      detail: message,
    });
  }

  const connector: RegisteredConnector = {
    id: generateId(),
    tenant_id,
    account_id,
    role_arn,
    regions: resolvedRegions,
    data_sources: resolvedSources,
    registered_at: new Date().toISOString(),
    last_poll_at: null,
    status: 'ACTIVE',
  };

  registerConnector(connector);

  console.log(`[Connector] Registered: ${connector.id} for account ${account_id} in ${resolvedRegions.join(', ')}`);
  console.log(`[Connector] Monitoring: ${resolvedSources.join(', ')}`);
  console.log(`[Connector] Polling will begin within 60 seconds`);

  return res.status(201).json({
    success: true,
    connector_id: connector.id,
    account_id,
    regions: resolvedRegions,
    data_sources: resolvedSources,
    status: 'ACTIVE',
    message: `Connector registered. Watcher will begin polling ${resolvedSources.join(', ')} within 60 seconds.`,
  });
});

/**
 * GET /api/v1/connectors
 * List all registered connectors.
 */
router.get('/', (_req: Request, res: Response) => {
  const all = getConnectors().map((c: RegisteredConnector) => ({
    id: c.id,
    tenant_id: c.tenant_id,
    account_id: c.account_id,
    regions: c.regions,
    data_sources: c.data_sources,
    status: c.status,
    registered_at: c.registered_at,
    last_poll_at: c.last_poll_at,
    error_message: c.error_message,
  }));
  res.json(all);
});

/**
 * GET /api/v1/connectors/:id
 * Get a specific connector's status.
 */
router.get('/:id', (req: Request, res: Response) => {
  const connector = getConnectorById(String(req.params['id']));
  if (!connector) return res.status(404).json({ error: 'Connector not found' });
  res.json(connector);
});

/**
 * DELETE /api/v1/connectors/:id
 * Pause a connector (stops polling without deleting registration).
 */
router.delete('/:id', (req: Request, res: Response) => {
  const id = String(req.params['id']);
  const connector = getConnectorById(id);
  if (!connector) return res.status(404).json({ error: 'Connector not found' });

  updateConnectorStatus(id, 'PAUSED');
  console.log(`[Connector] Paused: ${id}`);
  res.json({ success: true, message: 'Connector paused. Polling stopped.' });
});

export default router;
