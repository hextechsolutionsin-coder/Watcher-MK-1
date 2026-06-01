import { Router, Request, Response } from 'express';
import { getPendingApprovals, getActionById, updateAction, addAction, addTimelineEvent } from '../store.js';
import { RealAwsApiClient } from '../../connectors/aws-connector.js';
import { getConnectors } from '../../pipeline/polling-loop.js';

const router = Router();
const awsClient = new RealAwsApiClient();

/** GET /api/v1/approvals — all pending approval requests */
router.get('/', (_req: Request, res: Response) => {
  res.json(getPendingApprovals());
});

/** POST /api/v1/approvals/:action_id/approve */
router.post('/:action_id/approve', async (req: Request, res: Response) => {
  const action_id = String(req.params['action_id']);
  const { approver_id } = req.body as { approver_id?: string };

  if (!approver_id) return res.status(400).json({ error: 'approver_id is required' });

  const action = getActionById(action_id);
  if (!action) return res.status(404).json({ error: 'Action not found' });
  if (action.status !== 'PENDING_APPROVAL') {
    return res.status(409).json({ error: `Action is not pending approval (status: ${action.status})` });
  }

  const now = new Date().toISOString();

  // Update status to EXECUTING
  updateAction(action_id, { status: 'EXECUTING', approver_id, updated_at: now });

  addTimelineEvent({
    id: `tl-${Date.now()}`,
    incident_id: action.incident_id,
    timestamp: now,
    type: 'approval',
    title: 'Action Approved',
    description: `${action.action_type} approved by ${approver_id}`,
    actor: approver_id,
  });

  // Execute the action against AWS
  try {
    // Find the connector's role ARN for this tenant
    const connectors = getConnectors().filter((c) => c.tenant_id === action.tenant_id && c.status === 'ACTIVE');
    const roleArn = connectors[0]?.role_arn;

    if (!roleArn) {
      updateAction(action_id, { status: 'FAILED', outcome: 'No active connector found', updated_at: new Date().toISOString() });
      addTimelineEvent({
        id: `tl-${Date.now()}`,
        incident_id: action.incident_id,
        timestamp: new Date().toISOString(),
        type: 'remediation',
        title: 'Action Failed',
        description: `${action.action_type} failed: No active connector found for tenant`,
        actor: 'Watcher MK-1',
      });
      return res.json({ ...action, status: 'FAILED', outcome: 'No active connector found' });
    }

    // Parse the action type to determine the AWS API call
    const execution = await executeApprovedAction(action.action_type, action.affected_asset, roleArn, action.ai_params);

    if (execution.success) {
      // Verify the action actually took effect
      const verification = await verifyAction(action.action_type, action.affected_asset, roleArn, action.ai_params);

      const updated = updateAction(action_id, {
        status: 'COMPLETED',
        outcome: verification.verified ? 'SUCCESS' : `SUCCESS_UNVERIFIED: ${verification.detail}`,
        execution_timestamp: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });

      addTimelineEvent({
        id: `tl-${Date.now()}`,
        incident_id: action.incident_id,
        timestamp: new Date().toISOString(),
        type: 'remediation',
        title: 'Action Executed',
        description: `${action.action_type} executed successfully: ${execution.detail}`,
        actor: 'Watcher MK-1',
      });

      console.log(`[Approval] ✅ Executed: ${action.action_type} on ${action.affected_asset?.identifier ?? 'unknown'}`);
      return res.json(updated);
    } else {
      const updated = updateAction(action_id, {
        status: 'FAILED',
        outcome: `FAILURE: ${execution.detail}`,
        updated_at: new Date().toISOString(),
      });

      addTimelineEvent({
        id: `tl-${Date.now()}`,
        incident_id: action.incident_id,
        timestamp: new Date().toISOString(),
        type: 'remediation',
        title: 'Action Failed',
        description: `${action.action_type} failed: ${execution.detail}`,
        actor: 'Watcher MK-1',
      });

      // Create a new retry action with incremented retry_count
      const retryAction = {
        id: `${action.id}-retry-${action.retry_count + 1}`,
        incident_id: action.incident_id,
        tenant_id: action.tenant_id,
        action_type: action.action_type,
        status: 'PENDING_APPROVAL',
        severity_level: action.severity_level,
        retry_count: action.retry_count + 1,
        affected_asset: action.affected_asset,
        ai_reasoning: action.ai_reasoning,
        ai_params: action.ai_params,
        blast_radius: action.blast_radius,
        rollback_description: action.rollback_description,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      addAction(retryAction);

      addTimelineEvent({
        id: `tl-${Date.now()}-retry`,
        incident_id: action.incident_id,
        timestamp: new Date().toISOString(),
        type: 'approval',
        title: 'Retry Queued',
        description: `${action.action_type} re-queued for approval (retry #${retryAction.retry_count})`,
        actor: 'Watcher MK-1',
      });

      console.log(`[Approval] ❌ Failed: ${action.action_type} — ${execution.detail} (retry queued)`);
      return res.json(updated);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    updateAction(action_id, { status: 'FAILED', outcome: `ERROR: ${message}`, updated_at: new Date().toISOString() });
    console.error(`[Approval] Error executing ${action.action_type}:`, message);
    return res.json({ ...action, status: 'FAILED', outcome: message });
  }
});

/** POST /api/v1/approvals/:action_id/reject */
router.post('/:action_id/reject', (req: Request, res: Response) => {
  const action_id = String(req.params['action_id']);
  const { approver_id, reason } = req.body as { approver_id?: string; reason?: string };

  if (!approver_id) return res.status(400).json({ error: 'approver_id is required' });
  if (!reason) return res.status(400).json({ error: 'reason is required' });

  const action = getActionById(action_id);
  if (!action) return res.status(404).json({ error: 'Action not found' });
  if (action.status !== 'PENDING_APPROVAL') {
    return res.status(409).json({ error: `Action is not pending approval (status: ${action.status})` });
  }

  const now = new Date().toISOString();
  const updated = updateAction(action_id, {
    status: 'REJECTED', approver_id, rejection_reason: reason, updated_at: now,
  });

  addTimelineEvent({
    id: `tl-${Date.now()}`,
    incident_id: action.incident_id,
    timestamp: now,
    type: 'approval',
    title: 'Action Rejected',
    description: `${action.action_type} rejected by ${approver_id}: ${reason}`,
    actor: approver_id,
  });

  console.log(`[Approval] 🚫 Rejected: ${action.action_type} by ${approver_id} — ${reason}`);
  res.json(updated);
});

/** POST /api/v1/approvals/:action_id/retry — re-queue a failed action */
router.post('/:action_id/retry', (req: Request, res: Response) => {
  const action_id = String(req.params['action_id']);

  const action = getActionById(action_id);
  if (!action) return res.status(404).json({ error: 'Action not found' });
  if (action.status !== 'FAILED') {
    return res.status(409).json({ error: `Action is not failed (status: ${action.status})` });
  }

  const MAX_RETRIES = 3;
  if (action.retry_count >= MAX_RETRIES) {
    return res.status(409).json({
      error: `Maximum retries (${MAX_RETRIES}) reached. Manual intervention required.`,
      retry_count: action.retry_count,
    });
  }

  const now = new Date().toISOString();
  const newRetryCount = action.retry_count + 1;

  // Use base ID to avoid chained IDs like action-retry-1-retry-2-retry-3
  const baseId = action.id.replace(/-retry-\d+$/, '');

  const retryAction = {
    id: `${baseId}-retry-${newRetryCount}`,
    incident_id: action.incident_id,
    tenant_id: action.tenant_id,
    action_type: action.action_type,
    status: 'PENDING_APPROVAL',
    severity_level: action.severity_level,
    retry_count: newRetryCount,
    affected_asset: action.affected_asset,
    ai_reasoning: action.ai_reasoning,
    ai_params: action.ai_params,
    blast_radius: action.blast_radius,
    rollback_description: action.rollback_description,
    created_at: now,
    updated_at: now,
  };
  addAction(retryAction);

  addTimelineEvent({
    id: `tl-${Date.now()}-retry`,
    incident_id: action.incident_id,
    timestamp: now,
    type: 'approval',
    title: 'Manual Retry',
    description: `${action.action_type} manually re-queued for approval (attempt #${newRetryCount} of ${MAX_RETRIES})`,
    actor: 'operator',
  });

  console.log(`[Approval] 🔄 Retry queued: ${action.action_type} (attempt #${newRetryCount}/${MAX_RETRIES})`);
  res.status(201).json(retryAction);
});

// ============================================================================
// Action Execution Logic
// ============================================================================

interface ExecutionResult {
  success: boolean;
  detail: string;
}

interface VerificationResult {
  verified: boolean;
  detail: string;
}

async function verifyAction(
  actionType: string,
  affectedAsset: any,
  roleArn: string,
  aiParams?: Record<string, unknown>
): Promise<VerificationResult> {
  try {
    const userNameFromParams = aiParams?.['UserName'] ? String(aiParams['UserName']) : null;
    const rawIdentifier = String(affectedAsset?.identifier ?? '');

    function extractUsername(id: string): string | null {
      if (id.includes(':root')) return null;
      if (id.includes(':user/')) return id.split(':user/').pop()!;
      if (id.includes('/')) return id.split('/').pop()!;
      if (id.startsWith('arn:aws:')) return null;
      return id || null;
    }

    switch (actionType) {
      case 'aws:iam:disable-access-key':
      case 'DISABLE_ACCESS_KEY':
      case 'REVOKE_CREDENTIALS': {
        const userName = userNameFromParams ?? extractUsername(rawIdentifier);
        if (!userName) return { verified: false, detail: 'Cannot verify root account key status' };

        const result = await awsClient.execute('iam', 'ListAccessKeys', { UserName: userName }, roleArn);
        if (!result.success) return { verified: false, detail: `Verification call failed: ${result.errorMessage}` };

        const keys = (result.response as any)?.AccessKeyMetadata ?? [];
        const hasActiveKey = keys.some((k: any) => k.Status === 'Active');
        return hasActiveKey
          ? { verified: false, detail: `User ${userName} still has active access keys` }
          : { verified: true, detail: `Confirmed: no active access keys for ${userName}` };
      }

      case 'aws:iam:attach-deny-policy':
      case 'DISABLE_USER_ACCOUNT': {
        const userName = userNameFromParams ?? extractUsername(rawIdentifier);
        if (!userName) return { verified: false, detail: 'Cannot verify policy attachment' };

        const { IAMClient, ListAttachedUserPoliciesCommand } = await import('@aws-sdk/client-iam');
        const { createAssumedRoleCredentials } = await import('../../connectors/aws-connector.js');
        const region = process.env['AWS_REGION'] ?? 'us-east-1';
        const credentials = createAssumedRoleCredentials(roleArn, region);
        const client = new IAMClient({ region, credentials });
        const response = await client.send(new ListAttachedUserPoliciesCommand({ UserName: userName }));
        const hasDenyAll = (response.AttachedPolicies ?? []).some(
          (p) => p.PolicyArn === 'arn:aws:iam::aws:policy/AWSDenyAll'
        );
        return hasDenyAll
          ? { verified: true, detail: `Confirmed: AWSDenyAll attached to ${userName}` }
          : { verified: false, detail: `AWSDenyAll not found on ${userName} — may need retry` };
      }

      default:
        return { verified: true, detail: 'No verification available for this action type' };
    }
  } catch (err) {
    return { verified: false, detail: `Verification error: ${err instanceof Error ? err.message : String(err)}` };
  }
}

async function executeApprovedAction(
  actionType: string,
  affectedAsset: any,
  roleArn: string,
  aiParams?: Record<string, unknown>
): Promise<ExecutionResult> {
  const rawIdentifier = String(affectedAsset?.identifier ?? '');

  // Extract clean username — prefer ai_params.UserName (most accurate),
  // then parse from ARN/identifier
  function extractUsername(id: string): string | null {
    if (id.includes(':root')) return null;
    if (id.includes(':user/')) return id.split(':user/').pop()!;
    if (id.includes('/')) return id.split('/').pop()!;
    if (id.startsWith('arn:aws:')) return null;
    return id || null;
  }

  // Use UserName from AI params if available — it's always correct
  const userNameFromParams = aiParams?.['UserName'] ? String(aiParams['UserName']) : null;

  switch (actionType) {
    case 'aws:iam:disable-access-key':
    case 'DISABLE_ACCESS_KEY':
    case 'REVOKE_CREDENTIALS': {
      const userName = userNameFromParams ?? extractUsername(rawIdentifier);
      if (!userName) {
        return { success: false, detail: `Cannot disable access key for "${rawIdentifier}" — root accounts require manual intervention` };
      }

      const listResult = await awsClient.execute('iam', 'ListAccessKeys', { UserName: userName }, roleArn);
      if (!listResult.success) return { success: false, detail: `Failed to list keys for ${userName}: ${listResult.errorMessage}` };

      const keys = (listResult.response as any)?.AccessKeyMetadata ?? [];
      const activeKey = keys.find((k: any) => k.Status === 'Active');
      if (!activeKey) return { success: false, detail: `No active access key found for user ${userName}` };

      const result = await awsClient.execute('iam', 'UpdateAccessKey', {
        UserName: userName,
        AccessKeyId: activeKey.AccessKeyId,
        Status: 'Inactive',
      }, roleArn);

      return result.success
        ? { success: true, detail: `Disabled access key ${activeKey.AccessKeyId} for user ${userName}` }
        : { success: false, detail: result.errorMessage ?? 'Unknown error' };
    }

    case 'aws:ec2:stop-instance':
    case 'STOP_INSTANCE':
    case 'ISOLATE_HOST': {
      const instanceIds = aiParams?.['InstanceIds'] as string[] | undefined;
      const instanceId = instanceIds?.[0]
        ? String(instanceIds[0])
        : rawIdentifier.includes('/') ? rawIdentifier.split('/').pop()! : rawIdentifier;

      const result = await awsClient.execute('ec2', 'StopInstances', {
        InstanceIds: [instanceId],
      }, roleArn);

      return result.success
        ? { success: true, detail: `Stopped instance ${instanceId}` }
        : { success: false, detail: result.errorMessage ?? 'Unknown error' };
    }

    case 'aws:ec2:revoke-sg-ingress':
    case 'BLOCK_IP': {
      return { success: false, detail: 'BLOCK_IP requires security group ID and IP — manual action needed' };
    }

    case 'aws:iam:attach-deny-policy':
    case 'DISABLE_USER_ACCOUNT': {
      const userName = userNameFromParams ?? extractUsername(rawIdentifier);
      if (!userName) {
        return { success: false, detail: `Cannot attach deny policy to "${rawIdentifier}" — not a valid IAM user` };
      }

      const result = await awsClient.execute('iam', 'AttachUserPolicy', {
        UserName: userName,
        PolicyArn: 'arn:aws:iam::aws:policy/AWSDenyAll',
      }, roleArn);

      return result.success
        ? { success: true, detail: `Attached DenyAll policy to user ${userName}` }
        : { success: false, detail: result.errorMessage ?? 'Unknown error' };
    }

    default:
      console.log(`[Approval] Action type '${actionType}' not mapped to AWS API — marking as advisory`);
      return { success: true, detail: `Advisory action logged: ${actionType}` };
  }
}

export default router;
