import { Router, Request, Response } from 'express';
import { memoryLayer } from '../memory-layer-instance.js';

const router = Router();

/**
 * GET /api/v1/memory/health
 *
 * Returns the current Supermemory connection status.
 * Always returns HTTP 200 — the status field is informational, not an error signal.
 *
 * Validates: Requirement 9.4
 */
router.get('/health', (_req: Request, res: Response) => {
  const status = memoryLayer.healthCheck();
  res.json({
    status,
    timestamp: new Date().toISOString(),
  });
});

export default router;
