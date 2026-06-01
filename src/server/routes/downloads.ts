/**
 * Downloads route — serves the CloudFormation template for customers.
 */

import { Router, Request, Response } from 'express';
import { readFileSync, existsSync } from 'fs';
import { resolve, join } from 'path';

const router = Router();

/**
 * Resolves the project root directory.
 * Works whether running from src/ (tsx) or dist/ (compiled).
 */
function getProjectRoot(): string {
  // When running with tsx: process.cwd() is the project root
  // When running compiled: dist/server/routes/ → go up 3 levels
  const cwd = process.cwd();
  if (existsSync(join(cwd, 'cloudformation', 'watcher-connector-role.yaml'))) {
    return cwd;
  }
  // Fallback: try going up from __dirname equivalent
  return resolve(cwd, '..');
}

/**
 * GET /api/v1/downloads/cloudformation
 * Returns the CloudFormation YAML template for customer IAM role setup.
 */
router.get('/cloudformation', (_req: Request, res: Response) => {
  try {
    const templatePath = join(getProjectRoot(), 'cloudformation', 'watcher-connector-role.yaml');
    const template = readFileSync(templatePath, 'utf-8');

    res.setHeader('Content-Type', 'application/x-yaml');
    res.setHeader('Content-Disposition', 'attachment; filename="watcher-connector-role.yaml"');
    res.send(template);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error('[Downloads] Failed to serve CloudFormation template:', message);
    res.status(500).json({ error: 'Failed to load CloudFormation template' });
  }
});

/**
 * GET /api/v1/downloads/cloudformation/preview
 * Returns the template as JSON for preview in the UI (not as a download).
 */
router.get('/cloudformation/preview', (_req: Request, res: Response) => {
  try {
    const templatePath = join(getProjectRoot(), 'cloudformation', 'watcher-connector-role.yaml');
    const template = readFileSync(templatePath, 'utf-8');
    res.json({ filename: 'watcher-connector-role.yaml', content: template });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load template' });
  }
});

export default router;
