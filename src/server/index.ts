import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { testConnection } from '../database/connection.js';
import { authRouter, authMiddleware } from './auth.js';
import incidentsRouter from './routes/incidents.js';
import approvalsRouter from './routes/approvals.js';
import actionsRouter from './routes/actions.js';
import metricsRouter from './routes/metrics.js';
import webhooksRouter from './routes/webhooks.js';
import pipelineRouter from './routes/pipeline.js';
import connectorsRouter from './routes/connectors.js';
import downloadsRouter from './routes/downloads.js';
import suppressionsRouter from './routes/suppressions.js';
import eventsRouter from './routes/events.js';
import memoryRouter from './routes/memory.js';
import { pipeline } from './pipeline-instance.js';
import { startPollingLoop, setWatcherAccountId } from '../pipeline/polling-loop.js';
import { hydrateFromDatabase } from './store.js';

const app = express();
const PORT = parseInt(process.env['PORT'] ?? '4000', 10);

app.use(cors({
  origin: process.env['CORS_ORIGIN'] ?? 'http://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// ── Public routes (no auth required) ──────────────────────────────────────────
app.get('/api/v1/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    ai_model: 'us.anthropic.claude-sonnet-4-6',
    bedrock_region: process.env['AWS_REGION'] ?? 'not configured',
    db_enabled: process.env['DB_ENABLED'] === 'true',
    auth_enabled: process.env['AUTH_ENABLED'] === 'true',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/v1/auth', authRouter);

// ── Protected routes (auth middleware applied) ────────────────────────────────
app.use('/api/v1/incidents', authMiddleware, incidentsRouter);
app.use('/api/v1/approvals', authMiddleware, approvalsRouter);
app.use('/api/v1/actions', authMiddleware, actionsRouter);
app.use('/api/v1/metrics', authMiddleware, metricsRouter);
app.use('/api/v1/webhooks', webhooksRouter); // webhooks use their own auth (token-based)
app.use('/api/v1/pipeline', authMiddleware, pipelineRouter);
app.use('/api/v1/connectors', authMiddleware, connectorsRouter);
app.use('/api/v1/suppressions', authMiddleware, suppressionsRouter);
app.use('/api/v1/events', authMiddleware, eventsRouter);
app.use('/api/v1/memory', memoryRouter); // public health check for Supermemory status
app.use('/api/v1/downloads', downloadsRouter); // public — customers need this before auth

// ── Server startup ────────────────────────────────────────────────────────────
async function start() {
  // Test DB connection if enabled
  if (process.env['DB_ENABLED'] === 'true') {
    const connected = await testConnection();
    if (!connected) {
      console.error('[Watcher MK-1] Database connection failed. Check DB_* env vars.');
      console.error('[Watcher MK-1] Starting without database (in-memory mode).');
    } else {
      // Hydrate in-memory store from DB — restores incidents, actions, connectors
      await hydrateFromDatabase();
    }
  } else {
    console.log('[Watcher MK-1] Database disabled (DB_ENABLED != true). Using in-memory stores.');
  }

  // Determine Watcher account ID for self-filtering
  if (process.env['AWS_ACCESS_KEY_ID']) {
    try {
      const { STSClient, GetCallerIdentityCommand } = await import('@aws-sdk/client-sts');
      const sts = new STSClient({ region: process.env['AWS_REGION'] ?? 'us-east-1' });
      const identity = await sts.send(new GetCallerIdentityCommand({}));
      if (identity.Account) {
        setWatcherAccountId(identity.Account);
      }
    } catch {
      console.log('[Watcher MK-1] Could not determine Watcher account ID — self-filtering may be incomplete');
    }
  }

  app.listen(PORT, () => {
    console.log(`[Watcher MK-1] API server running on http://localhost:${PORT}`);
    console.log(`[Watcher MK-1] AI Model: us.anthropic.claude-sonnet-4-6`);
    console.log(`[Watcher MK-1] Bedrock Region: ${process.env['AWS_REGION'] ?? 'not configured'}`);
    console.log(`[Watcher MK-1] Auth: ${process.env['AUTH_ENABLED'] === 'true' ? 'ENABLED' : 'DISABLED (dev mode)'}`);
    console.log(`[Watcher MK-1] CORS: ${process.env['CORS_ORIGIN'] ?? 'http://localhost:5173'}`);

    // Start polling loop — interval configurable via POLL_INTERVAL_SECONDS env var
    const pollIntervalMs = parseInt(process.env['POLL_INTERVAL_SECONDS'] ?? '60', 10) * 1000;
    startPollingLoop(pipeline, pollIntervalMs);
    console.log(`[Watcher MK-1] Polling loop started (${pollIntervalMs / 1000}s interval)`);
  });
}

start().catch((err) => {
  console.error('[Watcher MK-1] Fatal startup error:', err);
  process.exit(1);
});
