import express from 'express';
import cors from 'cors';
import incidentsRouter from './routes/incidents.js';
import approvalsRouter from './routes/approvals.js';
import actionsRouter from './routes/actions.js';
import metricsRouter from './routes/metrics.js';
import webhooksRouter from './routes/webhooks.js';
import pipelineRouter from './routes/pipeline.js';
import connectorsRouter from './routes/connectors.js';
import { pipeline } from './pipeline-instance.js';
import { startPollingLoop } from '../pipeline/polling-loop.js';

const app = express();
const PORT = 4000;

app.use(cors({ origin: 'http://localhost:5173' }));
app.use(express.json());

// Routes
app.use('/api/v1/incidents', incidentsRouter);
app.use('/api/v1/approvals', approvalsRouter);
app.use('/api/v1/actions', actionsRouter);
app.use('/api/v1/metrics', metricsRouter);
app.use('/api/v1/webhooks', webhooksRouter);
app.use('/api/v1/pipeline', pipelineRouter);
app.use('/api/v1/connectors', connectorsRouter);

// Health check
app.get('/api/v1/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    ai_model: 'us.anthropic.claude-sonnet-4-6',
    bedrock_region: process.env['AWS_REGION'] ?? 'not configured',
    timestamp: new Date().toISOString(),
  });
});

app.listen(PORT, () => {
  console.log(`[Watcher MK-1] API server running on http://localhost:${PORT}`);
  console.log(`[Watcher MK-1] AI Model: us.anthropic.claude-sonnet-4-6`);
  console.log(`[Watcher MK-1] Bedrock Region: ${process.env['AWS_REGION'] ?? 'not configured — set AWS_REGION'}`);
  console.log(`[Watcher MK-1] CORS enabled for http://localhost:5173`);

  // Start the polling loop — polls all registered connectors every 60 seconds
  startPollingLoop(pipeline, 60_000);
  console.log(`[Watcher MK-1] Polling loop started (60s interval)`);
  console.log(`[Watcher MK-1] Register a connector: POST /api/v1/connectors`);
});
