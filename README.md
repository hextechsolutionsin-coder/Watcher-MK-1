# Watcher MK-1

AI-powered autonomous cybersecurity agent that monitors AWS CloudTrail events, detects threats using Claude Sonnet 4 via AWS Bedrock, and takes automated remediation actions with human-in-the-loop approval.

## Features

- **Real-time AWS CloudTrail monitoring** — Polls for security events across multiple accounts and regions
- **AI-powered threat detection** — Uses Claude Sonnet 4 (via AWS Bedrock) for reasoning about security incidents
- **Automated remediation** — Executes security actions (revoke keys, block IPs, isolate instances) with approval workflows
- **Semantic memory** — Learns from past incidents using Supermemory for pattern recognition
- **Multi-tenant** — Supports multiple AWS accounts with tenant isolation
- **SOC Dashboard** — Real-time web UI for incident management, approvals, and monitoring

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Watcher MK-1                          │
├───────────┬───────────┬──────────────┬─────────────────┤
│ CloudTrail│ AI Engine │ Action       │ SOC Dashboard   │
│ Poller    │ (Bedrock) │ Executor     │ (React + Vite)  │
├───────────┴───────────┴──────────────┴─────────────────┤
│ PostgreSQL │ Supermemory (Semantic Memory) │ Ollama     │
└────────────┴──────────────────────────────┴────────────┘
```

## Prerequisites

- Ubuntu 22.04+ or Debian 12+ (tested on Ubuntu 24.04)
- A user with sudo access
- Minimum 8 GB RAM (`t3.large` or equivalent)
- 30 GB disk space
- AWS account with CloudTrail enabled
- AWS Bedrock access to Claude Sonnet 4 in us-east-1

## Quick Start (Production)

The installer automates everything. On a fresh server:

```bash
git clone https://github.com/hextechsolutionsin-coder/Watcher-MK-1.git
cd Watcher-MK-1
git checkout feature/linux-production-installer
chmod +x install.sh
./install.sh
```

The installer will:
1. Install Node.js 20, PostgreSQL 16, Ollama, Supermemory, and PM2
2. Create the database and apply the schema
3. Generate a production `.env` file
4. Build the backend and frontend
5. Start all services via PM2
6. Verify the health check passes

### After Installation

1. **Open port 4000** in your cloud firewall/security group
2. **Access the dashboard** at `http://<your-public-ip>:4000`
3. **Configure AWS credentials** in `.env`:
   ```
   AWS_ACCESS_KEY_ID=your-key
   AWS_SECRET_ACCESS_KEY=your-secret
   AWS_REGION=us-east-1
   ```
4. **Restart the app**: `pm2 restart watcher-mk1`
5. **Connect an AWS account** via the Connectors page in the UI

### Supermemory Setup

On first run, Supermemory requires interactive configuration. The installer will prompt you. Choose:
- **Provider**: OpenAI (or OpenAI-compatible)
- **API Key**: `sk-ollama` (placeholder, Ollama doesn't validate keys)
- **Base URL**: `http://localhost:11434/v1`
- **Model**: `nomic-embed-text`

If Supermemory fails to start, you can re-run the setup manually:
```bash
pm2 stop supermemory
PORT=6767 npx supermemory@latest local
# Complete the interactive setup, then Ctrl+C
pm2 restart supermemory
```

## Configuration

All configuration is in the `.env` file. Key settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | API server port | `4000` |
| `NODE_ENV` | Environment | `production` |
| `DB_ENABLED` | Use PostgreSQL | `true` |
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `DB_NAME` | Database name | `watcher_mk1` |
| `DB_USER` | Database user | Set during install |
| `DB_PASSWORD` | Database password | Set during install |
| `AUTH_ENABLED` | Require JWT auth | `false` |
| `CORS_ORIGIN` | Allowed origins | `*` |
| `AWS_REGION` | Bedrock region | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS key | Required for monitoring |
| `AWS_SECRET_ACCESS_KEY` | AWS secret | Required for monitoring |
| `SUPERMEMORY_BASE_URL` | Supermemory endpoint | `http://localhost:6767` |
| `SUPERMEMORY_LLM_PROVIDER` | Embedding provider | `ollama` |
| `POLL_INTERVAL_SECONDS` | CloudTrail poll interval | `60` |

## Enabling Authentication

Auth is disabled by default (no login UI is wired up yet). To enable:

```bash
# Enable auth
sed -i 's|AUTH_ENABLED=false|AUTH_ENABLED=true|' .env
pm2 restart watcher-mk1

# Register an admin user
curl -X POST http://localhost:4000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your-secure-password"}'
```

The register endpoint returns a JWT token. Use it in the `Authorization: Bearer <token>` header for API calls.

## Service Management

All services are managed by PM2:

```bash
# Check status
pm2 status

# View logs
pm2 logs watcher-mk1 --lines 50
pm2 logs supermemory --lines 50

# Restart services
pm2 restart watcher-mk1
pm2 restart supermemory

# Stop everything
pm2 stop all

# Start everything
pm2 start all
```

Ollama runs via systemd:
```bash
sudo systemctl status ollama
sudo systemctl restart ollama
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check (public) |
| POST | `/api/v1/auth/register` | Register user |
| POST | `/api/v1/auth/login` | Login |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/:id` | Get incident details |
| GET | `/api/v1/approvals` | List pending approvals |
| POST | `/api/v1/approvals/:id/approve` | Approve action |
| POST | `/api/v1/approvals/:id/reject` | Reject action |
| GET | `/api/v1/connectors` | List AWS connectors |
| POST | `/api/v1/connectors` | Register connector |
| GET | `/api/v1/events` | List polled events |
| GET | `/api/v1/metrics/risk-score` | Current risk score |
| GET | `/api/v1/pipeline/status` | Pipeline status |

## Troubleshooting

### "Cannot GET /" in browser
The frontend is served from the API. Make sure you rebuilt after pulling the latest code:
```bash
npm run build
pm2 restart watcher-mk1
```

### Supermemory crash loop (segfault)
This means your server doesn't have enough RAM. Supermemory needs ~1.5 GB.
```bash
free -h  # Check available RAM
```
**Fix**: Upgrade to at least 8 GB RAM (e.g., `t3.large` on AWS).

### Supermemory "No model provider API key configured"
Run interactive setup:
```bash
pm2 stop supermemory
PORT=6767 npx supermemory@latest local
# Follow prompts, then Ctrl+C after it starts
pm2 restart supermemory
```

### Supermemory tries to use port 4000
Supermemory reads the `PORT` variable from `.env`. The PM2 start command must explicitly set `PORT=6767`:
```bash
pm2 delete supermemory
PORT=6767 pm2 start npx --name supermemory --cwd /home/ubuntu/Watcher-MK-1 -- supermemory@latest local
pm2 save
```

### "MemoryLayer Failed to connect" in logs
This is non-critical. The app works in fallback mode without Supermemory. To fix:
```bash
# Verify Supermemory is running
curl http://localhost:6767

# If not responding, restart it
pm2 restart supermemory

# Then restart watcher to reconnect
pm2 restart watcher-mk1
```

### "Connection Error" in the dashboard UI
1. Check CORS: `grep CORS_ORIGIN .env` — should be `*`
2. Check auth: `grep AUTH_ENABLED .env` — should be `false` unless you have a login UI
3. Restart: `pm2 restart watcher-mk1`

### PM2 processes not starting after reboot
```bash
pm2 startup systemd
pm2 save
```

### Express "Missing parameter name at index 1" crash
This means the code has `app.get('*', ...)` which is invalid in Express 5. Pull the latest code:
```bash
git pull
npm run build
pm2 restart watcher-mk1
```

### Database connection failed
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Verify credentials
sudo -u postgres psql -c "\l" | grep watcher_mk1

# Test connection manually
PGPASSWORD=your-password psql -U your-user -h localhost -d watcher_mk1 -c "SELECT 1;"
```

### Port 4000 not accessible from browser
1. Check the app is running: `curl http://localhost:4000/api/v1/health`
2. Open port 4000 in your AWS Security Group (EC2 → Security Groups → Inbound Rules)
3. Check if firewall is blocking: `sudo ufw status`

## Development

```bash
# Install dependencies
npm install
cd ui && npm install && cd ..

# Run in dev mode
npm run dev      # Backend (watches TypeScript)
cd ui && npm run dev  # Frontend (Vite dev server on :5173)

# Build
npm run build
cd ui && npm run build

# Run tests
npm test
```

## Project Structure

```
├── install.sh              # Production installer script
├── ecosystem.config.cjs    # PM2 process configuration
├── src/
│   ├── server/             # Express API server + routes
│   ├── ai/                 # AI reasoning engine (Bedrock)
│   ├── pipeline/           # Event processing pipeline
│   ├── memory/             # Supermemory integration layer
│   ├── connectors/         # AWS connector management
│   ├── execution/          # Action executor + rollback
│   ├── safety/             # Safety gates + trust levels
│   ├── ingestion/          # Telemetry normalization
│   └── database/           # PostgreSQL schema + repos
├── ui/                     # React frontend (Vite + Tailwind)
├── deploy/                 # Nginx config + deployment docs
└── cloudformation/         # AWS IAM role template
```

## License

Private — All rights reserved.
