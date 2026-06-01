# Watcher MK-1 — Deployment Guide

Autonomous AI-powered AWS security agent. Monitors CloudTrail in real-time, reasons about threats using Claude Sonnet 4.6 on AWS Bedrock, and executes remediation actions with human approval.

---

## Architecture

```
Internet
    │
    ▼
┌─────────────────────┐
│   Nginx (80/443)    │  SSL termination · rate limiting · static files
│   /api/* → :4000   │
│   /* → ui/dist      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Node.js (:4000)   │  Express API · AI Pipeline · Polling Loop
│   PM2 managed       │
└──────────┬──────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
┌────────┐  ┌──────────────┐
│Postgres│  │ AWS Bedrock  │
│ :5432  │  │ Claude 4.6   │
└────────┘  └──────────────┘
                  │
                  ▼
         ┌────────────────┐
         │ Customer AWS   │  CloudTrail · IAM · EC2 · S3
         │ (cross-account)│
         └────────────────┘
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Ubuntu | 22.04+ | or Amazon Linux 2023 |
| Node.js | 20+ | `node --version` |
| npm | 10+ | comes with Node.js |
| PostgreSQL | 15+ | `psql --version` |
| Nginx | 1.18+ | `nginx -v` |
| PM2 | latest | `npm install -g pm2` |

---

## Step 1 — Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Install Nginx
sudo apt install -y nginx

# Install PM2 globally
sudo npm install -g pm2

# Verify
node --version    # v20.x.x
psql --version    # psql (PostgreSQL) 15.x
nginx -v          # nginx/1.x.x
pm2 --version     # 5.x.x
```

---

## Step 2 — Clone and Build

```bash
# Clone the repository
git clone https://github.com/your-org/watcher-mk1.git /opt/watcher-mk1
cd /opt/watcher-mk1

# Install backend dependencies
npm install

# Build TypeScript → dist/
npm run build

# Install and build frontend
cd ui
npm install
npm run build
cd ..

# Verify build output exists
ls dist/server/index.js    # must exist
ls ui/dist/index.html      # must exist
```

---

## Step 3 — PostgreSQL Setup

```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database user and database
sudo -u postgres psql <<EOF
CREATE USER watcher WITH PASSWORD 'your-secure-password-here';
CREATE DATABASE watcher_mk1 OWNER watcher;
GRANT ALL PRIVILEGES ON DATABASE watcher_mk1 TO watcher;
EOF

# Run the schema (creates all tables)
psql -U watcher -h localhost -d watcher_mk1 -f src/database/schema.sql

# Verify tables were created
psql -U watcher -h localhost -d watcher_mk1 -c "\dt"
# Should show: incidents, actions, connectors, timeline_events, trust_levels, audit_log, users, tenants
```

---

## Step 4 — Environment Configuration

```bash
# Copy the example file
cp .env.example .env

# Edit with your values
nano .env
```

**Required values to fill in:**

```bash
# ── AWS Bedrock (AI Reasoning Engine) ──────────────────────────────────────
# The Watcher server account — where Bedrock runs
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
# Tip: On EC2, use an instance role instead of access keys (remove the key lines)

# ── Database ────────────────────────────────────────────────────────────────
DB_ENABLED=true
DB_HOST=localhost
DB_PORT=5432
DB_NAME=watcher_mk1
DB_USER=watcher
DB_PASSWORD=your-secure-password-here
DB_SSL=false          # Set true for RDS or managed PostgreSQL
DB_POOL_MAX=20

# ── Server ──────────────────────────────────────────────────────────────────
PORT=4000
CORS_ORIGIN=https://watcher.hextechsolutions.in    # Your actual domain
NODE_ENV=production

# ── Authentication ──────────────────────────────────────────────────────────
AUTH_ENABLED=true
JWT_SECRET=<generate a 64-character random string — see below>
JWT_EXPIRES_IN=24h
DEFAULT_TENANT_ID=tenant-001

# ── Notifications (Discord) ─────────────────────────────────────────────────
# Discord: Server Settings → Integrations → Webhooks → New Webhook → Copy URL
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DASHBOARD_URL=https://watcher.hextechsolutions.in

# ── Polling ─────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS=60
# POLL_LOOKBACK_MINUTES=120   # Uncomment to limit catch-up window (default: 90 days)
```

**Generate a secure JWT secret:**
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## Step 5 — Log Directory

```bash
sudo mkdir -p /var/log/watcher-mk1
sudo chown $USER:$USER /var/log/watcher-mk1
```

---

## Step 6 — PM2 Process Manager

```bash
# Start the application
pm2 start ecosystem.config.cjs

# Verify it's running
pm2 status
# Should show: watcher-mk1 | online

# Check logs
pm2 logs watcher-mk1 --lines 50

# Save PM2 config so it survives reboots
pm2 save

# Set PM2 to start on system boot
pm2 startup
# Run the command it outputs (starts with: sudo env PATH=...)
```

**Verify the API is responding:**
```bash
curl http://localhost:4000/api/v1/health
# Expected: {"status":"ok","version":"1.0.0",...}
```

---

## Step 7 — Nginx Configuration

```bash
# Copy the config (domain is already set to watcher.hextechsolutions.in)
sudo cp deploy/nginx.conf /etc/nginx/sites-available/watcher-mk1

# Enable the site
sudo ln -s /etc/nginx/sites-available/watcher-mk1 /etc/nginx/sites-enabled/

# Remove default site if present
sudo rm -f /etc/nginx/sites-enabled/default

# Test config
sudo nginx -t
# Expected: syntax is ok / test is successful

# Reload Nginx
sudo systemctl reload nginx
sudo systemctl enable nginx
```

---

## Step 8 — SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get certificate (replace with your domain)
sudo certbot --nginx -d watcher.hextechsolutions.in

# Certbot auto-renews via a systemd timer — verify:
sudo systemctl status certbot.timer

# Test renewal
sudo certbot renew --dry-run
```

---

## Step 9 — First-Time Application Setup

**1. Register the first admin user:**
```bash
curl -X POST https://watcher.hextechsolutions.in/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourcompany.com",
    "password": "your-secure-password",
    "name": "Admin",
    "tenant_name": "Your Company"
  }'
```

**2. Deploy the CloudFormation template in the customer AWS account:**
- Download from: `https://watcher.hextechsolutions.in/api/v1/downloads/cloudformation`
- Deploy in the customer account via AWS Console → CloudFormation → Create Stack
- Note the `RoleArn` from the stack Outputs tab

**3. Connect the customer account via the UI:**
- Open `https://watcher.hextechsolutions.in`
- Navigate to **Connectors** → **Connect Account**
- Paste the Role ARN from step 2
- Enter the customer AWS Account ID
- Select region(s) to monitor
- Click **Connect Account**

**4. Watcher starts monitoring immediately:**
- First poll: catches up on all write events from the last 90 days
- Subsequent polls: every 60 seconds, incremental from last seen event
- Incidents appear in the Dashboard as threats are detected
- Discord alerts fire when approvals are needed

---

## Step 10 — Add Known IPs (Reduce False Positives)

Before going live, add your admin IPs so the AI doesn't flag legitimate activity:

- Navigate to **Suppressions** → **Known IPs** → **Add IP**
- Add your office IP, VPN IP, and any admin workstation IPs
- Label them clearly (e.g. "Office Network", "Admin VPN")

---

## Verification Checklist

```bash
# API health
curl https://watcher.hextechsolutions.in/api/v1/health

# Database connected
curl https://watcher.hextechsolutions.in/api/v1/health | grep db_enabled
# Should show: "db_enabled":true

# Auth working
curl -X POST https://watcher.hextechsolutions.in/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"your-password"}'
# Should return a JWT token

# Frontend loading
curl -I https://watcher.hextechsolutions.in
# Should return: HTTP/2 200
```

---

## Useful Commands

```bash
# ── Application ──────────────────────────────────────────────────────────────
pm2 status                        # Check process status
pm2 logs watcher-mk1              # Live logs
pm2 logs watcher-mk1 --lines 100  # Last 100 lines
pm2 restart watcher-mk1           # Restart (picks up .env changes)
pm2 stop watcher-mk1              # Stop
pm2 reload watcher-mk1            # Zero-downtime reload

# ── Database ─────────────────────────────────────────────────────────────────
psql -U watcher -h localhost -d watcher_mk1          # Connect
psql -U watcher -h localhost -d watcher_mk1 -c "SELECT COUNT(*) FROM incidents;"
psql -U watcher -h localhost -d watcher_mk1 -f src/database/schema.sql  # Re-run schema (safe)

# ── Nginx ────────────────────────────────────────────────────────────────────
sudo nginx -t                     # Test config
sudo systemctl reload nginx       # Apply changes
sudo tail -f /var/log/nginx/error.log

# ── SSL ──────────────────────────────────────────────────────────────────────
sudo certbot renew                # Manual renewal
sudo certbot certificates         # List certificates

# ── Logs ─────────────────────────────────────────────────────────────────────
tail -f /var/log/watcher-mk1/out.log    # Application output
tail -f /var/log/watcher-mk1/error.log  # Application errors
```

---

## Updating the Application

```bash
cd /opt/watcher-mk1

# Pull latest code
git pull origin main

# Install any new dependencies
npm install
cd ui && npm install && cd ..

# Rebuild
npm run build
cd ui && npm run build && cd ..

# Restart
pm2 restart watcher-mk1

# Verify
pm2 logs watcher-mk1 --lines 20
curl https://watcher.hextechsolutions.in/api/v1/health
```

---

## Troubleshooting

**PM2 shows errored status:**
```bash
pm2 logs watcher-mk1 --lines 50
# Look for the error message, most common causes:
# - Missing .env values
# - Database connection failed (check DB_HOST, DB_PASSWORD)
# - Port 4000 already in use: sudo lsof -i :4000
```

**Database connection failed:**
```bash
# Test connection manually
psql -U watcher -h localhost -d watcher_mk1 -c "SELECT 1;"
# If fails: check PostgreSQL is running
sudo systemctl status postgresql
```

**Nginx 502 Bad Gateway:**
```bash
# Check if Node.js is running
pm2 status
curl http://localhost:4000/api/v1/health
# If Node.js is down: pm2 restart watcher-mk1
```

**No events being detected:**
```bash
# Check the debug endpoint
curl https://watcher.hextechsolutions.in/api/v1/pipeline/debug
# Look for events with suppressed: false
# If empty: CloudTrail may not have delivered events yet (5-15 min delay)
```

**Discord notifications not arriving:**
```bash
# Test the webhook manually
curl -X POST "$DISCORD_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"content":"Watcher MK-1 test notification"}'
# Should return HTTP 204
```

---

## Security Hardening (Production)

```bash
# Firewall — only allow 80, 443, and SSH
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Block direct access to Node.js port from outside
sudo ufw deny 4000/tcp

# PostgreSQL — only allow local connections (default, verify)
sudo grep "listen_addresses" /etc/postgresql/*/main/postgresql.conf
# Should show: listen_addresses = 'localhost'

# Set strong file permissions on .env
chmod 600 /opt/watcher-mk1/.env
chown $USER:$USER /opt/watcher-mk1/.env
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_REGION` | ✅ | — | AWS region for Bedrock (e.g. `us-east-1`) |
| `AWS_ACCESS_KEY_ID` | ✅* | — | Watcher account access key (*or use EC2 instance role) |
| `AWS_SECRET_ACCESS_KEY` | ✅* | — | Watcher account secret key |
| `DB_ENABLED` | ✅ | `false` | Set `true` for production |
| `DB_HOST` | ✅ | `localhost` | PostgreSQL host |
| `DB_PORT` | — | `5432` | PostgreSQL port |
| `DB_NAME` | ✅ | `watcher_mk1` | Database name |
| `DB_USER` | ✅ | `watcher` | Database user |
| `DB_PASSWORD` | ✅ | — | Database password |
| `DB_SSL` | — | `false` | Set `true` for RDS/cloud DB |
| `PORT` | — | `4000` | API server port |
| `CORS_ORIGIN` | ✅ | — | Frontend URL (`https://watcher.hextechsolutions.in`) |
| `NODE_ENV` | — | `development` | Set `production` for deployment |
| `AUTH_ENABLED` | ✅ | `false` | Set `true` for production |
| `JWT_SECRET` | ✅ | — | 64-char random string for JWT signing |
| `JWT_EXPIRES_IN` | — | `24h` | JWT token expiry |
| `DEFAULT_TENANT_ID` | — | `tenant-001` | Default tenant identifier |
| `DISCORD_WEBHOOK_URL` | — | — | Discord webhook for approval alerts |
| `DASHBOARD_URL` | — | `http://localhost:5173` | Dashboard URL for Discord links |
| `POLL_INTERVAL_SECONDS` | — | `60` | CloudTrail poll interval |
| `POLL_LOOKBACK_MINUTES` | — | `129600` (90 days) | Catch-up window on first connect |
