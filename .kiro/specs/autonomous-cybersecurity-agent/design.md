# Design Document: Autonomous Cybersecurity Reasoning Agent

## Overview

Watcher MK1 is a cloud-native, multi-tenant SaaS platform built around a central AI Reasoning Engine that autonomously monitors enterprise environments, understands threats through contextual reasoning, generates dynamic response plans, and executes remediation actions — all without pre-written detection rules or playbooks.

Unlike traditional security platforms that rely on human-authored rules, coded detection modules, and scripted playbooks, Watcher MK1 uses a domain-specialized AI agent that reasons about raw telemetry in real-time. The AI discovers what tools a customer has, understands their APIs, reasons about threats in the context of the customer's specific environment, and generates + executes response actions dynamically.

### Core Philosophy

**No rules. No playbooks. The AI reasons every time.**

- Detection is not pattern matching — it's contextual understanding
- Response is not playbook execution — it's dynamic action planning
- Correlation is not indicator matching — it's causal reasoning
- Learning is not model retraining — it's accumulated reasoning experience

### Problem Statement

1. **Knowledge Gap**: Security expertise is scarce, inconsistent, and doesn't scale. The best analysts can't be everywhere. Tribal knowledge lives in people's heads, not systems.
2. **Response Time**: The human loop (detect → investigate → decide → act) takes hours to days. Attackers operate in minutes.

### Key Design Goals

- **AI-first architecture**: Every detection, correlation, and response decision is made by the AI Reasoning Engine — no coded detection logic or pre-written rules
- **Zero pre-written rules**: The AI reasons about threats from first principles using its training, environment context, and threat intelligence
- **Zero playbooks**: The AI generates response plans per-incident based on the specific threat and available tools
- **Dynamic tool usage**: The AI discovers connected tool capabilities and generates correct API calls without pre-mapped adapters
- **Tiered autonomy with earned trust**: Autonomous for low-risk actions; human-in-loop for high-risk; trust level increases over time as AI proves reliability
- **Full explainability**: Every AI decision includes natural language reasoning explaining what it detected, why it matters, and what it's doing about it
- **Continuous learning**: Per-tenant reasoning memory that improves with every incident and analyst feedback
- **Tenant isolation by default**: Every data path enforces tenant boundaries
- **Compliance-ready**: Immutable audit trail of all AI decisions and actions

### Research Findings

1. **LLM Agent Architectures for Security**: Modern LLM agent frameworks (ReAct, tool-calling, chain-of-thought) enable AI systems to reason about complex multi-step problems, use tools dynamically, and explain their reasoning. The platform uses an agent architecture where the AI can observe, reason, plan, and act in a continuous loop.

2. **Retrieval-Augmented Generation (RAG)**: RAG enables the AI to reason with up-to-date knowledge (MITRE ATT&CK, CVE databases, threat intel feeds) without retraining. The AI retrieves relevant context at reasoning time, ensuring decisions reflect current threat landscape.

3. **MITRE ATT&CK as reasoning context**: The ATT&CK framework provides structured knowledge about adversary tactics and techniques that the AI uses as reasoning context — not as a rule database, but as domain knowledge that informs its understanding of attack patterns.

4. **Multi-tenant isolation patterns**: Hybrid isolation model — shared AI infrastructure with per-tenant data isolation (schema-per-tenant in relational stores, tenant-keyed partitions in event stores). Tenant context propagated via signed JWT claims.

5. **Event-driven pipeline for low-latency processing**: Event streaming backbone (Kafka or EventBridge) enables sub-10-second event-to-AI-reasoning latency. A fast filter model handles initial triage to manage cost and latency.

6. **LLM cost management through tiered inference**: A multi-tier model approach manages cost at scale: small/fast model for initial event filtering (99% of events), medium model for triage, large model for complex reasoning on confirmed threats.

7. **Tool-calling and API generation**: LLMs can read API documentation and generate correct API calls. Combined with authenticated connections to customer tools, this enables dynamic action execution without pre-coded adapters.

8. **Safety and guardrails for autonomous AI**: Blast radius scoring, confidence thresholds, reversibility requirements, and earned trust models provide safety without eliminating autonomy.

---

## Architecture

### High-Level Architecture

The platform is organized into five logical layers:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           TENANT INTERFACE LAYER                              │
│   Web Console (React/TS SPA)  ←→  API Gateway  ←→  RBAC / AuthN / AuthZ     │
│   [AI Reasoning Explanations | Approval Queue | Audit Trail | Risk View]     │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                           INGESTION LAYER                                     │
│   Connector Manager  →  Telemetry Normalizer  →  Event Bus                   │
│   Tool Discovery Engine (auto-discovers connected tool capabilities)          │
│   (Cloud APIs, EDR, NDR, XDR, SaaS, IAM, CI/CD, Webhooks, Threat Feeds)    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                        AI REASONING LAYER                                     │
│                                                                               │
│   ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────┐        │
│   │ Fast Filter │ →  │ Context Assembly  │ →  │ AI Reasoning Engine │        │
│   │ (small LLM) │    │ (environment +   │    │ (domain-specialized │        │
│   │ 99% triage  │    │  history + intel) │    │  LLM + RAG + tools)│        │
│   └─────────────┘    └──────────────────┘    └──────────┬──────────┘        │
│                                                          │                    │
│   Capabilities (all via AI reasoning, no coded logic):   │                    │
│   • Threat detection & understanding                     │                    │
│   • Attack path prediction & validation                  │                    │
│   • Kill chain reconstruction                            │                    │
│   • Behavioral analytics                                 │                    │
│   • Threat hunting (proactive reasoning)                 │                    │
│   • Forecasting (trends, configs, vulns)                 │                    │
│   • Dynamic response planning                            │                    │
│   • Severity & confidence assessment                     │                    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                           SAFETY & EXECUTION LAYER                            │
│                                                                               │
│   ┌──────────────┐    ┌───────────────────┐    ┌──────────────────────┐     │
│   │ Safety Gate  │ →  │ Approval Workflow  │ →  │ Action Executor      │     │
│   │ (blast radius│    │ (tiered autonomy,  │    │ (executes AI-planned │     │
│   │  confidence, │    │  earned trust,     │    │  API calls against   │     │
│   │  reversibility)│  │  human-in-loop)    │    │  connected tools)    │     │
│   └──────────────┘    └───────────────────┘    └──────────┬───────────┘     │
│                                                            │                  │
│   ┌──────────────────┐    ┌────────────────────────────┐  │                  │
│   │ Rollback Registry│    │ Audit Logger (immutable)    │←─┘                  │
│   │ (undo any action)│    │ (every AI decision logged)  │                     │
│   └──────────────────┘    └────────────────────────────┘                     │
└──────────────────────────────────────────────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼───────────────────────────────────────┐
│                        KNOWLEDGE & MEMORY LAYER                               │
│                                                                               │
│   ┌──────────────────┐    ┌─────────────────┐    ┌────────────────────┐     │
│   │ Environment Model│    │ Reasoning Memory │    │ Threat Intelligence│     │
│   │ (live infra graph│    │ (per-tenant      │    │ (ATT&CK, CVEs,    │     │
│   │  assets, perms,  │    │  incident history│    │  IOCs, OSINT,     │     │
│   │  topology)       │    │  feedback, what  │    │  dark web feeds)  │     │
│   │                  │    │  worked before)  │    │                    │     │
│   └──────────────────┘    └─────────────────┘    └────────────────────┘     │
│                                                                               │
│   ┌──────────────────────────────────────────────────────────────────┐       │
│   │ Cross-Tenant Intelligence (anonymized, opt-in network effects)    │       │
│   └──────────────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Deployment Architecture

The platform is deployed on AWS with the following topology:

- **API Gateway**: AWS API Gateway — handles AuthN, rate limiting, tenant routing.
- **AI Inference**: Dedicated GPU instances (or managed LLM API) for reasoning engine; CPU instances for fast filter model.
- **Event Bus**: Amazon EventBridge or Kafka for telemetry streaming and inter-service messaging.
- **Data stores**:
  - **PostgreSQL (schema-per-tenant)**: Incident records, configurations, RBAC, reasoning memory.
  - **Vector Store (Pinecone/pgvector)**: RAG embeddings for threat intelligence, ATT&CK knowledge, environment context.
  - **Redis**: Session state, rate limiting, real-time event buffering.
  - **Elasticsearch**: Audit log (write-once), telemetry search.
  - **S3**: Compliance reports, audit exports, model artifacts, reasoning traces.
  - **Neo4j or Neptune**: Environment model graph (assets, permissions, network topology).
- **Horizontal scaling**: Ingestion workers scale on event bus lag; AI reasoning scales on queue depth.

### Scalability Design

- Fast filter model handles 99% of events at low cost — only suspicious events reach the full reasoning engine.
- AI Reasoning Engine scales horizontally — each reasoning request is stateless (context assembled per-request from stores).
- Environment Model is pre-computed and cached — AI reads it, doesn't compute it at reasoning time.
- Tiered model approach manages cost: ~$0.001/event for filtering, ~$0.05/event for full reasoning (only 1% of events).
- Target: 10,000 tenants × 1,000 events/min = 10M events/min through fast filter, ~100K events/min through full reasoning.

---

## Components and Interfaces

### 1. Connector Manager

Responsible for lifecycle management of all tool integrations. Connectors are **dumb pipes** — they authenticate and maintain connections. They don't contain detection or response logic.

**Responsibilities:**
- Register, authenticate, and health-check tool connections.
- Begin telemetry ingestion within 5 minutes of successful authentication.
- Detect credential expiry and alert Tenant Administrator within 5 minutes.
- Detect telemetry gaps ≥ 60 seconds and raise alerts.
- Provide authenticated API access for the Action Executor to use when executing AI-planned responses.

**Key Interfaces:**
```
POST   /api/v1/connectors                  — Register a new tool connection
DELETE /api/v1/connectors/{id}             — Remove a connection
GET    /api/v1/connectors/{id}/status      — Health and last-ingestion status
POST   /api/v1/connectors/{id}/test        — Send test event and verify receipt
POST   /api/v1/webhooks/{tenant_id}/ingest — Webhook ingestion endpoint
```

**Supported Tool Categories:**
| Category | Examples |
|---|---|
| Cloud | AWS (CloudTrail, GuardDuty, Security Hub, Config, IAM), Azure, GCP |
| EDR | CrowdStrike Falcon, SentinelOne, Microsoft Defender |
| XDR | Palo Alto Cortex XDR, Trend Micro Vision One |
| NDR | Darktrace, ExtraHop |
| Identity | Okta, Azure AD, Google Workspace |
| SaaS | Microsoft 365, Salesforce, GitHub |
| SIEM | Splunk, Microsoft Sentinel |
| Notification | Slack, PagerDuty, Email (SMTP) |
| Ticketing | Jira, ServiceNow |

### 2. Telemetry Normalizer

Converts raw events from heterogeneous sources into a canonical schema before publishing to the event bus. This is pure data transformation — no intelligence.

**Pipeline:**
1. Parse raw payload (JSON, CEF, LEEF, syslog, cloud-native formats).
2. Map to canonical `TelemetryEvent` schema fields.
3. Stamp with `tenant_id`, `connector_id`, `source_tool`, `ingestion_timestamp`.
4. Publish to event bus for AI processing.

### 3. Tool Discovery Engine

Automatically discovers what capabilities each connected tool provides. This information is fed to the AI Reasoning Engine so it knows what actions are available per customer.

**How it works:**
- When a connector is registered, the Tool Discovery Engine inspects:
  - What API permissions were granted
  - What actions the tool's API supports
  - What data the tool can provide
- Produces a **Tool Capability Profile** per connector:
  ```
  {
    "connector_id": "conn_aws_123",
    "tool_type": "aws",
    "capabilities": {
      "can_read": ["cloudtrail_events", "iam_policies", "security_groups", "s3_bucket_policies"],
      "can_write": ["iam_access_keys", "security_groups", "ec2_instances", "s3_bucket_acls"],
      "api_base": "https://iam.amazonaws.com",
      "auth_method": "assume_role",
      "permissions_granted": ["iam:UpdateAccessKey", "ec2:StopInstances", ...]
    }
  }
  ```
- The AI Reasoning Engine reads these profiles to understand what actions are possible for each customer.
- No pre-defined "intent" vocabulary — the AI reasons about what's possible from the raw capability data.

### 4. Environment Model

A continuously-updated live representation of the customer's infrastructure. This is the AI's **situational awareness** — it needs to understand the environment to reason about threats in context.

**What it contains:**
- **Assets**: All known resources (EC2 instances, S3 buckets, IAM roles, users, databases, endpoints, etc.)
- **Relationships**: Network connectivity, permission grants, trust relationships, data flows
- **Criticality**: Business importance of each asset (production vs. dev, customer-facing vs. internal)
- **Baselines**: Normal behavior patterns per asset and per user (built over 30+ days)
- **Configuration state**: Current security posture (encryption, access controls, exposure)
- **Vulnerabilities**: Known CVEs affecting assets, misconfigurations

**Implementation:**
- Graph database (Neo4j or Neptune) for assets and relationships
- Time-series store for behavioral baselines
- Updated continuously from connector telemetry
- Full refresh every 24 hours; incremental updates within minutes of changes
- Fed to AI Reasoning Engine as context for every reasoning request

**Key difference from current spec:** This is not just for "attack path analysis" — it's the foundation for ALL AI reasoning. The AI can't assess severity, plan responses, or predict attacks without understanding the environment.

### 5. Fast Filter Model

A lightweight, low-cost AI model that performs initial triage on ALL incoming events. Its job is to answer one question: "Is this event worth the AI Reasoning Engine's attention?"

**Purpose:** Cost and latency management. Running the full reasoning engine on every event (10M/min) would be prohibitively expensive. The fast filter reduces this to ~1% that need deep reasoning.

**Implementation:**
- Small, fine-tuned model (e.g., distilled classifier or small LLM)
- Trained on: historical incidents (what turned out to be real), known-benign patterns, event severity signals
- Input: normalized telemetry event + minimal context (asset criticality, source tool)
- Output: `{ interesting: boolean, urgency: "immediate" | "queue" | "drop", reason: string }`
- Latency target: < 100ms per event
- Cost target: < $0.001 per event

**Routing logic:**
- `interesting: false` → Drop (log for audit, don't process further)
- `interesting: true, urgency: "immediate"` → Send to AI Reasoning Engine immediately
- `interesting: true, urgency: "queue"` → Batch for next reasoning cycle (within 60 seconds)

### 6. AI Reasoning Engine (Core)

The brain of the platform. A domain-specialized AI agent that receives security events with full context and reasons about them — detecting threats, understanding attack patterns, and generating response plans.

**This replaces:** Signal Correlator, Threat Classifier, Incident Engine detection logic, False Positive Elimination Engine, Attack Detection modules, Threat Hunting queries, and Playbook-based response planning from the previous design.

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                    AI REASONING ENGINE                        │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Foundation Model (GPT-4 / Claude / fine-tuned open)    │ │
│  │ + Security domain fine-tuning                          │ │
│  │ + Agent framework (tool-calling, multi-step reasoning) │ │
│  └────────────────────────────────────────────────────────┘ │
│                          │                                    │
│  ┌───────────────────────▼────────────────────────────────┐ │
│  │ RAG Layer (retrieval-augmented generation)              │ │
│  │ • MITRE ATT&CK knowledge base                          │ │
│  │ • CVE database (NVD + vendor advisories)               │ │
│  │ • Customer environment model (live)                    │ │
│  │ • Tenant reasoning memory (past incidents + feedback)  │ │
│  │ • Threat intelligence feeds (IOCs, TTPs, OSINT)        │ │
│  │ • Tool capability profiles (what can I do here?)       │ │
│  └────────────────────────────────────────────────────────┘ │
│                          │                                    │
│  ┌───────────────────────▼────────────────────────────────┐ │
│  │ Reasoning Modes                                         │ │
│  │ • REACTIVE: Analyze incoming threat event               │ │
│  │ • PROACTIVE: Hunt for hidden threats (scheduled)        │ │
│  │ • PREDICTIVE: Forecast future attack paths              │ │
│  │ • INVESTIGATIVE: Deep-dive on analyst request           │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Input (per reasoning request):**
```json
{
  "event": { /* normalized telemetry event or batch */ },
  "environment_context": { /* relevant slice of environment model */ },
  "recent_events": [ /* last N events for this asset/user */ ],
  "reasoning_memory": { /* past incidents, what worked, false positives */ },
  "threat_intel": { /* relevant IOCs, TTPs, CVEs */ },
  "tool_capabilities": { /* what tools are available, what can they do */ },
  "tenant_config": { /* trust level, sensitivity settings, notification prefs */ }
}
```

**Output (per reasoning request):**
```json
{
  "assessment": {
    "is_threat": true,
    "threat_description": "Compromised IAM access key used from anomalous location...",
    "severity": "HIGH",
    "confidence": 87,
    "mitre_techniques": ["T1078.004"],
    "kill_chain_stage": "credential_access",
    "related_incidents": ["inc_abc123"],
    "reasoning_trace": "Step 1: Observed API call from IP 198.51.100.23..."
  },
  "action_plan": [
    {
      "action": "Revoke compromised IAM access key",
      "tool": "aws-iam",
      "api_call": { "service": "iam", "action": "UpdateAccessKey", "params": {...} },
      "rollback": { "action": "UpdateAccessKey", "params": { "Status": "Active" } },
      "blast_radius": "low",
      "urgency": "immediate",
      "reasoning": "Key is actively being used by attacker. Revoking stops further access."
    },
    {
      "action": "Investigate affected resources",
      "tool": "aws-cloudtrail",
      "api_call": { "service": "cloudtrail", "action": "LookupEvents", "params": {...} },
      "blast_radius": "none",
      "urgency": "immediate",
      "reasoning": "Need to determine what the attacker accessed with this key."
    }
  ],
  "explanation": "A compromised IAM access key (AKIA3EXAMPLE) was used from an IP in Russia that has never been associated with this account. The key belongs to a service account with S3 and DynamoDB access. I'm revoking the key immediately and investigating what was accessed.",
  "predictions": {
    "next_likely_action": "Data exfiltration from S3 buckets accessible by this key",
    "probability": 72,
    "recommended_preemption": "Audit S3 access logs for this key in the last 24 hours"
  }
}
```

**Reasoning Modes:**

1. **REACTIVE** — Triggered by incoming events that pass the fast filter. AI analyzes the event in context, determines if it's a threat, and generates a response plan if needed.

2. **PROACTIVE** — Scheduled (at least daily per tenant). AI reviews the environment model, recent telemetry patterns, and threat intelligence to hunt for threats that weren't caught by reactive analysis. This replaces coded "threat hunting queries."

3. **PREDICTIVE** — Triggered by new threat intelligence or configuration changes. AI reasons about whether the customer's environment is vulnerable to emerging techniques. This replaces the coded "Forecast Engine."

4. **INVESTIGATIVE** — Triggered by analyst request. AI performs deep analysis on a specific asset, user, or incident. Analyst asks a question in natural language, AI reasons and responds.

**What the AI does NOT do:**
- It does not execute actions directly — it generates plans that the Safety Gate validates and the Action Executor runs.
- It does not have unrestricted API access — it can only use tools registered in the Tool Capability Profiles.
- It does not retain state between requests — all context is assembled per-request from stores (stateless reasoning).

### 7. Safety Gate

Validates every AI-generated action plan before execution. This is the critical guardrail that makes autonomous AI safe for production infrastructure.

**Validation checks (in order):**

1. **Tool permission check**: Is the proposed API call within the permissions granted by the connector? Reject if not.
2. **Blast radius scoring**: How much damage could this action cause if wrong?
   - `none`: Read-only actions (queries, lookups) → auto-approve
   - `low`: Single-resource write (revoke one key, block one IP) → auto-approve if trust level sufficient
   - `medium`: Multi-resource or service-affecting (stop instance, modify security group) → require higher confidence
   - `high`: Environment-wide or irreversible (delete data, modify IAM policies broadly) → require human approval regardless of trust level
3. **Confidence threshold**: Is the AI's confidence score above the tenant-configured threshold for this blast radius level?
4. **Reversibility check**: Does the action plan include a valid rollback? Reject high-blast actions without rollback.
5. **Trust level check**: Has this AI earned enough trust with this tenant to act autonomously at this blast radius?
   - New tenants start at trust level 1 (human approves everything except read-only)
   - Trust increases as AI makes correct decisions confirmed by analysts
   - Trust level determines the maximum blast radius for autonomous action
6. **Rate limiting**: Is the AI taking too many actions too quickly? (Prevents runaway loops)

**Output:**
- `APPROVED` → Send to Action Executor immediately
- `HUMAN_REVIEW` → Send to Approval Workflow with full AI reasoning + plan
- `REJECTED` → Log rejection reason, notify AI to re-plan with constraints

### 8. Approval Workflow Engine

Manages human-in-the-loop for actions that require approval. Simplified from the previous design — no playbook logic, just approve/reject AI-generated plans.

**Flow:**
1. Safety Gate routes action plan to human review
2. Notification sent to designated approver (Slack, email, PagerDuty) within 60 seconds
3. Approver sees: AI's reasoning, proposed actions, blast radius, rollback plan
4. Approver clicks: Approve / Reject / Modify
5. On approve → Action Executor runs the plan
6. On reject → AI receives feedback, logs rejection, learns
7. On timeout (configurable, default 4 hours) → Escalate

**Trust ramp:**
- First 30 days: AI presents all plans for approval (building trust)
- After 30 days with >90% approval rate: Low-blast actions auto-approved
- After 90 days with >95% approval rate: Medium-blast actions auto-approved
- High-blast actions always require human approval (never fully autonomous)

### 9. Action Executor

Executes AI-generated action plans against connected tools. This is a **dumb executor** — it doesn't decide what to do, it just runs the API calls the AI planned and the Safety Gate approved.

**Responsibilities:**
- Execute API calls against connected tools using connector credentials
- Verify execution success (confirm the action took effect)
- Register rollback information in the Rollback Registry
- Report execution outcome back to the AI (for learning) and to the Audit Log
- Handle execution failures: retry once, then escalate

**Execution flow:**
```
Approved Action Plan
    │
    ▼
┌─────────────────────┐
│ Resolve connector   │ ← Which authenticated connection to use?
│ credentials         │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Execute API call    │ ← Run the exact call the AI specified
│                     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Verify outcome      │ ← Did it work? Query to confirm.
│                     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Register rollback   │ ← Store how to undo this action
│                     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Log to Audit Trail  │ ← Immutable record of what was done and why
│ + Report to AI      │
└─────────────────────┘
```

**Execution SLAs:**
- Read-only actions: < 10 seconds
- Single-resource writes: < 30 seconds
- Multi-resource operations: < 5 minutes
- On failure: retry once within 30 seconds; on second failure, escalate to human

### 10. Rollback Registry

Maintains the ability to undo any action the AI has taken. Every executed action must have a registered rollback.

**Implementation:**
- Stores: action ID, original state, rollback API call, expiry time
- Rollback can be triggered by: analyst (one-click undo), AI (if it determines the action was wrong), or automatic (if verification shows the action didn't achieve its goal)
- Rollback actions go through the same Safety Gate (to prevent rollback from causing more damage)
- Rollback availability is time-limited (some actions become irreversible after a window)

### 11. Reasoning Memory (per-tenant)

The AI's accumulated experience for each customer. This is what makes the AI get smarter over time for each specific environment.

**What it stores:**
- Past incidents: what happened, what the AI did, what the outcome was
- Analyst feedback: false positives, true positives, severity overrides, action rejections
- Environment-specific patterns: "this service account always does X on Tuesdays" (learned normal)
- Reasoning traces: full chain-of-thought for past decisions (for learning and audit)

**How the AI uses it:**
- RAG retrieval: when reasoning about a new event, retrieve similar past incidents and their outcomes
- Confidence calibration: if the AI was wrong about similar events before, lower confidence
- False positive avoidance: if analysts marked similar events as FP, factor that in
- Response optimization: if a particular response worked well before, prefer it

**Feedback loop:**
```
AI makes decision → Action executed → Outcome observed
                                           │
                                           ▼
                              Analyst provides feedback
                              (correct / incorrect / partial)
                                           │
                                           ▼
                              Memory updated → AI reasons better next time
```

### 12. Threat Intelligence Layer

External knowledge that the AI uses as context for reasoning. Not a detection rule database — a knowledge source the AI reasons over.

**Sources:**
- MITRE ATT&CK framework (tactics, techniques, procedures)
- NVD CVE database (vulnerabilities, affected products, CVSS scores)
- Commercial IOC feeds (malicious IPs, domains, hashes)
- OSINT feeds (open-source threat intelligence)
- Dark web monitoring (credential leaks, targeted threats)
- Cross-tenant intelligence (anonymized patterns from opted-in tenants)

**Implementation:**
- Vector store with embeddings for semantic search
- Updated continuously as new intelligence arrives
- AI retrieves relevant intel at reasoning time via RAG
- SLAs: CVE/TTP within 4 hours, IOC within 2 hours, dark web within 30 minutes

### 13. Cross-Tenant Intelligence

Network effects from multiple customers — anonymized, opt-in.

**How it works:**
- When the AI detects a threat at Customer A, the pattern (stripped of all customer-identifying info) is added to the shared intelligence pool
- When reasoning about events at Customer B, the AI can retrieve: "This pattern was seen at 3 other environments this week and confirmed as malicious"
- De-identification removes: tenant_id, organization_name, user_ids, asset_ids, IP addresses (internal)
- Opt-out tenants: excluded from contributing and receiving cross-tenant intelligence

**Moat:** This creates network effects — more customers = better intelligence = better reasoning for everyone. Competitors starting later have less data.

### 14. Notification Dispatcher

Delivers notifications across configured channels. Unchanged from previous design — this is plumbing.

**Delivery logic:**
- Attempt delivery on all configured channels in parallel
- Retry failed channels up to 3 times with exponential backoff
- Log each failure in the Audit Log
- Channels: Slack, email, PagerDuty, SMS, ticketing (Jira, ServiceNow)

### 15. Audit Logger

Maintains the immutable, append-only record of ALL AI decisions and actions.

**What gets logged:**
- Every AI reasoning request and output (full reasoning trace)
- Every action plan generated
- Every Safety Gate decision (approved/rejected/human-review and why)
- Every action executed (what, where, outcome)
- Every rollback performed
- Every analyst feedback submission
- Every human approval/rejection decision

**Implementation:**
- Write-once Elasticsearch index (lifecycle policy prevents updates/deletes)
- Any modification attempt is itself logged as a new entry
- Query SLA: < 5 seconds for queries spanning ≤ 90 days
- Retention: minimum 12 months
- Export: JSON and CSV, available within 5 minutes of request

### 16. Web Console (SOC UI)

The human interface to the AI agent. Key difference from traditional SOC UIs: this shows the AI's reasoning, not just alerts.

**Key views:**
- **AI Activity Feed**: Real-time stream of what the AI is doing — detecting, reasoning, acting. Each entry shows the AI's explanation in natural language.
- **Approval Queue**: Actions awaiting human approval. Shows AI reasoning, proposed plan, blast radius, rollback plan. One-click approve/reject.
- **Incident Detail**: Full context — AI's reasoning trace, related events, environment context, action history, predictions.
- **Environment Model**: Visual graph of infrastructure, highlighted with current threats and vulnerabilities.
- **Audit Trail**: Complete history of all AI decisions and actions, searchable and exportable.
- **Executive Risk View**: Business risk score, KPIs (MTTD, MTTR, false positive rate, autonomous resolution rate), trend charts.
- **Trust Dashboard**: Current AI trust level, approval rate history, path to increased autonomy.

---

## Data Flow: End-to-End Example

**Scenario:** Compromised AWS IAM key used from anomalous location.

```
1. CloudTrail event arrives: AssumeRole from IP 198.51.100.23
   → Connector Manager ingests
   → Telemetry Normalizer produces canonical event

2. Fast Filter evaluates:
   → "New source IP for this role, geo = Russia, role has S3 access"
   → Output: { interesting: true, urgency: "immediate" }

3. Context Assembly gathers:
   → Environment: This role accesses production S3 buckets
   → History: This role has never been used from outside US
   → Threat Intel: IP 198.51.100.23 flagged in 2 IOC feeds
   → Tool Capabilities: Can revoke keys, can modify SGs, can stop instances
   → Memory: Similar incident 3 months ago was confirmed compromise

4. AI Reasoning Engine analyzes:
   → "This is credential compromise (T1078.004). High confidence (92).
      The key has S3:GetObject on production buckets. Attacker likely
      exfiltrating data. Need to revoke immediately and audit access."
   → Generates action plan: revoke key + audit CloudTrail + check S3 logs

5. Safety Gate validates:
   → Revoke key: blast_radius=low, confidence=92, trust_level=2 → APPROVED
   → Audit CloudTrail: blast_radius=none → APPROVED
   → Check S3 logs: blast_radius=none → APPROVED

6. Action Executor runs:
   → Calls AWS IAM UpdateAccessKey (Status=Inactive) → Success
   → Registers rollback (Status=Active)
   → Calls CloudTrail LookupEvents → Returns results to AI
   → Logs everything to Audit Trail

7. AI receives execution results:
   → "Key revoked. CloudTrail shows 47 S3 GetObject calls in last 2 hours
      to production-data bucket. Recommending: notify security team,
      assess data exposure, rotate all keys for this service account."
   → Generates follow-up plan (higher blast radius → routes to human approval)

8. Human receives notification:
   → "AI detected and contained credential compromise. Key revoked.
      Potential data exfiltration: 47 objects accessed. AI recommends
      rotating all service account keys. Approve?"
   → Human approves → AI executes rotation
```

---

## Security Considerations

- **AI cannot execute arbitrary code** — only pre-authenticated API calls against connected tools
- **All AI actions are auditable** — full reasoning trace stored immutably
- **Blast radius limits autonomous action** — high-impact actions always require human approval
- **Rollback available for every action** — mistakes are reversible
- **Trust is earned, not assumed** — new tenants start with maximum human oversight
- **Tenant data isolation** — AI reasoning for Tenant A never sees Tenant B's data
- **AI reasoning is stateless** — no persistent state between requests; all context assembled from stores
- **Rate limiting** — AI cannot take more than N actions per minute per tenant (prevents runaway)

---

## Future Considerations (Post-MVP)

- **Endpoint Agent**: Lightweight daemon for on-device response (process termination, file quarantine, device isolation)
- **Sandbox Detonation**: gVisor/Firecracker microVMs for file analysis
- **Multi-cloud**: Azure and GCP support (same architecture, new connectors + tool discovery)
- **Custom tool SDK**: Let customers teach the AI about internal/custom tools
- **Adversary simulation**: AI-driven purple team exercises
- **Compliance automation**: Automated compliance report generation (SOC 2, ISO 27001, GDPR)
