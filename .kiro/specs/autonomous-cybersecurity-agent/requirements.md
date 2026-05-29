# Requirements Document

## Introduction

This document defines the requirements for Watcher MK1 — an AI-powered autonomous cybersecurity reasoning agent deployed as a cloud-native SaaS platform. The platform uses a central AI Reasoning Engine to continuously monitor customer environments, understand threats through contextual reasoning (not pre-written rules), generate dynamic response plans (not playbooks), and execute remediation actions autonomously with appropriate safety guardrails.

The core innovation is that ALL detection, correlation, triage, and response planning is performed by the AI reasoning about raw telemetry in context — with no human-authored detection rules, no coded detection modules, and no scripted playbooks. The AI discovers connected tools, understands their capabilities, and generates correct API calls dynamically.

**Problem Statement:**
1. Knowledge Gap — Security expertise is scarce, inconsistent, and doesn't scale.
2. Response Time — The human detect-investigate-decide-act loop takes hours to days; attackers operate in minutes.

---

## Glossary

- **AI Reasoning Engine**: The core AI agent that analyzes telemetry, understands threats, and generates response plans through contextual reasoning — not rule matching or playbook execution.
- **Tenant**: A customer organization using the platform.
- **Incident**: A confirmed or suspected threat event that the AI has identified and recorded.
- **Action Plan**: A dynamically-generated set of response actions the AI determines are necessary for a specific incident — not a pre-written playbook.
- **Safety Gate**: The validation layer that checks every AI-generated action for blast radius, confidence, reversibility, and trust level before allowing execution.
- **Blast Radius**: The potential impact scope of an action if it's wrong (none/low/medium/high).
- **Trust Level**: A per-tenant score that increases as the AI demonstrates correct decisions, determining how much autonomy the AI has.
- **Environment Model**: A live, continuously-updated representation of the customer's infrastructure that provides situational awareness to the AI.
- **Reasoning Memory**: Per-tenant accumulated experience — past incidents, outcomes, feedback — that makes the AI smarter over time for each customer.
- **Tool Capability Profile**: Auto-discovered description of what a connected tool can do (read/write capabilities, API permissions).
- **Fast Filter**: A lightweight AI model that triages all incoming events, routing only suspicious ones to the full Reasoning Engine.
- **Rollback**: The ability to undo any action the AI has taken.
- **Connector**: An authenticated connection to a customer's security tool or cloud platform.
- **Reasoning Trace**: The full chain-of-thought explanation of why the AI made a specific decision.

---

## Requirements

### Requirement 1: Telemetry Ingestion and Normalization

**User Story:** As a security engineer, I want the platform to ingest telemetry from all my security tools and cloud platforms, so that the AI has complete visibility into my environment.

#### Acceptance Criteria

1. THE platform SHALL provide Connectors for the following tool categories: cloud platforms (AWS at minimum for MVP), EDR platforms, identity providers, SaaS applications, SIEM platforms, notification channels, and ticketing systems.
2. WHEN a new Connector is registered by a Tenant, THE platform SHALL begin ingesting telemetry from that source within 5 minutes of successful authentication.
3. THE platform SHALL normalize all ingested telemetry into a canonical event schema containing: source tool, event type, timestamp, affected asset(s), actor, and raw payload — before passing events to the AI for reasoning.
4. IF a Connector fails to deliver telemetry for 60 or more consecutive seconds, THEN THE platform SHALL raise an alert to the Tenant identifying the affected Connector and last successful ingestion timestamp.
5. IF a Connector's authentication credentials expire, THEN THE platform SHALL alert the Tenant administrator within 5 minutes and suspend ingestion from that Connector until credentials are renewed.
6. THE platform SHALL support webhook-based ingestion for tools not covered by native Connectors, via a documented REST API that validates authentication and payload schema before accepting data.

---

### Requirement 2: Tool Discovery and Dynamic Capability Understanding

**User Story:** As a security engineer, I want the platform to automatically understand what my connected tools can do, so that the AI can use them for response without me configuring action mappings.

#### Acceptance Criteria

1. WHEN a Connector is registered, THE Tool Discovery Engine SHALL automatically inspect the granted API permissions and produce a Tool Capability Profile describing what read and write actions are available through that connection.
2. THE Tool Capability Profile SHALL include: connector identifier, tool type, list of readable data sources, list of writable actions (with required parameters), authentication method, and API endpoint information.
3. THE AI Reasoning Engine SHALL have access to all Tool Capability Profiles for the Tenant when generating action plans, and SHALL only generate actions that are within the discovered capabilities.
4. WHEN a Connector's permissions change (expanded or restricted), THE Tool Discovery Engine SHALL update the Tool Capability Profile within 10 minutes of detecting the change.
5. IF the AI generates an action plan that references a capability not available in any connected tool, THE AI SHALL note the gap in its response and suggest alternative actions using available tools, or recommend the Tenant connect an additional tool.

---

### Requirement 3: Environment Model

**User Story:** As a security analyst, I want the platform to maintain a live understanding of my infrastructure, so that the AI can reason about threats in the context of my specific environment.

#### Acceptance Criteria

1. THE platform SHALL maintain a continuously-updated Environment Model for each Tenant containing: all known assets, relationships between assets (network connectivity, permission grants, data flows), asset criticality ratings, behavioral baselines per asset and user, and current configuration state.
2. THE Environment Model SHALL be refreshed fully at least once every 24 hours, and SHALL incorporate incremental updates from ingested telemetry within 5 minutes of relevant events being processed.
3. THE Environment Model SHALL establish behavioral baselines per asset and per user by analyzing a minimum of 30 days of historical activity, and SHALL update baselines within 24 hours of new activity being recorded.
4. THE AI Reasoning Engine SHALL receive relevant portions of the Environment Model as context for every reasoning request, enabling it to assess threats in the context of the specific customer's infrastructure.
5. WHEN a configuration change is detected (new asset, permission change, network topology change), THE Environment Model SHALL reflect that change within 2 hours and the AI SHALL factor the updated state into subsequent reasoning.

---

### Requirement 4: AI Reasoning Engine — Threat Detection and Understanding

**User Story:** As a SOC analyst, I want the AI to detect and understand threats through reasoning — not pre-written rules — so that it can identify novel attacks that no rule has been written for.

#### Acceptance Criteria

1. THE AI Reasoning Engine SHALL analyze incoming telemetry events in context (environment model, recent history, threat intelligence, reasoning memory) and determine whether each event represents a genuine threat — without relying on pre-written detection rules or coded detection modules.
2. WHEN the AI identifies a threat, it SHALL produce a structured Incident record containing: threat description in natural language, severity assessment, confidence score (0–100), affected assets, MITRE ATT&CK technique mapping, reasoning trace explaining how it reached its conclusion, and a generated action plan.
3. THE AI SHALL assess severity contextually — considering the specific environment, asset criticality, current attack state, and potential business impact — rather than applying a fixed formula to all events regardless of context.
4. THE AI SHALL detect threats across all attack types including but not limited to: credential compromise, lateral movement, data exfiltration, insider threats, misconfigurations, zero-day behavioral patterns, and supply chain attacks — all through reasoning, not through separate coded detection modules.
5. WHEN the AI detects related events that form a multi-stage attack, it SHALL reconstruct the kill chain as an ordered sequence of observed techniques and affected assets, and SHALL predict the next likely attack stage with a probability score.
6. THE AI SHALL operate in multiple reasoning modes: REACTIVE (analyzing incoming events), PROACTIVE (hunting for hidden threats at least daily), PREDICTIVE (forecasting vulnerability to emerging techniques), and INVESTIGATIVE (deep analysis on analyst request).
7. WHEN operating in PROACTIVE mode, THE AI SHALL autonomously search for hidden threats across all ingested telemetry at least once every 24 hours per Tenant, without requiring analyst initiation or pre-written hunting queries.
8. WHEN operating in PREDICTIVE mode, THE AI SHALL assess the Tenant's environment for susceptibility to emerging attack techniques observed in threat intelligence feeds or across other tenants, and SHALL generate a forecast report with affected assets, attack paths, and recommended mitigations.

---

### Requirement 5: AI Reasoning Engine — Dynamic Response Planning

**User Story:** As a CISO, I want the AI to generate response plans specific to each incident — not execute pre-written playbooks — so that responses are tailored to the exact threat and environment context.

#### Acceptance Criteria

1. WHEN the AI identifies a threat requiring action, it SHALL generate a dynamic action plan specific to that incident — considering the threat type, affected assets, available tools, environment context, and past outcomes — without referencing or executing pre-written playbooks.
2. EACH action in the generated plan SHALL include: the specific API call to execute (tool, endpoint, parameters), a natural language explanation of why this action is necessary, a blast radius assessment (none/low/medium/high), an urgency level, and a rollback specification describing how to undo the action.
3. THE AI SHALL only generate actions that are within the capabilities discovered by the Tool Discovery Engine for the Tenant's connected tools. If the ideal action is not available, the AI SHALL reason about alternatives using available tools.
4. THE AI SHALL generate a natural language explanation for the complete action plan that a non-technical approver can understand — describing what was detected, why it matters, and what the AI proposes to do about it.
5. IF the AI determines that no automated action is appropriate (insufficient confidence, no available tools, or business context requires human judgment), it SHALL generate an advisory-only response with its analysis and recommendations, routed to the analyst queue.
6. WHEN the AI receives execution results from completed actions, it SHALL reason about the outcomes and generate follow-up actions if needed (e.g., "key revoked successfully, now auditing what was accessed").

---

### Requirement 6: Fast Filter (Event Triage)

**User Story:** As a platform operator, I want a lightweight model to triage all incoming events before they reach the full reasoning engine, so that the platform remains cost-effective and responsive at scale.

#### Acceptance Criteria

1. THE Fast Filter SHALL evaluate every normalized telemetry event and classify it as: interesting (requires AI reasoning) or not interesting (can be dropped from active processing).
2. THE Fast Filter SHALL process each event with a latency of less than 100 milliseconds.
3. THE Fast Filter SHALL route events classified as interesting with urgency "immediate" to the AI Reasoning Engine within 5 seconds, and events with urgency "queue" within 60 seconds.
4. THE Fast Filter SHALL achieve a false negative rate of less than 1% — meaning no more than 1% of events that would be classified as threats by the full Reasoning Engine are incorrectly dropped by the filter.
5. THE Fast Filter SHALL be continuously improved using feedback from the AI Reasoning Engine — events that the filter dropped but should have flagged (identified through proactive hunting) are used to retrain the filter.

---

### Requirement 7: Safety Gate and Tiered Autonomy

**User Story:** As a CISO, I want the platform to validate every AI-generated action before execution with appropriate safety checks, so that the AI cannot cause unintended damage to my environment.

#### Acceptance Criteria

1. THE Safety Gate SHALL validate every action in every AI-generated plan before execution, checking: tool permission validity, blast radius, AI confidence score, reversibility, and tenant trust level.
2. THE Safety Gate SHALL assign a blast radius to each proposed action: `none` (read-only), `low` (single-resource write), `medium` (multi-resource or service-affecting), `high` (environment-wide or potentially irreversible).
3. ACTIONS with blast radius `none` SHALL be auto-approved regardless of trust level.
4. ACTIONS with blast radius `high` SHALL always require explicit human approval regardless of trust level — the AI SHALL never autonomously execute high-blast-radius actions.
5. ACTIONS with blast radius `low` or `medium` SHALL be auto-approved or routed to human review based on the Tenant's current trust level and the AI's confidence score for that action.
6. THE Safety Gate SHALL reject any action that does not include a valid rollback specification (except for read-only actions with blast radius `none`).
7. THE Safety Gate SHALL enforce rate limiting — no more than a configurable maximum number of write actions per minute per Tenant (default: 10) to prevent runaway AI behavior.
8. IF the Safety Gate rejects an action, it SHALL log the rejection reason in the Audit Log and notify the AI Reasoning Engine, which MAY generate an alternative plan with different actions.

---

### Requirement 8: Trust Level and Earned Autonomy

**User Story:** As a security operations manager, I want the AI to earn increased autonomy over time by demonstrating correct decisions, so that I start with full oversight and gradually let the AI act more independently.

#### Acceptance Criteria

1. EACH Tenant SHALL have a trust level (starting at level 1) that determines the maximum blast radius the AI can execute autonomously without human approval.
2. Trust level 1 (new tenant, first 30 days): ALL write actions require human approval. AI operates in recommend-only mode for writes.
3. Trust level 2 (after 30 days with >90% approval rate): Low-blast-radius write actions are auto-approved. Medium and high still require human approval.
4. Trust level 3 (after 90 days with >95% approval rate): Low and medium-blast-radius actions are auto-approved. High-blast-radius actions still require human approval.
5. THE platform SHALL track approval rate as: (approved actions) / (total actions presented for approval) over a rolling 30-day window.
6. IF the approval rate drops below 80% at any trust level, THE platform SHALL automatically reduce the trust level by one and notify the Tenant administrator.
7. THE Tenant administrator SHALL be able to manually override the trust level (increase or decrease) at any time.

---

### Requirement 9: Action Execution and Rollback

**User Story:** As a security engineer, I want every action the AI takes to be reversible, so that mistakes can be quickly undone without lasting damage.

#### Acceptance Criteria

1. THE Action Executor SHALL execute approved actions within 30 seconds of approval for single-resource operations, and within 5 minutes for multi-resource operations.
2. THE Action Executor SHALL verify execution success by confirming the action took effect (e.g., querying the resource state after modification) and SHALL report the verified outcome to the Audit Log.
3. THE Rollback Registry SHALL store a rollback specification for every executed write action, containing: the original state, the API call to restore it, and an expiry time after which rollback may no longer be possible.
4. WHEN a rollback is triggered (by analyst, by AI, or automatically), THE platform SHALL execute the rollback through the same Safety Gate validation as any other action.
5. IF an action execution fails, THE Action Executor SHALL retry once within 30 seconds. If the retry fails, it SHALL escalate to a human operator via configured notification channels and log both failures in the Audit Log.
6. THE platform SHALL provide a one-click rollback capability in the SOC UI for every executed action that has a valid rollback registered.

---

### Requirement 10: Reasoning Memory and Continuous Learning

**User Story:** As a security operations manager, I want the AI to learn from every incident in my environment, so that it gets smarter and more accurate over time for my specific infrastructure.

#### Acceptance Criteria

1. THE platform SHALL persist all Incidents, action plans, execution outcomes, and analyst feedback in the Reasoning Memory for the lifetime of the Tenant's subscription.
2. WHEN an analyst provides feedback on an AI decision (correct, incorrect, false positive, severity override, action rejection), THE Reasoning Memory SHALL incorporate that feedback and the AI SHALL factor it into subsequent reasoning within 24 hours.
3. THE AI Reasoning Engine SHALL retrieve relevant past incidents and their outcomes from Reasoning Memory when analyzing new events, using them to calibrate confidence and inform response planning.
4. WHEN the AI was previously wrong about a similar event (marked as false positive by analyst), it SHALL reduce its confidence for similar events in the future and note the historical context in its reasoning trace.
5. THE platform SHALL generate and deliver a weekly summary to the Tenant's security team containing: incidents detected, actions taken, approval rate, false positive rate, and AI confidence trends.
6. WHEN a Tenant's subscription ends, THE platform SHALL delete all Tenant-specific Reasoning Memory data within 30 days and provide a deletion confirmation record.

---

### Requirement 11: Threat Intelligence Integration

**User Story:** As a security analyst, I want the AI to have access to current threat intelligence, so that its reasoning reflects the latest known threats, vulnerabilities, and attack techniques.

#### Acceptance Criteria

1. THE platform SHALL ingest threat intelligence from: MITRE ATT&CK framework, NVD CVE database, configured commercial IOC feeds, OSINT feeds, and dark web monitoring sources.
2. THE AI Reasoning Engine SHALL have access to current threat intelligence via RAG retrieval when reasoning about any event, enabling it to correlate observed behavior with known threat patterns.
3. NEW CVE and TTP intelligence SHALL be available to the AI within 4 hours of publication. New IOC intelligence SHALL be available within 2 hours of ingestion. Dark web alerts SHALL be available within 30 minutes.
4. WHEN dark web monitoring detects a reference to a Tenant's domain, IP range, or credential set, THE AI SHALL generate a high-severity Incident within 30 minutes of the alert being ingested.
5. THE platform SHALL deduplicate intelligence across feed sources using a composite key of indicator type and normalized value, storing each unique indicator once with provenance metadata recording all reporting feeds.
6. WHEN an IOC has not been refreshed by any feed for more than 90 days, THE platform SHALL mark it as expired and exclude it from active reasoning context.

---

### Requirement 12: Cross-Tenant Intelligence

**User Story:** As a platform operator, I want the AI to learn from patterns across all customers (with consent), so that an attack seen at one customer improves protection for all customers.

#### Acceptance Criteria

1. WHERE a Tenant has opted into cross-tenant intelligence sharing, THE platform SHALL contribute anonymized threat patterns from that Tenant's incidents to the shared intelligence pool.
2. BEFORE contributing to the shared pool, THE platform SHALL remove all Tenant-specific identifiers: tenant_id, organization_name, user_ids, asset_ids, and internal IP addresses.
3. THE AI Reasoning Engine SHALL retrieve relevant cross-tenant patterns when reasoning about events for opted-in Tenants, noting when a pattern has been observed across multiple environments.
4. IF a Tenant opts out of cross-tenant sharing, THE platform SHALL exclude that Tenant's data from the shared pool AND exclude shared pool data from that Tenant's AI reasoning context.
5. THE platform SHALL deploy updated shared intelligence models with zero gap in event processing using blue/green deployment.

---

### Requirement 13: Approval Workflow

**User Story:** As a CISO, I want to review and approve high-impact AI decisions before they execute, so that I maintain control over critical actions while allowing the AI to handle routine threats autonomously.

#### Acceptance Criteria

1. WHEN the Safety Gate routes an action to human review, THE platform SHALL notify the designated approver via configured channels (Slack, email, PagerDuty) within 60 seconds.
2. THE approval notification SHALL include: the AI's natural language explanation of the threat, the proposed action plan with blast radius for each action, the AI's confidence score, and a one-click approve/reject interface.
3. WHEN a human approves an action, THE platform SHALL execute it within 30 seconds of approval.
4. WHEN a human rejects an action, THE platform SHALL record the rejection reason, log it in the Audit Log, and feed the rejection back to the AI's Reasoning Memory as learning signal.
5. IF no approval or rejection decision is received within the configurable timeout (default: 4 hours, range: 1–72 hours), THE platform SHALL escalate via all configured notification channels and log the timeout in the Audit Log.
6. THE platform SHALL support configurable approval routing — different approvers for different blast radius levels or asset types.

---

### Requirement 14: Audit Trail and Explainability

**User Story:** As a compliance officer, I want a complete, immutable record of every AI decision and action, with full explanations of the AI's reasoning, so that I can demonstrate accountability and compliance.

#### Acceptance Criteria

1. THE platform SHALL maintain an immutable Audit Log where each entry is write-once. Any attempt to modify or delete an existing entry SHALL be rejected and itself recorded as a new entry.
2. THE Audit Log SHALL record for every AI decision: the reasoning trace (full chain-of-thought), the input context used, the output (assessment + action plan), the Safety Gate decision, and the execution outcome.
3. THE Audit Log SHALL record for every executed action: action type, target asset, execution timestamp, outcome (success/failure), the AI's explanation of why this action was taken, and the rollback specification.
4. THE platform SHALL retain Audit Log entries for a minimum of 12 months. Export in JSON and CSV formats SHALL be available within 5 minutes of request.
5. EVERY Incident record SHALL include a natural language explanation that a non-technical stakeholder can understand — describing what happened, why it matters, and what was done about it.
6. THE Audit Log SHALL support queries with results returned within 5 seconds for queries spanning up to 90 days.

---

### Requirement 15: Multi-Tenant Isolation and Data Privacy

**User Story:** As a platform operator, I want each tenant's data to be strictly isolated, so that no tenant can access another tenant's data and the AI never leaks information between tenants.

#### Acceptance Criteria

1. THE platform SHALL enforce logical data isolation between Tenants such that: the AI Reasoning Engine for Tenant A never receives Tenant B's data as context, and any API request attempting cross-tenant access is rejected with an authorization error that does not reveal the other Tenant's existence.
2. THE platform SHALL encrypt all Tenant data at rest (AES-256) and in transit (TLS 1.2+).
3. THE platform SHALL support Tenant-level RBAC with at minimum: Administrator (full access), Analyst (read incidents + provide feedback), Approver (approve/reject actions), and Read-Only roles.
4. WHEN a Tenant's subscription ends, THE platform SHALL permanently delete all Tenant-specific data from primary storage, backups, and replicated copies within 30 days, and SHALL provide a deletion confirmation record.
5. ROLE changes SHALL take effect within 60 seconds of being saved.

---

### Requirement 16: Platform Availability and Scalability

**User Story:** As a platform operator, I want the platform to be highly available and scale with tenant growth without degrading AI reasoning quality or response time.

#### Acceptance Criteria

1. THE platform SHALL maintain minimum 99.9% uptime per calendar month, excluding scheduled maintenance (communicated 48 hours in advance, max 4 hours per window).
2. THE platform SHALL process events through the Fast Filter with median latency of less than 100 milliseconds.
3. THE platform SHALL complete AI reasoning (from event reaching Reasoning Engine to action plan output) with median latency of less than 30 seconds under normal load.
4. THE platform SHALL execute approved actions within 30 seconds of approval for single-resource operations.
5. THE platform SHALL scale to support a minimum of 10,000 concurrent Tenants while maintaining the latency SLAs above.
6. WHEN a new Tenant is onboarded, THE platform SHALL provision the Tenant's isolated environment and make Connector configuration available within 10 minutes of account creation.

---

### Requirement 17: Web Console (SOC UI)

**User Story:** As a SOC analyst, I want a web console that shows me what the AI is doing, why it's doing it, and lets me approve or override its decisions, so that I maintain situational awareness and control.

#### Acceptance Criteria

1. THE SOC UI SHALL display a real-time AI activity feed showing all AI reasoning outputs, actions taken, and their explanations — updated within 10 seconds of each AI decision.
2. THE SOC UI SHALL provide an approval queue showing all actions awaiting human review, with the AI's full reasoning, proposed plan, blast radius, and one-click approve/reject.
3. THE SOC UI SHALL provide an incident detail view showing: AI reasoning trace, related events, environment context, action history, predictions, and natural language explanation.
4. THE SOC UI SHALL provide a one-click rollback button for every executed action that has a valid rollback registered.
5. THE SOC UI SHALL provide an executive risk view (Administrator role only) showing: business risk score (0–100), KPIs (mean time to detect, mean time to respond, false positive rate, autonomous resolution rate), and trend charts over 7/30/90 day windows.
6. THE SOC UI SHALL display the current trust level and approval rate history, showing the path toward increased AI autonomy.
7. THE SOC UI SHALL provide an audit trail view with search and filter capabilities, and export functionality.
8. IF a user session has no interaction for 30 consecutive minutes, THE SOC UI SHALL invalidate the session and require re-authentication.
