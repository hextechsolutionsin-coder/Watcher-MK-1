/**
 * Prompt templates for the AI Reasoning Engine.
 *
 * Separated from the engine so prompts can be tuned independently.
 * All prompts use structured XML tags — Claude responds better to
 * clearly delimited sections than to free-form instructions.
 */

import {
  ReasoningRequest,
  ToolCapabilityProfile,
  ReasoningMemoryEntry,
  EnvironmentContext,
  NormalizedEvent,
  TenantConfig,
} from '../types/index.js';
import { getEnvironmentFacts, buildKnownIpsContext } from '../pipeline/environment-config.js';

// ============================================================================
// System Prompt
// ============================================================================

export const SYSTEM_PROMPT = `You are Watcher MK1, an autonomous cybersecurity reasoning agent.

Your job is to analyze security events from AWS environments, determine if they represent genuine threats, and generate specific response plans using the tools available in the customer's environment.

<core_principles>
- You reason from first principles — you have no pre-written detection rules or playbooks
- Every decision you make must be explainable in plain English
- You only plan actions that are within the available tool capabilities
- You are conservative: when uncertain, escalate to human review rather than act
- You think about blast radius — prefer reversible, targeted actions over broad ones
- You consider the specific customer environment, not generic patterns
</core_principles>

<output_format>
You must respond with valid JSON matching this exact structure:
{
  "is_threat": boolean,
  "assessment": {
    "threat_type": "string — concise threat category e.g. 'Credential Compromise'",
    "threat_description": "string — what is happening",
    "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL",
    "confidence": number between 0-100,
    "mitre_techniques": [
      { "technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access" }
    ],
    "affected_assets": ["arn:aws:..."],
    "kill_chain_stage": "string — current stage e.g. 'Initial Access'",
    "related_incident_ids": [],
    "predictions": {
      "next_likely_action": "string",
      "probability": number 0-100,
      "recommended_preemption": "string"
    }
  },
  "action_plan": {
    "actions": [
      {
        "sequence": 1,
        "description": "string — what this action does",
        "reasoning": "string — why this specific action is necessary",
        "connector_id": "string — from available tools",
        "tool_action_id": "string — from available tool actions",
        "aws_service": "string",
        "aws_api_call": "string",
        "api_params": {},
        "blast_radius": "NONE | LOW | MEDIUM | HIGH",
        "urgency": "IMMEDIATE | QUEUE | ADVISORY",
        "confidence": number 0-100,
        "rollback_spec": {
          "aws_service": "string",
          "aws_api_call": "string",
          "api_params": {},
          "description": "string — what rollback does"
        }
      }
    ],
    "overall_reasoning": "string — why this plan addresses the threat"
  },
  "explanation": "string — plain English explanation for a non-technical approver",
  "reasoning_trace": "string — your full chain of thought"
}

If is_threat is false, omit action_plan. assessment is also optional if is_threat is false.
</output_format>`;

// ============================================================================
// Reactive Prompt (triggered by an incoming event)
// ============================================================================

export function buildReactivePrompt(request: ReasoningRequest): string {
  const event = request.trigger_event!;
  const env = request.environment_context;
  const memory = request.relevant_memory;
  const tools = request.tool_capabilities;
  const config = request.tenant_config;

  return `<task>
Analyze the following AWS security event and determine if it represents a genuine threat. If it does, generate a specific response plan using the available tools.
</task>

${buildKnownFactsSection()}

<event>
Source: ${event.source}
Event Type: ${event.event_type}
Account: ${event.account_id}
Region: ${event.region}
Timestamp: ${event.ingestion_timestamp}

Actor:
  Type: ${event.actor.type}
  Identity: ${event.actor.identifier}
  Account: ${event.actor.account_id ?? 'unknown'}
  Session: ${event.actor.session_context ?? 'none'}

Target Resource:
  Type: ${event.target.resource_type}
  ID: ${event.target.resource_id}
  Name: ${event.target.resource_name ?? 'unnamed'}
  Attack Surface: ${event.target.attack_surface}

Network:
  Source IP: ${event.source_ip ?? 'not available'}
  User Agent: ${event.user_agent ?? 'not available'}

Raw Event Data:
${JSON.stringify(event.raw_payload, null, 2).slice(0, 2000)}
</event>

${buildExistingIncidentSection(event.raw_payload as Record<string, unknown>)}

${buildEnvironmentSection(env)}

${buildToolsSection(tools)}

${buildMemorySection(memory)}

${buildConfigSection(config)}

<instructions>
1. Analyze the event in the context of this specific AWS environment
2. If this event matches a known fact (e.g., a known trusted account), dismiss it immediately with a one-line explanation. Do NOT write long essays for benign events.
3. Keep your response under 200 words for non-threats. Only write detailed analysis for actual threats.
4. Consider: Is this behavior normal for this actor and resource? Is the source IP suspicious? Is the action dangerous given the target resource's criticality?
5. If this is a threat: determine severity, map to MITRE ATT&CK, and generate a specific response plan
6. Only include actions that are available in the tool capabilities above
7. For each action, specify the exact AWS API call and parameters
8. Include rollback specifications for any write actions
9. Write your explanation for a CISO who needs to approve or understand the response
</instructions>`;
}

// ============================================================================
// Proactive Prompt (threat hunting — no triggering event)
// ============================================================================

export function buildProactivePrompt(request: ReasoningRequest): string {
  const env = request.environment_context;
  const memory = request.relevant_memory;
  const tools = request.tool_capabilities;

  return `<task>
Perform a proactive threat hunt across this AWS environment. Review the environment state, recent activity patterns, and your memory of past incidents to identify any hidden threats, suspicious patterns, or security gaps that may have been missed by reactive detection.
</task>

${buildEnvironmentSection(env)}

${buildToolsSection(tools)}

${buildMemorySection(memory)}

<recent_events>
${request.recent_events.slice(0, 20).map(formatEventSummary).join('\n')}
</recent_events>

<instructions>
1. Look for patterns across recent events that individually seem benign but together suggest an attack
2. Check for dormant threats — activity that stopped but may resume
3. Identify configuration risks in the environment that could be exploited
4. Consider what an attacker who already has a foothold might do next
5. If you find threats or suspicious patterns, generate response plans
6. If the environment looks clean, say so clearly with your reasoning
</instructions>`;
}

// ============================================================================
// Predictive Prompt (forecasting — new threat intel or config change)
// ============================================================================

export function buildPredictivePrompt(request: ReasoningRequest): string {
  const env = request.environment_context;
  const tools = request.tool_capabilities;

  return `<task>
${request.trigger_description ?? 'Assess this AWS environment for susceptibility to emerging threats.'}
</task>

${buildEnvironmentSection(env)}

${buildToolsSection(tools)}

<instructions>
1. Analyze the environment's attack surface against the described threat or technique
2. Identify specific assets that could be exploited and the attack path to reach them
3. Assess the exploitability score (0-100) based on: path length, asset criticality, public exposure
4. Generate pre-emptive recommendations to close the attack path before exploitation
5. If the environment is not susceptible, explain why clearly
</instructions>`;
}

// ============================================================================
// Investigative Prompt (analyst-requested deep dive)
// ============================================================================

export function buildInvestigativePrompt(request: ReasoningRequest): string {
  const env = request.environment_context;
  const memory = request.relevant_memory;
  const tools = request.tool_capabilities;

  return `<task>
${request.trigger_description ?? 'Perform a deep investigation of this security situation.'}
</task>

${buildEnvironmentSection(env)}

${buildToolsSection(tools)}

${buildMemorySection(memory)}

<recent_events>
${request.recent_events.slice(0, 30).map(formatEventSummary).join('\n')}
</recent_events>

<instructions>
1. Perform a thorough investigation of the described situation
2. Reconstruct the timeline of events
3. Identify all affected assets and the relationships between them
4. Determine the attacker's likely objective and current position in the kill chain
5. Generate a comprehensive response plan to contain and remediate
6. Identify any evidence that should be preserved before remediation
</instructions>`;
}

// ============================================================================
// Section Builders
// ============================================================================

function buildExistingIncidentSection(rawPayload: Record<string, unknown>): string {
  const existing = rawPayload['_watcher_existing_incident'] as Record<string, unknown> | undefined;
  if (!existing) return '';

  return `<existing_incident>
IMPORTANT: This actor already has an open incident (ID: ${existing['id']}).
Threat type: ${existing['threat_type']}
Evidence collected so far: ${existing['evidence_count']} events
Incident opened: ${existing['created_at']}

Decide: Is this new event a continuation of the same attack (add to existing incident) or a distinct new threat?
If continuation — reference the existing incident in your response and focus your action plan on the NEW step only.
If new threat — treat independently.
</existing_incident>`;
}

function buildKnownFactsSection(): string {
  const facts = getEnvironmentFacts();
  const knownIpsContext = buildKnownIpsContext();

  const allFacts = [
    ...facts,
    ...(knownIpsContext ? [knownIpsContext] : []),
  ];

  if (allFacts.length === 0) return '';

  return `<known_facts>
${allFacts.map((f) => `- ${f}`).join('\n')}

IP ADDRESS REASONING RULES:
- If the source IP matches a known trusted IP above: lower your threat confidence by 20-30 points for that factor alone. Still flag if the ACTION itself is dangerous (e.g. CreateUser, StopLogging) regardless of IP.
- If the source IP is NOT in the known list and the actor is root or an admin: treat as higher risk.
- Off-hours activity (outside 06:00-22:00 UTC) from even trusted IPs warrants a note in your reasoning.
- A trusted IP does NOT mean the action is safe — it means the identity is more likely legitimate.
</known_facts>`;
}

function buildEnvironmentSection(env: EnvironmentContext): string {
  const criticalAssets = env.critical_assets.slice(0, 15);

  return `<environment>
Account: ${env.account_id}
Total Assets: ${env.total_assets}
Active Incidents: ${env.active_incidents_count}
Recent Config Changes: ${env.recent_config_changes.slice(0, 10).join(', ') || 'none'}

Critical Assets (criticality >= 7):
${criticalAssets.map((a) =>
  `  - ${a.resource_type} | ${a.resource_name ?? a.resource_id} | criticality: ${a.criticality}/10 | public: ${a.is_public_facing} | surface: ${a.attack_surface}`
).join('\n') || '  none identified yet'}
</environment>`;
}

function buildToolsSection(tools: ToolCapabilityProfile[]): string {
  if (tools.length === 0) {
    return `<available_tools>
No tools connected. You can only provide advisory recommendations.
</available_tools>`;
  }

  const allActions = tools.flatMap((t) => t.writable_actions);
  const readSources = [...new Set(tools.flatMap((t) => t.readable_sources))];

  return `<available_tools>
Connected Accounts: ${tools.map((t) => t.account_id).join(', ')}
Readable Data Sources: ${readSources.join(', ')}

Available Response Actions:
${allActions.map((a) =>
  `  - ${a.action_id} | ${a.description} | blast_radius: ${a.blast_radius} | reversible: ${a.reversible}`
).join('\n')}

IMPORTANT: Only plan actions from the list above. Do not invent action_ids.
Use the connector_id: "${tools[0]?.connector_id ?? 'unknown'}"
</available_tools>`;
}

function buildMemorySection(memory: ReasoningMemoryEntry[]): string {
  if (memory.length === 0) {
    return `<memory>
No relevant past incidents found for this environment.
</memory>`;
  }

  return `<memory>
Relevant Past Incidents (most recent first):
${memory.slice(0, 5).map((m) =>
  `  - [${m.outcome}] ${m.threat_type}: ${m.threat_description.slice(0, 100)}
    Actions taken: ${m.actions_taken.join(', ')}
    Feedback: ${m.analyst_feedback ? m.analyst_feedback.verdict : 'no feedback'}`
).join('\n')}
</memory>`;
}

function buildConfigSection(config: TenantConfig): string {
  return `<tenant_config>
Trust Level: ${config.trust_level} (1=supervised, 2=semi-auto, 3=autonomous)
Reasoning Sensitivity: ${config.reasoning_sensitivity}
Confidence Threshold (low blast): ${config.confidence_threshold_low}
Confidence Threshold (medium blast): ${config.confidence_threshold_medium}
</tenant_config>`;
}

function formatEventSummary(event: NormalizedEvent): string {
  return `  [${event.source}] ${event.event_type} | actor: ${event.actor.identifier} | target: ${event.target.resource_id} | ip: ${event.source_ip ?? 'n/a'} | ${event.ingestion_timestamp}`;
}
