/**
 * AI Reasoning Engine
 *
 * The core brain of Watcher MK1. Uses AWS Bedrock (Claude) to reason about
 * security events, understand threats in context, and generate dynamic
 * response plans — with no pre-written rules or playbooks.
 *
 * Architecture:
 *   ReasoningRequest (assembled context)
 *     → Bedrock Claude (reasoning)
 *     → Structured JSON output
 *     → ReasoningResponse (threat assessment + action plan)
 *
 * The engine is stateless — all context is assembled per-request from stores.
 */

import {
  BedrockRuntimeClient,
  InvokeModelCommand,
  InvokeModelCommandInput,
} from '@aws-sdk/client-bedrock-runtime';

import {
  ReasoningRequest,
  ReasoningResponse,
  ReasoningMode,
  ThreatAssessment,
  ActionPlan,
  PlannedAction,
  MitreTechnique,
  ThreatPrediction,
  RollbackSpec,
  IncidentSeverity,
  BlastRadius,
  ActionUrgency,
} from '../types/index.js';

import {
  SYSTEM_PROMPT,
  buildReactivePrompt,
  buildProactivePrompt,
  buildPredictivePrompt,
  buildInvestigativePrompt,
} from './prompts.js';

// ============================================================================
// Bedrock Configuration
// ============================================================================

/**
 * Supported Bedrock model IDs for reasoning.
 *
 * Claude 4.x models use cross-region inference profile IDs (us.anthropic.*)
 * rather than base model IDs. Pass these as the modelId to Bedrock.
 * See: https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-support.html
 */
export const BEDROCK_MODELS = {
  // Claude 4.x — cross-region inference profiles (available in your catalog)
  CLAUDE_SONNET_46: 'us.anthropic.claude-sonnet-4-6',
  CLAUDE_HAIKU_45:  'us.anthropic.claude-haiku-4-5',
  CLAUDE_OPUS_46:   'us.anthropic.claude-opus-4-6',
  // Claude 3.x — legacy direct model IDs (fallback)
  CLAUDE_35_SONNET: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
  CLAUDE_3_HAIKU:   'anthropic.claude-3-haiku-20240307-v1:0',
} as const;

export type BedrockModelId = typeof BEDROCK_MODELS[keyof typeof BEDROCK_MODELS];

export interface ReasoningEngineConfig {
  /** AWS region where Bedrock is available. */
  region: string;
  /** Model to use for full reasoning. Default: Claude Sonnet 4.6. */
  primaryModel: BedrockModelId;
  /** Max tokens for reasoning response. */
  maxTokens: number;
  /** Temperature — keep low for deterministic security reasoning. */
  temperature: number;
}

export const DEFAULT_CONFIG: ReasoningEngineConfig = {
  region: 'us-east-1',
  primaryModel: BEDROCK_MODELS.CLAUDE_SONNET_46,
  maxTokens: 4096,
  temperature: 0.1,
};

// ============================================================================
// Bedrock Client Interface (for testability)
// ============================================================================

/**
 * Abstraction over the Bedrock API call.
 * In production: calls AWS Bedrock.
 * In tests: returns mock responses.
 */
export interface BedrockInvoker {
  invoke(modelId: string, prompt: string, systemPrompt: string, maxTokens: number, temperature: number): Promise<BedrockInvokeResult>;
}

export interface BedrockInvokeResult {
  content: string;
  input_tokens: number;
  output_tokens: number;
}

// ============================================================================
// Production Bedrock Invoker
// ============================================================================

/**
 * Production implementation — calls AWS Bedrock using the Messages API.
 */
export class AwsBedrockInvoker implements BedrockInvoker {
  private readonly client: BedrockRuntimeClient;

  constructor(region: string) {
    this.client = new BedrockRuntimeClient({ region });
  }

  async invoke(
    modelId: string,
    prompt: string,
    systemPrompt: string,
    maxTokens: number,
    temperature: number
  ): Promise<BedrockInvokeResult> {
    const body = JSON.stringify({
      anthropic_version: 'bedrock-2023-05-31',
      max_tokens: maxTokens,
      temperature,
      system: systemPrompt,
      messages: [
        { role: 'user', content: prompt },
      ],
    });

    const input: InvokeModelCommandInput = {
      modelId,
      contentType: 'application/json',
      accept: 'application/json',
      body: Buffer.from(body),
    };

    const command = new InvokeModelCommand(input);
    const response = await this.client.send(command);

    const responseBody = JSON.parse(Buffer.from(response.body).toString('utf-8')) as {
      content: Array<{ type: string; text: string }>;
      usage: { input_tokens: number; output_tokens: number };
    };

    const text = responseBody.content
      .filter((c) => c.type === 'text')
      .map((c) => c.text)
      .join('');

    return {
      content: text,
      input_tokens: responseBody.usage?.input_tokens ?? 0,
      output_tokens: responseBody.usage?.output_tokens ?? 0,
    };
  }
}

// ============================================================================
// Response Parser
// ============================================================================

/**
 * Parses the raw JSON string from Claude into a typed ReasoningResponse.
 * Handles malformed output gracefully — returns a safe fallback.
 */
export function parseReasoningResponse(
  raw: string,
  requestId: string,
  tenantId: string,
  mode: ReasoningMode,
  modelId: string,
  tokensUsed: number
): ReasoningResponse {
  const now = new Date().toISOString();
  const id = generateId();

  let parsed: Record<string, unknown>;

  try {
    // Claude sometimes wraps JSON in markdown code blocks — strip them
    const cleaned = raw
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/\s*```$/i, '')
      .trim();

    parsed = JSON.parse(cleaned) as Record<string, unknown>;
  } catch {
    // Unparseable response — return safe non-threat assessment
    return {
      id,
      request_id: requestId,
      tenant_id: tenantId,
      mode,
      is_threat: false,
      explanation: 'AI reasoning produced an unparseable response. Manual review recommended.',
      reasoning_trace: raw.slice(0, 500),
      tokens_used: tokensUsed,
      model_id: modelId,
      created_at: now,
    };
  }

  const isThreat = Boolean(parsed.is_threat);
  const explanation = String(parsed.explanation ?? 'No explanation provided.');
  const reasoningTrace = String(parsed.reasoning_trace ?? '');

  let assessment: ThreatAssessment | undefined;
  let actionPlan: ActionPlan | undefined;

  if (isThreat && parsed.assessment) {
    assessment = parseAssessment(parsed.assessment as Record<string, unknown>);
  }

  if (isThreat && parsed.action_plan) {
    actionPlan = parseActionPlan(
      parsed.action_plan as Record<string, unknown>,
      id
    );
  }

  return {
    id,
    request_id: requestId,
    tenant_id: tenantId,
    mode,
    is_threat: isThreat,
    assessment,
    action_plan: actionPlan,
    explanation,
    reasoning_trace: reasoningTrace,
    tokens_used: tokensUsed,
    model_id: modelId,
    created_at: now,
  };
}

function parseAssessment(raw: Record<string, unknown>): ThreatAssessment {
  const techniques: MitreTechnique[] = [];
  if (Array.isArray(raw.mitre_techniques)) {
    for (const t of raw.mitre_techniques) {
      const technique = t as Record<string, unknown>;
      techniques.push({
        technique_id: String(technique.technique_id ?? 'T0000'),
        technique_name: String(technique.technique_name ?? 'Unknown'),
        tactic: String(technique.tactic ?? 'Unknown'),
      });
    }
  }

  const predictions: ThreatPrediction = {
    next_likely_action: 'Unknown',
    probability: 0,
    recommended_preemption: 'Monitor for further activity',
  };
  if (raw.predictions && typeof raw.predictions === 'object') {
    const p = raw.predictions as Record<string, unknown>;
    predictions.next_likely_action = String(p.next_likely_action ?? 'Unknown');
    predictions.probability = Math.min(100, Math.max(0, Number(p.probability ?? 0)));
    predictions.recommended_preemption = String(p.recommended_preemption ?? 'Monitor');
  }

  const severity = parseSeverity(String(raw.severity ?? 'MEDIUM'));

  return {
    threat_type: String(raw.threat_type ?? 'Unknown Threat'),
    threat_description: String(raw.threat_description ?? ''),
    severity,
    confidence: Math.min(100, Math.max(0, Number(raw.confidence ?? 50))),
    mitre_techniques: techniques,
    affected_assets: Array.isArray(raw.affected_assets)
      ? raw.affected_assets.map(String)
      : [],
    kill_chain_stage: raw.kill_chain_stage ? String(raw.kill_chain_stage) : undefined,
    related_incident_ids: Array.isArray(raw.related_incident_ids)
      ? raw.related_incident_ids.map(String)
      : [],
    predictions,
  };
}

function parseActionPlan(raw: Record<string, unknown>, incidentId: string): ActionPlan {
  const actions: PlannedAction[] = [];

  if (Array.isArray(raw.actions)) {
    for (const a of raw.actions) {
      const action = a as Record<string, unknown>;
      const planned = parsePlannedAction(action);
      if (planned) actions.push(planned);
    }
  }

  return {
    id: generateId(),
    incident_id: incidentId,
    actions,
    overall_reasoning: String(raw.overall_reasoning ?? ''),
    created_at: new Date().toISOString(),
  };
}

function parsePlannedAction(raw: Record<string, unknown>): PlannedAction | null {
  // Require minimum fields
  if (!raw.tool_action_id || !raw.aws_service || !raw.aws_api_call) return null;

  let rollbackSpec: RollbackSpec | undefined;
  if (raw.rollback_spec && typeof raw.rollback_spec === 'object') {
    const rs = raw.rollback_spec as Record<string, unknown>;
    if (rs.aws_service && rs.aws_api_call) {
      rollbackSpec = {
        aws_service: String(rs.aws_service),
        aws_api_call: String(rs.aws_api_call),
        api_params: (rs.api_params as Record<string, unknown>) ?? {},
        description: String(rs.description ?? 'Undo this action'),
      };
    }
  }

  return {
    id: generateId(),
    sequence: Number(raw.sequence ?? 1),
    description: String(raw.description ?? ''),
    reasoning: String(raw.reasoning ?? ''),
    connector_id: String(raw.connector_id ?? 'unknown'),
    tool_action_id: String(raw.tool_action_id),
    aws_service: String(raw.aws_service),
    aws_api_call: String(raw.aws_api_call),
    api_params: (raw.api_params as Record<string, unknown>) ?? {},
    blast_radius: parseBlastRadius(String(raw.blast_radius ?? 'MEDIUM')),
    urgency: parseUrgency(String(raw.urgency ?? 'QUEUE')),
    confidence: Math.min(100, Math.max(0, Number(raw.confidence ?? 50))),
    rollback_spec: rollbackSpec,
  };
}

function parseSeverity(raw: string): IncidentSeverity {
  const upper = raw.toUpperCase();
  if (upper in IncidentSeverity) return IncidentSeverity[upper as keyof typeof IncidentSeverity];
  return IncidentSeverity.MEDIUM;
}

function parseBlastRadius(raw: string): BlastRadius {
  const upper = raw.toUpperCase();
  if (upper in BlastRadius) return BlastRadius[upper as keyof typeof BlastRadius];
  return BlastRadius.MEDIUM;
}

function parseUrgency(raw: string): ActionUrgency {
  const upper = raw.toUpperCase();
  if (upper in ActionUrgency) return ActionUrgency[upper as keyof typeof ActionUrgency];
  return ActionUrgency.QUEUE;
}

function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) => Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join(''))
    .join('-');
}

// ============================================================================
// AI Reasoning Engine
// ============================================================================

/**
 * The AI Reasoning Engine.
 *
 * Receives a fully-assembled ReasoningRequest (event + environment context +
 * tool capabilities + memory) and returns a ReasoningResponse containing:
 * - Threat assessment (is this real? how severe? what MITRE technique?)
 * - Action plan (what should we do? exact AWS API calls with params)
 * - Explanation (plain English for human approvers)
 * - Reasoning trace (full chain-of-thought for audit)
 */
export class ReasoningEngine {
  private readonly invoker: BedrockInvoker;
  private readonly config: ReasoningEngineConfig;

  constructor(invoker: BedrockInvoker, config: Partial<ReasoningEngineConfig> = {}) {
    this.invoker = invoker;
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Main entry point. Routes to the appropriate reasoning mode.
   */
  async reason(request: ReasoningRequest): Promise<ReasoningResponse> {
    const prompt = this.buildPrompt(request);

    const result = await this.invoker.invoke(
      this.config.primaryModel,
      prompt,
      SYSTEM_PROMPT,
      this.config.maxTokens,
      this.config.temperature
    );

    const totalTokens = result.input_tokens + result.output_tokens;

    return parseReasoningResponse(
      result.content,
      request.id,
      request.tenant_id,
      request.mode,
      this.config.primaryModel,
      totalTokens
    );
  }

  /**
   * Builds the user-turn prompt based on reasoning mode.
   */
  private buildPrompt(request: ReasoningRequest): string {
    switch (request.mode) {
      case ReasoningMode.REACTIVE:
        if (!request.trigger_event) {
          throw new Error('REACTIVE mode requires a trigger_event');
        }
        return buildReactivePrompt(request);

      case ReasoningMode.PROACTIVE:
        return buildProactivePrompt(request);

      case ReasoningMode.PREDICTIVE:
        return buildPredictivePrompt(request);

      case ReasoningMode.INVESTIGATIVE:
        return buildInvestigativePrompt(request);

      default:
        throw new Error(`Unknown reasoning mode: ${request.mode}`);
    }
  }
}
