import { TelemetryNormalizer, RawEvent } from '../ingestion/telemetry-normalizer.js';
import { AttackSurface } from '../types/index.js';

export interface WebhookRequest {
  tenant_id: string;
  auth_token: string;
  payload: unknown;
  content_type: string;
}

export interface WebhookResponse {
  status: number;
  body: { success: boolean; error?: string; event_id?: string };
}

export interface TokenValidator {
  validateToken(tenantId: string, token: string): Promise<boolean>;
}

export interface PayloadValidator {
  validatePayload(payload: unknown): { valid: boolean; errors?: string[] };
}

/**
 * Handles incoming webhook requests.
 * Validates auth + payload before ingesting. Atomic — no partial ingestion on failure.
 */
export class WebhookIngestionHandler {
  private readonly tokenValidator: TokenValidator;
  private readonly payloadValidator: PayloadValidator;
  private readonly telemetryNormalizer: TelemetryNormalizer;

  constructor(
    tokenValidator: TokenValidator,
    payloadValidator: PayloadValidator,
    telemetryNormalizer: TelemetryNormalizer
  ) {
    this.tokenValidator = tokenValidator;
    this.payloadValidator = payloadValidator;
    this.telemetryNormalizer = telemetryNormalizer;
  }

  async handleRequest(request: WebhookRequest): Promise<WebhookResponse> {
    const isAuthenticated = await this.tokenValidator.validateToken(
      request.tenant_id,
      request.auth_token
    );
    if (!isAuthenticated) {
      return { status: 401, body: { success: false, error: 'Authentication failed: invalid or missing token' } };
    }

    const validationResult = this.payloadValidator.validatePayload(request.payload);
    if (!validationResult.valid) {
      return {
        status: 400,
        body: { success: false, error: `Payload validation failed: ${validationResult.errors?.join('; ') ?? 'unknown error'}` },
      };
    }

    const rawEvent: RawEvent = {
      raw_payload: request.payload as string | Record<string, unknown>,
      format: 'JSON',
      connector_id: `webhook-${request.tenant_id}`,
      tenant_id: request.tenant_id,
      attack_surface: this.resolveAttackSurface(request.payload),
    };

    const telemetryEvent = await this.telemetryNormalizer.normalize(rawEvent);
    return { status: 200, body: { success: true, event_id: telemetryEvent.id } };
  }

  private resolveAttackSurface(payload: unknown): AttackSurface {
    if (payload !== null && typeof payload === 'object' && 'attack_surface' in (payload as Record<string, unknown>)) {
      const surface = String((payload as Record<string, unknown>).attack_surface).toUpperCase();
      if (surface in AttackSurface) {
        return AttackSurface[surface as keyof typeof AttackSurface];
      }
    }
    return AttackSurface.CLOUD_IAM;
  }
}
