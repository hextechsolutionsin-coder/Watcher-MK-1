import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  WebhookIngestionHandler,
  WebhookRequest,
  TokenValidator,
  PayloadValidator,
} from './webhook-ingestion.js';
import { TelemetryNormalizer, KafkaProducer } from '../ingestion/telemetry-normalizer.js';

describe('WebhookIngestionHandler', () => {
  let mockTokenValidator: TokenValidator;
  let mockPayloadValidator: PayloadValidator;
  let mockKafkaProducer: KafkaProducer;
  let telemetryNormalizer: TelemetryNormalizer;
  let handler: WebhookIngestionHandler;

  beforeEach(() => {
    mockTokenValidator = {
      validateToken: vi.fn().mockResolvedValue(true),
    };
    mockPayloadValidator = {
      validatePayload: vi.fn().mockReturnValue({ valid: true }),
    };
    mockKafkaProducer = {
      publish: vi.fn().mockResolvedValue(undefined),
    };
    telemetryNormalizer = new TelemetryNormalizer(mockKafkaProducer);
    handler = new WebhookIngestionHandler(
      mockTokenValidator,
      mockPayloadValidator,
      telemetryNormalizer
    );
  });

  function validRequest(): WebhookRequest {
    return {
      tenant_id: 'tenant-001',
      auth_token: 'valid-token-abc',
      payload: {
        indicator_type: 'IP',
        indicator_value: '192.168.1.50',
        asset_id: 'server-web-01',
        asset_class: 'CLOUD_RESOURCE',
        event_type: 'unauthorized_access',
        source_ip: '10.0.0.5',
        attack_surface: 'CLOUD',
      },
      content_type: 'application/json',
    };
  }

  describe('Valid request → 200 with event_id', () => {
    it('should return 200 with success and event_id for a valid request', async () => {
      const request = validRequest();

      const response = await handler.handleRequest(request);

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.event_id).toBeDefined();
      expect(typeof response.body.event_id).toBe('string');
      expect(response.body.event_id!.length).toBeGreaterThan(0);
      expect(response.body.error).toBeUndefined();
    });

    it('should publish the normalized event to Kafka on success', async () => {
      const request = validRequest();

      await handler.handleRequest(request);

      expect(mockKafkaProducer.publish).toHaveBeenCalledTimes(1);
      expect(mockKafkaProducer.publish).toHaveBeenCalledWith(
        'telemetry.cloud_iam',
        expect.objectContaining({
          tenant_id: 'tenant-001',
        })
      );
    });

    it('should call token validator with correct tenant_id and token', async () => {
      const request = validRequest();

      await handler.handleRequest(request);

      expect(mockTokenValidator.validateToken).toHaveBeenCalledWith(
        'tenant-001',
        'valid-token-abc'
      );
    });

    it('should call payload validator with the request payload', async () => {
      const request = validRequest();

      await handler.handleRequest(request);

      expect(mockPayloadValidator.validatePayload).toHaveBeenCalledWith(request.payload);
    });
  });

  describe('Missing/invalid auth token → 401', () => {
    it('should return 401 when token validation fails', async () => {
      vi.mocked(mockTokenValidator.validateToken).mockResolvedValue(false);
      const request = validRequest();

      const response = await handler.handleRequest(request);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Authentication failed');
      expect(response.body.event_id).toBeUndefined();
    });

    it('should return 401 with empty auth token', async () => {
      vi.mocked(mockTokenValidator.validateToken).mockResolvedValue(false);
      const request = validRequest();
      request.auth_token = '';

      const response = await handler.handleRequest(request);

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
    });

    it('should not call payload validator when auth fails', async () => {
      vi.mocked(mockTokenValidator.validateToken).mockResolvedValue(false);
      const request = validRequest();

      await handler.handleRequest(request);

      expect(mockPayloadValidator.validatePayload).not.toHaveBeenCalled();
    });

    it('should not publish to Kafka when auth fails', async () => {
      vi.mocked(mockTokenValidator.validateToken).mockResolvedValue(false);
      const request = validRequest();

      await handler.handleRequest(request);

      expect(mockKafkaProducer.publish).not.toHaveBeenCalled();
    });
  });

  describe('Malformed payload → 400', () => {
    it('should return 400 when payload validation fails', async () => {
      vi.mocked(mockPayloadValidator.validatePayload).mockReturnValue({
        valid: false,
        errors: ['missing required field: indicator_type'],
      });
      const request = validRequest();

      const response = await handler.handleRequest(request);

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Payload validation failed');
      expect(response.body.error).toContain('missing required field: indicator_type');
      expect(response.body.event_id).toBeUndefined();
    });

    it('should return 400 with multiple validation errors', async () => {
      vi.mocked(mockPayloadValidator.validatePayload).mockReturnValue({
        valid: false,
        errors: ['missing field: indicator_type', 'invalid field: asset_class'],
      });
      const request = validRequest();

      const response = await handler.handleRequest(request);

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('missing field: indicator_type');
      expect(response.body.error).toContain('invalid field: asset_class');
    });

    it('should not publish to Kafka when payload is invalid', async () => {
      vi.mocked(mockPayloadValidator.validatePayload).mockReturnValue({
        valid: false,
        errors: ['schema mismatch'],
      });
      const request = validRequest();

      await handler.handleRequest(request);

      expect(mockKafkaProducer.publish).not.toHaveBeenCalled();
    });
  });

  describe('No partial ingestion on rejection', () => {
    it('should not ingest any data when auth token is invalid', async () => {
      vi.mocked(mockTokenValidator.validateToken).mockResolvedValue(false);
      const request = validRequest();

      await handler.handleRequest(request);

      // No Kafka publish means no data was ingested
      expect(mockKafkaProducer.publish).not.toHaveBeenCalled();
      // Payload validator should not even be called
      expect(mockPayloadValidator.validatePayload).not.toHaveBeenCalled();
    });

    it('should not ingest any data when payload is malformed', async () => {
      vi.mocked(mockPayloadValidator.validatePayload).mockReturnValue({
        valid: false,
        errors: ['invalid schema'],
      });
      const request = validRequest();

      await handler.handleRequest(request);

      // No Kafka publish means no data was ingested
      expect(mockKafkaProducer.publish).not.toHaveBeenCalled();
    });

    it('should validate auth before payload to ensure early rejection', async () => {
      const callOrder: string[] = [];
      vi.mocked(mockTokenValidator.validateToken).mockImplementation(async () => {
        callOrder.push('token');
        return false;
      });
      vi.mocked(mockPayloadValidator.validatePayload).mockImplementation(() => {
        callOrder.push('payload');
        return { valid: true };
      });

      const request = validRequest();
      await handler.handleRequest(request);

      // Token validation should happen first and payload should not be checked
      expect(callOrder).toEqual(['token']);
    });

    it('should ensure atomicity: either full ingestion or no ingestion', async () => {
      // First request: valid → should ingest
      const validReq = validRequest();
      const validResponse = await handler.handleRequest(validReq);
      expect(validResponse.status).toBe(200);
      expect(mockKafkaProducer.publish).toHaveBeenCalledTimes(1);

      // Reset mocks
      vi.mocked(mockKafkaProducer.publish).mockClear();

      // Second request: invalid payload → should NOT ingest
      vi.mocked(mockPayloadValidator.validatePayload).mockReturnValue({
        valid: false,
        errors: ['bad payload'],
      });
      const invalidReq = validRequest();
      const invalidResponse = await handler.handleRequest(invalidReq);
      expect(invalidResponse.status).toBe(400);
      expect(mockKafkaProducer.publish).not.toHaveBeenCalled();
    });
  });

  describe('Attack surface resolution', () => {
    it('should resolve attack surface from payload when specified', async () => {
      const request = validRequest();
      (request.payload as Record<string, unknown>).attack_surface = 'CLOUD_COMPUTE';

      await handler.handleRequest(request);

      expect(mockKafkaProducer.publish).toHaveBeenCalledWith(
        'telemetry.cloud_compute',
        expect.anything()
      );
    });

    it('should default to CLOUD when attack surface is not in payload', async () => {
      const request = validRequest();
      delete (request.payload as Record<string, unknown>).attack_surface;

      await handler.handleRequest(request);

      expect(mockKafkaProducer.publish).toHaveBeenCalledWith(
        'telemetry.cloud_iam',
        expect.anything()
      );
    });
  });
});
