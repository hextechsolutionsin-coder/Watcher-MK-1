import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  TelemetryNormalizer,
  RawEvent,
  KafkaProducer,
  parseJsonPayload,
  parseCefPayload,
  parseLeefPayload,
  parseSyslogPayload,
  IndicatorType,
  AssetClass,
  TelemetryEvent,
} from './telemetry-normalizer.js';
import { AttackSurface } from '../types/index.js';

describe('TelemetryNormalizer', () => {
  let mockKafkaProducer: KafkaProducer;
  let normalizer: TelemetryNormalizer;

  beforeEach(() => {
    mockKafkaProducer = { publish: vi.fn().mockResolvedValue(undefined) };
    normalizer = new TelemetryNormalizer(mockKafkaProducer);
  });

  describe('parseJsonPayload', () => {
    it('should parse a JSON string payload into NormalizedFields', () => {
      const payload = JSON.stringify({
        indicator_type: 'IP',
        indicator_value: '192.168.1.100',
        asset_id: 'server-01',
        asset_class: 'ENDPOINT',
        event_type: 'malware_detected',
        source_ip: '10.0.0.1',
        destination_ip: '192.168.1.100',
        user_id: 'user-42',
      });

      const result = parseJsonPayload(payload);

      expect(result.indicator_type).toBe(IndicatorType.IP);
      expect(result.indicator_value).toBe('192.168.1.100');
      expect(result.asset_id).toBe('server-01');
      expect(result.asset_class).toBe(AssetClass.ENDPOINT);
      expect(result.event_type).toBe('malware_detected');
      expect(result.source_ip).toBe('10.0.0.1');
      expect(result.destination_ip).toBe('192.168.1.100');
      expect(result.user_id).toBe('user-42');
    });

    it('should parse a Record payload directly', () => {
      const payload = {
        indicator_type: 'HASH',
        indicator_value: 'abc123def456',
        asset_id: 'workstation-05',
        asset_class: 'ENDPOINT',
        event_type: 'file_hash_match',
      };

      const result = parseJsonPayload(payload);

      expect(result.indicator_type).toBe(IndicatorType.HASH);
      expect(result.indicator_value).toBe('abc123def456');
      expect(result.source_ip).toBeUndefined();
    });

    it('should default indicator_type to IP when not recognized', () => {
      const payload = {
        indicator_type: 'UNKNOWN_TYPE',
        indicator_value: 'some-value',
        asset_id: 'asset-1',
        asset_class: 'ENDPOINT',
        event_type: 'test',
      };

      const result = parseJsonPayload(payload);
      expect(result.indicator_type).toBe(IndicatorType.IP);
    });
  });

  describe('parseCefPayload', () => {
    it('should parse a valid CEF payload', () => {
      const payload =
        'CEF:0|SecurityVendor|SecurityProduct|1.0|100|Malware Detected|9|src=10.0.0.1 dst=192.168.1.50 suser=admin indicatorType=IP indicatorValue=10.0.0.1 assetId=host-01 assetClass=ENDPOINT';

      const result = parseCefPayload(payload);

      expect(result.indicator_type).toBe(IndicatorType.IP);
      expect(result.indicator_value).toBe('10.0.0.1');
      expect(result.asset_id).toBe('host-01');
      expect(result.asset_class).toBe(AssetClass.ENDPOINT);
      expect(result.event_type).toBe('Malware Detected');
      expect(result.source_ip).toBe('10.0.0.1');
      expect(result.destination_ip).toBe('192.168.1.50');
      expect(result.user_id).toBe('admin');
    });

    it('should throw on invalid CEF format', () => {
      expect(() => parseCefPayload('not a CEF message')).toThrow('Invalid CEF format');
    });
  });

  describe('parseLeefPayload', () => {
    it('should parse a valid LEEF payload', () => {
      const payload =
        'LEEF:2.0|SecurityVendor|SecurityProduct|1.0|EventId123|src=10.0.0.5\tdst=192.168.1.10\tusrName=jdoe\tindicatorType=DOMAIN\tindicatorValue=evil.com\tassetId=proxy-01\tassetClass=NETWORK\teventType=dns_query';

      const result = parseLeefPayload(payload);

      expect(result.indicator_type).toBe(IndicatorType.DOMAIN);
      expect(result.indicator_value).toBe('evil.com');
      expect(result.event_type).toBe('dns_query');
    });

    it('should throw on invalid LEEF format', () => {
      expect(() => parseLeefPayload('not a LEEF message')).toThrow('Invalid LEEF format');
    });
  });

  describe('parseSyslogPayload', () => {
    it('should parse an RFC 5424 syslog message', () => {
      const payload =
        '<134>1 2024-01-15T10:30:00Z firewall-01 sshd 1234 ID47 - Failed login from src=192.168.1.100 dst=10.0.0.1 user=root event=auth_failure';

      const result = parseSyslogPayload(payload);

      expect(result.indicator_type).toBe(IndicatorType.IP);
      expect(result.indicator_value).toBe('192.168.1.100');
      expect(result.asset_class).toBe(AssetClass.NETWORK);
    });
  });

  describe('normalize', () => {
    it('should produce a TelemetryEvent with all required fields stamped', async () => {
      const rawEvent: RawEvent = {
        raw_payload: JSON.stringify({
          indicator_type: 'IP',
          indicator_value: '10.0.0.1',
          asset_id: 'server-01',
          asset_class: 'CLOUD_RESOURCE',
          event_type: 'unauthorized_access',
          source_ip: '10.0.0.1',
        }),
        format: 'JSON',
        connector_id: 'conn-abc',
        tenant_id: 'tenant-123',
        attack_surface: AttackSurface.CLOUD_IAM,
      };

      const result = await normalizer.normalize(rawEvent);

      expect(result.tenant_id).toBe('tenant-123');
      expect(result.connector_id).toBe('conn-abc');
      expect(result.ingestion_timestamp).toBeDefined();
      expect(new Date(result.ingestion_timestamp).getTime()).not.toBeNaN();
      expect(result.normalized_fields.indicator_type).toBe(IndicatorType.IP);
      expect(result.id).toBeDefined();
      expect(result.enrichment).toBeNull();
    });

    it('should publish to the correct topic based on attack surface', async () => {
      const rawEvent: RawEvent = {
        raw_payload: {
          indicator_type: 'IP',
          indicator_value: '10.0.0.1',
          asset_id: 'a1',
          asset_class: 'CLOUD_RESOURCE',
          event_type: 'test',
        },
        format: 'JSON',
        connector_id: 'conn-xyz',
        tenant_id: 'tenant-456',
        attack_surface: AttackSurface.CLOUD_COMPUTE,
      };

      await normalizer.normalize(rawEvent);

      expect(mockKafkaProducer.publish).toHaveBeenCalledWith(
        'telemetry.cloud_compute',
        expect.objectContaining({ tenant_id: 'tenant-456' })
      );
    });

    it('should generate unique IDs for each normalized event', async () => {
      const rawEvent: RawEvent = {
        raw_payload: { indicator_type: 'IP', indicator_value: '1.1.1.1', asset_id: 'a1', asset_class: 'ENDPOINT', event_type: 'test' },
        format: 'JSON',
        connector_id: 'c1',
        tenant_id: 't1',
        attack_surface: AttackSurface.CLOUD_IAM,
      };

      const result1 = await normalizer.normalize(rawEvent);
      const result2 = await normalizer.normalize(rawEvent);

      expect(result1.id).not.toBe(result2.id);
    });
  });
});
