import {
  AttackSurface,
} from '../types/index.js';

// Legacy types kept for backward compatibility with the generic normalizer
// New AWS-specific normalization is in src/ingestion/aws-normalizer.ts

export enum IndicatorType {
  IP = 'IP',
  HASH = 'HASH',
  DOMAIN = 'DOMAIN',
  USER = 'USER',
  ASSET = 'ASSET',
}

export enum AssetClass {
  ENDPOINT = 'ENDPOINT',
  IAM = 'IAM',
  CLOUD_RESOURCE = 'CLOUD_RESOURCE',
  NETWORK = 'NETWORK',
  SAAS = 'SAAS',
  CICD = 'CICD',
}

export interface TelemetryEvent {
  id: string;
  tenant_id: string;
  connector_id: string;
  attack_surface: AttackSurface;
  raw_payload: Record<string, unknown>;
  normalized_fields: NormalizedFields;
  enrichment: null;
  ingestion_timestamp: string;
}

export interface NormalizedFields {
  indicator_type: IndicatorType;
  indicator_value: string;
  asset_id: string;
  asset_class: AssetClass;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  user_id?: string;
}

/**
 * Generates a v4-style UUID without requiring Node.js crypto types.
 */
function generateId(): string {
  const hex = '0123456789abcdef';
  const segments = [8, 4, 4, 4, 12];
  return segments
    .map((len) =>
      Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join('')
    )
    .join('-');
}

// ============================================================================
// Interfaces
// ============================================================================

/**
 * Supported raw event formats.
 */
export type RawEventFormat = 'JSON' | 'CEF' | 'LEEF' | 'SYSLOG';

/**
 * A raw event received from a connector before normalization.
 */
export interface RawEvent {
  raw_payload: string | Record<string, unknown>;
  format: RawEventFormat;
  connector_id: string;
  tenant_id: string;
  attack_surface: AttackSurface;
}

/**
 * Interface for publishing messages to Kafka topics.
 */
export interface KafkaProducer {
  publish(topic: string, message: TelemetryEvent): Promise<void>;
}

// ============================================================================
// Parsers
// ============================================================================

/**
 * Parses a structured JSON payload into NormalizedFields.
 */
export function parseJsonPayload(payload: string | Record<string, unknown>): NormalizedFields {
  const data: Record<string, unknown> =
    typeof payload === 'string' ? JSON.parse(payload) : payload;

  return {
    indicator_type: toIndicatorType(data.indicator_type as string),
    indicator_value: String(data.indicator_value ?? ''),
    asset_id: String(data.asset_id ?? ''),
    asset_class: toAssetClass(data.asset_class as string),
    event_type: String(data.event_type ?? 'unknown'),
    ...(data.source_ip != null && { source_ip: String(data.source_ip) }),
    ...(data.destination_ip != null && { destination_ip: String(data.destination_ip) }),
    ...(data.user_id != null && { user_id: String(data.user_id) }),
  };
}

/**
 * Parses a CEF (Common Event Format) payload.
 * Format: CEF:0|vendor|product|version|signatureId|name|severity|extension
 */
export function parseCefPayload(payload: string): NormalizedFields {
  const raw = typeof payload === 'string' ? payload : String(payload);
  // Strip the CEF header prefix
  const cefMatch = raw.match(/^CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s);
  if (!cefMatch) {
    throw new Error(`Invalid CEF format: ${raw.substring(0, 100)}`);
  }

  const [, , , , signatureId, name, , extension] = cefMatch;

  // Parse extension key=value pairs
  const ext = parseCefExtension(extension);

  return {
    indicator_type: toIndicatorType(ext.indicatorType ?? ext.cs1 ?? 'IP'),
    indicator_value: ext.indicatorValue ?? ext.src ?? ext.dst ?? signatureId,
    asset_id: ext.assetId ?? ext.dhost ?? ext.dvc ?? '',
    asset_class: toAssetClass(ext.assetClass ?? ext.cs2 ?? 'ENDPOINT'),
    event_type: ext.eventType ?? name ?? 'unknown',
    ...(ext.src && { source_ip: ext.src }),
    ...(ext.dst && { destination_ip: ext.dst }),
    ...(ext.suser && { user_id: ext.suser }),
  };
}

/**
 * Parses CEF extension key=value pairs.
 */
function parseCefExtension(extension: string): Record<string, string> {
  const result: Record<string, string> = {};
  // CEF extensions are space-separated key=value pairs
  // Values can contain spaces if they are the last value before the next key=
  const regex = /(\w+)=((?:[^ =]| (?!\w+=))*)/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(extension)) !== null) {
    result[match[1]] = match[2].trim();
  }
  return result;
}

/**
 * Parses a LEEF (Log Event Extended Format) payload.
 * Format: LEEF:version|vendor|product|version|eventId|extension
 */
export function parseLeefPayload(payload: string): NormalizedFields {
  const raw = typeof payload === 'string' ? payload : String(payload);
  const leefMatch = raw.match(/^LEEF:([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s);
  if (!leefMatch) {
    throw new Error(`Invalid LEEF format: ${raw.substring(0, 100)}`);
  }

  const [, , , , , eventId, extension] = leefMatch;

  // Parse extension — LEEF uses tab-separated or key=value pairs
  const ext = parseLeefExtension(extension);

  return {
    indicator_type: toIndicatorType(ext.indicatorType ?? ext.cat ?? 'IP'),
    indicator_value: ext.indicatorValue ?? ext.src ?? ext.dst ?? eventId,
    asset_id: ext.assetId ?? ext.devName ?? ext.identHostName ?? '',
    asset_class: toAssetClass(ext.assetClass ?? 'ENDPOINT'),
    event_type: ext.eventType ?? ext.cat ?? 'unknown',
    ...(ext.src && { source_ip: ext.src }),
    ...(ext.dst && { destination_ip: ext.dst }),
    ...(ext.usrName && { user_id: ext.usrName }),
  };
}

/**
 * Parses LEEF extension key=value pairs (tab-separated).
 */
function parseLeefExtension(extension: string): Record<string, string> {
  const result: Record<string, string> = {};
  // LEEF 2.0 uses a configurable delimiter (default tab), LEEF 1.0 uses tab
  const delimiter = extension.includes('\t') ? '\t' : '\t';
  const pairs = extension.split(delimiter);
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx > 0) {
      const key = pair.substring(0, eqIdx).trim();
      const value = pair.substring(eqIdx + 1).trim();
      result[key] = value;
    }
  }
  return result;
}

/**
 * Parses an RFC 5424 syslog message.
 * Format: <priority>version timestamp hostname app-name procid msgid structured-data msg
 */
export function parseSyslogPayload(payload: string): NormalizedFields {
  const raw = typeof payload === 'string' ? payload : String(payload);

  // RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
  const syslogMatch = raw.match(
    /^<(\d+)>(\d+)?\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*((?:\[.*?\])*)\s*(.*)/s
  );

  let hostname = '';
  let appName = '';
  let message = '';

  if (syslogMatch) {
    [, , , , hostname, appName, , , , message] = syslogMatch;
  } else {
    // Fallback: try BSD syslog format <PRI>TIMESTAMP HOSTNAME MSG
    const bsdMatch = raw.match(/^<(\d+)>(.+)/s);
    if (bsdMatch) {
      message = bsdMatch[2];
      // Try to extract hostname from message
      const parts = message.trim().split(/\s+/);
      if (parts.length > 2) {
        hostname = parts[1] ?? '';
      }
    } else {
      message = raw;
    }
  }

  // Extract fields from the message body
  const sourceIp = extractIp(message, 'src') ?? extractFirstIp(message);
  const destIp = extractIp(message, 'dst') ?? extractSecondIp(message, sourceIp);
  const userId = extractField(message, 'user') ?? extractField(message, 'uid');

  return {
    indicator_type: sourceIp ? IndicatorType.IP : IndicatorType.ASSET,
    indicator_value: sourceIp ?? hostname ?? '',
    asset_id: hostname || appName || '',
    asset_class: AssetClass.NETWORK,
    event_type: extractField(message, 'event') ?? appName ?? 'syslog',
    ...(sourceIp && { source_ip: sourceIp }),
    ...(destIp && { destination_ip: destIp }),
    ...(userId && { user_id: userId }),
  };
}

// ============================================================================
// Helper functions
// ============================================================================

function extractIp(text: string, prefix: string): string | undefined {
  const regex = new RegExp(`${prefix}[=:]\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})`);
  const match = text.match(regex);
  return match?.[1];
}

function extractFirstIp(text: string): string | undefined {
  const match = text.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  return match?.[1];
}

function extractSecondIp(text: string, firstIp: string | undefined): string | undefined {
  if (!firstIp) return undefined;
  const regex = new RegExp(`(?:${firstIp.replace(/\./g, '\\.')}.*?)(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})`);
  const match = text.match(regex);
  return match?.[1];
}

function extractField(text: string, fieldName: string): string | undefined {
  const regex = new RegExp(`${fieldName}[=:]\\s*(\\S+)`);
  const match = text.match(regex);
  return match?.[1];
}

/**
 * Maps a string to an IndicatorType enum value.
 */
function toIndicatorType(value: string | undefined | null): IndicatorType {
  if (!value) return IndicatorType.IP;
  const upper = value.toUpperCase();
  if (upper in IndicatorType) {
    return IndicatorType[upper as keyof typeof IndicatorType];
  }
  return IndicatorType.IP;
}

/**
 * Maps a string to an AssetClass enum value.
 */
function toAssetClass(value: string | undefined | null): AssetClass {
  if (!value) return AssetClass.ENDPOINT;
  const upper = value.toUpperCase().replace(/[- ]/g, '_');
  if (upper in AssetClass) {
    return AssetClass[upper as keyof typeof AssetClass];
  }
  return AssetClass.ENDPOINT;
}

// ============================================================================
// TelemetryNormalizer
// ============================================================================

/**
 * The TelemetryNormalizer service converts raw events from connectors into
 * canonical TelemetryEvent records and publishes them to Kafka.
 */
export class TelemetryNormalizer {
  private readonly kafkaProducer: KafkaProducer;

  constructor(kafkaProducer: KafkaProducer) {
    this.kafkaProducer = kafkaProducer;
  }

  /**
   * Normalizes a raw event and publishes it to the appropriate Kafka topic.
   * Returns the normalized TelemetryEvent.
   */
  async normalize(rawEvent: RawEvent): Promise<TelemetryEvent> {
    // Step 1: Parse raw payload based on format
    const normalizedFields = this.parsePayload(rawEvent);

    // Step 2 & 3: Build the TelemetryEvent with stamped metadata
    const telemetryEvent: TelemetryEvent = {
      id: generateId(),
      tenant_id: rawEvent.tenant_id,
      connector_id: rawEvent.connector_id,
      attack_surface: rawEvent.attack_surface,
      raw_payload: this.toRawPayloadRecord(rawEvent.raw_payload),
      normalized_fields: normalizedFields,
      enrichment: null, // Enrichment is handled separately (deferred if TIL unavailable)
      ingestion_timestamp: new Date().toISOString(),
    };

    // Step 4: Publish to the appropriate Kafka topic
    const topic = `telemetry.${rawEvent.attack_surface.toLowerCase()}`;
    await this.kafkaProducer.publish(topic, telemetryEvent);

    return telemetryEvent;
  }

  /**
   * Parses the raw payload based on the event format.
   */
  private parsePayload(rawEvent: RawEvent): NormalizedFields {
    switch (rawEvent.format) {
      case 'JSON':
        return parseJsonPayload(rawEvent.raw_payload);
      case 'CEF':
        return parseCefPayload(
          typeof rawEvent.raw_payload === 'string'
            ? rawEvent.raw_payload
            : JSON.stringify(rawEvent.raw_payload)
        );
      case 'LEEF':
        return parseLeefPayload(
          typeof rawEvent.raw_payload === 'string'
            ? rawEvent.raw_payload
            : JSON.stringify(rawEvent.raw_payload)
        );
      case 'SYSLOG':
        return parseSyslogPayload(
          typeof rawEvent.raw_payload === 'string'
            ? rawEvent.raw_payload
            : JSON.stringify(rawEvent.raw_payload)
        );
      default:
        throw new Error(`Unsupported event format: ${rawEvent.format}`);
    }
  }

  /**
   * Converts the raw payload to a Record for storage.
   */
  private toRawPayloadRecord(payload: string | Record<string, unknown>): Record<string, unknown> {
    if (typeof payload === 'string') {
      try {
        return JSON.parse(payload) as Record<string, unknown>;
      } catch {
        return { raw: payload };
      }
    }
    return payload;
  }
}
