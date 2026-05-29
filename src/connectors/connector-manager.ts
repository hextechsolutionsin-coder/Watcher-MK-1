/** Simple alert service interface — implementations can write to Slack, PagerDuty, etc. */
export interface AlertService {
  raiseAlert(tenantId: string, alertType: string, message: string): Promise<void>;
}

// ============================================================================
// Interfaces
// ============================================================================

/**
 * Connector status lifecycle.
 */
export type ConnectorStatus = 'ACTIVE' | 'INACTIVE' | 'FAILED' | 'CREDENTIAL_EXPIRED';

/**
 * A registered connector integration.
 * Requirement 1.2, 6.1: Connector lifecycle management.
 */
export interface Connector {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  platform: string;
  status: ConnectorStatus;
  config: Record<string, unknown>;
  last_ingestion_at: string | null;
  created_at: string;
}

/**
 * Configuration provided when registering a new connector.
 */
export interface ConnectorConfig {
  name: string;
  type: string;
  platform: string;
  config: Record<string, unknown>;
}

/**
 * Persistence interface for connector records.
 */
export interface ConnectorStore {
  register(connector: Connector): Promise<void>;
  remove(connectorId: string, tenantId: string): Promise<void>;
  getById(connectorId: string, tenantId: string): Promise<Connector | null>;
  getByTenantId(tenantId: string): Promise<Connector[]>;
  updateStatus(connectorId: string, tenantId: string, status: ConnectorStatus): Promise<void>;
  updateLastIngestion(connectorId: string, tenantId: string, timestamp: string): Promise<void>;
  getAllActive(): Promise<Connector[]>;
}

/**
 * Interface for authenticating connector credentials.
 */
export interface ConnectorAuthenticator {
  authenticate(connector: Connector): Promise<boolean>;
  isCredentialExpired(connector: Connector): Promise<boolean>;
  healthCheck(connector: Connector): Promise<{ healthy: boolean; latencyMs: number }>;
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Generates a v4-style UUID.
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
// ConnectorManager
// ============================================================================

/**
 * Manages the lifecycle of connectors: registration, removal, health monitoring,
 * heartbeat checks, and credential expiry detection.
 *
 * Validates Requirements:
 * - 1.2: Begin ingesting telemetry within 5 minutes of successful authentication.
 * - 1.5: Raise Informational alert when telemetry gap >= 60 seconds.
 * - 6.1: Provide connectors for SIEM, EDR, XDR, cloud, SOAR, ticketing, notification.
 * - 6.2: Test event verification within 30 seconds.
 * - 6.8: Alert Tenant Administrator within 5 minutes of credential expiry.
 */
export class ConnectorManager {
  private readonly store: ConnectorStore;
  private readonly authenticator: ConnectorAuthenticator;
  private readonly alertService: AlertService;

  /** Telemetry gap threshold in milliseconds (60 seconds). */
  private static readonly HEARTBEAT_THRESHOLD_MS = 60_000;

  constructor(
    store: ConnectorStore,
    authenticator: ConnectorAuthenticator,
    alertService: AlertService
  ) {
    this.store = store;
    this.authenticator = authenticator;
    this.alertService = alertService;
  }

  /**
   * Registers a new connector for a tenant.
   * Authenticates, performs a health check, and marks as ACTIVE.
   * Requirement 1.2: Begin ingestion within 5 minutes of successful auth.
   */
  async registerConnector(tenantId: string, connectorConfig: ConnectorConfig): Promise<Connector> {
    const connector: Connector = {
      id: generateId(),
      tenant_id: tenantId,
      name: connectorConfig.name,
      type: connectorConfig.type,
      platform: connectorConfig.platform,
      status: 'INACTIVE',
      config: connectorConfig.config,
      last_ingestion_at: null,
      created_at: new Date().toISOString(),
    };

    // Authenticate the connector credentials
    const authenticated = await this.authenticator.authenticate(connector);
    if (!authenticated) {
      connector.status = 'FAILED';
      await this.store.register(connector);
      return connector;
    }

    // Perform health check
    const healthResult = await this.authenticator.healthCheck(connector);
    if (!healthResult.healthy) {
      connector.status = 'FAILED';
      await this.store.register(connector);
      return connector;
    }

    // Mark as active — telemetry ingestion begins
    connector.status = 'ACTIVE';
    await this.store.register(connector);

    return connector;
  }

  /**
   * Removes a connector for a tenant.
   */
  async removeConnector(connectorId: string, tenantId: string): Promise<void> {
    await this.store.remove(connectorId, tenantId);
  }

  /**
   * Returns the current status of a connector.
   */
  async getConnectorStatus(connectorId: string, tenantId: string): Promise<Connector | null> {
    return this.store.getById(connectorId, tenantId);
  }

  /**
   * Tests a connector by performing a health check.
   * Requirement 6.2: Send test event and verify receipt within 30 seconds.
   */
  async testConnector(
    connectorId: string,
    tenantId: string
  ): Promise<{ success: boolean; latencyMs: number }> {
    const connector = await this.store.getById(connectorId, tenantId);
    if (!connector) {
      return { success: false, latencyMs: 0 };
    }

    const result = await this.authenticator.healthCheck(connector);
    return { success: result.healthy, latencyMs: result.latencyMs };
  }

  /**
   * Checks all active connectors for telemetry gaps >= 60 seconds.
   * Raises an Informational alert when a gap is detected.
   * Requirement 1.5: Raise Informational alert for telemetry gap >= 60s.
   */
  async checkHeartbeats(): Promise<void> {
    const activeConnectors = await this.store.getAllActive();
    const now = Date.now();

    for (const connector of activeConnectors) {
      if (!connector.last_ingestion_at) {
        // If never ingested and connector has been active for >= threshold
        const createdAt = new Date(connector.created_at).getTime();
        if (now - createdAt >= ConnectorManager.HEARTBEAT_THRESHOLD_MS) {
          await this.alertService.raiseAlert(
            connector.tenant_id,
            'TELEMETRY_GAP',
            `Connector "${connector.name}" (${connector.id}) has not delivered telemetry. Last successful ingestion: never. Gap detected at ${new Date(now).toISOString()}.`
          );
        }
        continue;
      }

      const lastIngestion = new Date(connector.last_ingestion_at).getTime();
      const gap = now - lastIngestion;

      if (gap >= ConnectorManager.HEARTBEAT_THRESHOLD_MS) {
        await this.alertService.raiseAlert(
          connector.tenant_id,
          'TELEMETRY_GAP',
          `Connector "${connector.name}" (${connector.id}) telemetry gap detected. Last successful ingestion: ${connector.last_ingestion_at}. Gap: ${Math.round(gap / 1000)}s.`
        );
      }
    }
  }

  /**
   * Checks all active connectors for expired credentials.
   * Alerts the Tenant Administrator within 5 minutes of detection.
   * Requirement 6.8: Alert Tenant Administrator within 5 minutes of credential expiry.
   */
  async checkCredentialExpiry(): Promise<void> {
    const activeConnectors = await this.store.getAllActive();

    for (const connector of activeConnectors) {
      const expired = await this.authenticator.isCredentialExpired(connector);

      if (expired) {
        // Update connector status to CREDENTIAL_EXPIRED
        await this.store.updateStatus(connector.id, connector.tenant_id, 'CREDENTIAL_EXPIRED');

        // Alert the Tenant Administrator
        await this.alertService.raiseAlert(
          connector.tenant_id,
          'CREDENTIAL_EXPIRED',
          `Connector "${connector.name}" (${connector.id}) credentials have expired. Data ingestion is suspended until credentials are renewed.`
        );
      }
    }
  }
}
