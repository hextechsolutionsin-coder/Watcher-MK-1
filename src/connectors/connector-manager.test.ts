import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ConnectorManager,
  ConnectorStore,
  ConnectorAuthenticator,
  Connector,
  ConnectorConfig,
  ConnectorStatus,
  AlertService,
} from './connector-manager.js';

// ============================================================================
// Test Helpers
// ============================================================================

function createMockStore(): ConnectorStore {
  const connectors: Map<string, Connector> = new Map();

  return {
    register: vi.fn(async (connector: Connector) => {
      connectors.set(`${connector.tenant_id}:${connector.id}`, connector);
    }),
    remove: vi.fn(async (connectorId: string, tenantId: string) => {
      connectors.delete(`${tenantId}:${connectorId}`);
    }),
    getById: vi.fn(async (connectorId: string, tenantId: string) => {
      return connectors.get(`${tenantId}:${connectorId}`) ?? null;
    }),
    getByTenantId: vi.fn(async (tenantId: string) => {
      return Array.from(connectors.values()).filter((c) => c.tenant_id === tenantId);
    }),
    updateStatus: vi.fn(async (connectorId: string, tenantId: string, status: ConnectorStatus) => {
      const key = `${tenantId}:${connectorId}`;
      const connector = connectors.get(key);
      if (connector) {
        connector.status = status;
        connectors.set(key, connector);
      }
    }),
    updateLastIngestion: vi.fn(async (connectorId: string, tenantId: string, timestamp: string) => {
      const key = `${tenantId}:${connectorId}`;
      const connector = connectors.get(key);
      if (connector) {
        connector.last_ingestion_at = timestamp;
        connectors.set(key, connector);
      }
    }),
    getAllActive: vi.fn(async () => {
      return Array.from(connectors.values()).filter((c) => c.status === 'ACTIVE');
    }),
  };
}

function createMockAuthenticator(options?: {
  authenticated?: boolean;
  healthy?: boolean;
  latencyMs?: number;
  expired?: boolean;
}): ConnectorAuthenticator {
  const { authenticated = true, healthy = true, latencyMs = 50, expired = false } = options ?? {};
  return {
    authenticate: vi.fn(async () => authenticated),
    isCredentialExpired: vi.fn(async () => expired),
    healthCheck: vi.fn(async () => ({ healthy, latencyMs })),
  };
}

function createMockAlertService(): AlertService {
  return {
    raiseAlert: vi.fn(async () => {}),
  };
}

function createConnectorConfig(overrides?: Partial<ConnectorConfig>): ConnectorConfig {
  return {
    name: 'Test SIEM Connector',
    type: 'SIEM',
    platform: 'Splunk',
    config: { host: 'splunk.example.com', token: 'abc123' },
    ...overrides,
  };
}

// ============================================================================
// Tests
// ============================================================================

describe('ConnectorManager', () => {
  let store: ConnectorStore;
  let authenticator: ConnectorAuthenticator;
  let alertService: AlertService;
  let manager: ConnectorManager;

  beforeEach(() => {
    store = createMockStore();
    authenticator = createMockAuthenticator();
    alertService = createMockAlertService();
    manager = new ConnectorManager(store, authenticator, alertService);
  });

  describe('registerConnector', () => {
    it('should register a connector with ACTIVE status on successful auth and health check', async () => {
      const config = createConnectorConfig();
      const result = await manager.registerConnector('tenant-1', config);

      expect(result.status).toBe('ACTIVE');
      expect(result.tenant_id).toBe('tenant-1');
      expect(result.name).toBe('Test SIEM Connector');
      expect(result.type).toBe('SIEM');
      expect(result.platform).toBe('Splunk');
      expect(result.id).toBeDefined();
      expect(result.created_at).toBeDefined();
      expect(result.last_ingestion_at).toBeNull();
      expect(store.register).toHaveBeenCalledOnce();
    });

    it('should register with FAILED status when authentication fails', async () => {
      authenticator = createMockAuthenticator({ authenticated: false });
      manager = new ConnectorManager(store, authenticator, alertService);

      const config = createConnectorConfig();
      const result = await manager.registerConnector('tenant-1', config);

      expect(result.status).toBe('FAILED');
      expect(store.register).toHaveBeenCalledOnce();
    });

    it('should register with FAILED status when health check fails', async () => {
      authenticator = createMockAuthenticator({ healthy: false });
      manager = new ConnectorManager(store, authenticator, alertService);

      const config = createConnectorConfig();
      const result = await manager.registerConnector('tenant-1', config);

      expect(result.status).toBe('FAILED');
      expect(store.register).toHaveBeenCalledOnce();
    });

    it('should store the connector config correctly', async () => {
      const config = createConnectorConfig({
        config: { host: 'sentinel.azure.com', clientId: 'xyz' },
      });
      const result = await manager.registerConnector('tenant-2', config);

      expect(result.config).toEqual({ host: 'sentinel.azure.com', clientId: 'xyz' });
    });
  });

  describe('removeConnector', () => {
    it('should delegate removal to the store', async () => {
      await manager.removeConnector('conn-1', 'tenant-1');

      expect(store.remove).toHaveBeenCalledWith('conn-1', 'tenant-1');
    });
  });

  describe('getConnectorStatus', () => {
    it('should return the connector when it exists', async () => {
      const config = createConnectorConfig();
      const registered = await manager.registerConnector('tenant-1', config);

      const result = await manager.getConnectorStatus(registered.id, 'tenant-1');

      expect(result).not.toBeNull();
      expect(result!.id).toBe(registered.id);
      expect(result!.status).toBe('ACTIVE');
    });

    it('should return null when connector does not exist', async () => {
      const result = await manager.getConnectorStatus('nonexistent', 'tenant-1');

      expect(result).toBeNull();
    });
  });

  describe('testConnector', () => {
    it('should return success and latency when health check passes', async () => {
      const config = createConnectorConfig();
      const registered = await manager.registerConnector('tenant-1', config);

      const result = await manager.testConnector(registered.id, 'tenant-1');

      expect(result.success).toBe(true);
      expect(result.latencyMs).toBe(50);
    });

    it('should return failure when connector does not exist', async () => {
      const result = await manager.testConnector('nonexistent', 'tenant-1');

      expect(result.success).toBe(false);
      expect(result.latencyMs).toBe(0);
    });

    it('should return failure when health check fails', async () => {
      // Register with healthy authenticator first
      const config = createConnectorConfig();
      const registered = await manager.registerConnector('tenant-1', config);

      // Switch to unhealthy authenticator for the test
      authenticator = createMockAuthenticator({ healthy: false, latencyMs: 200 });
      manager = new ConnectorManager(store, authenticator, alertService);

      const result = await manager.testConnector(registered.id, 'tenant-1');

      expect(result.success).toBe(false);
      expect(result.latencyMs).toBe(200);
    });
  });

  describe('checkHeartbeats', () => {
    it('should raise alert when telemetry gap >= 60 seconds', async () => {
      // Register a connector
      const config = createConnectorConfig();
      const registered = await manager.registerConnector('tenant-1', config);

      // Simulate last ingestion 90 seconds ago
      const ninetySecondsAgo = new Date(Date.now() - 90_000).toISOString();
      await store.updateLastIngestion(registered.id, 'tenant-1', ninetySecondsAgo);

      await manager.checkHeartbeats();

      expect(alertService.raiseAlert).toHaveBeenCalledWith(
        'tenant-1',
        'TELEMETRY_GAP',
        expect.stringContaining('telemetry gap detected')
      );
    });

    it('should not raise alert when telemetry gap < 60 seconds', async () => {
      const config = createConnectorConfig();
      const registered = await manager.registerConnector('tenant-1', config);

      // Simulate last ingestion 30 seconds ago
      const thirtySecondsAgo = new Date(Date.now() - 30_000).toISOString();
      await store.updateLastIngestion(registered.id, 'tenant-1', thirtySecondsAgo);

      await manager.checkHeartbeats();

      expect(alertService.raiseAlert).not.toHaveBeenCalled();
    });

    it('should raise alert for connector that never ingested and is old enough', async () => {
      // Create a connector with a created_at timestamp 120 seconds ago
      const connector: Connector = {
        id: 'old-conn',
        tenant_id: 'tenant-1',
        name: 'Old Connector',
        type: 'EDR',
        platform: 'CrowdStrike',
        status: 'ACTIVE',
        config: {},
        last_ingestion_at: null,
        created_at: new Date(Date.now() - 120_000).toISOString(),
      };
      await store.register(connector);

      await manager.checkHeartbeats();

      expect(alertService.raiseAlert).toHaveBeenCalledWith(
        'tenant-1',
        'TELEMETRY_GAP',
        expect.stringContaining('has not delivered telemetry')
      );
    });

    it('should not raise alert for newly created connector with no ingestion', async () => {
      // Create a connector with a created_at timestamp just now
      const connector: Connector = {
        id: 'new-conn',
        tenant_id: 'tenant-1',
        name: 'New Connector',
        type: 'EDR',
        platform: 'CrowdStrike',
        status: 'ACTIVE',
        config: {},
        last_ingestion_at: null,
        created_at: new Date().toISOString(),
      };
      await store.register(connector);

      await manager.checkHeartbeats();

      expect(alertService.raiseAlert).not.toHaveBeenCalled();
    });
  });

  describe('checkCredentialExpiry', () => {
    it('should update status and alert when credentials are expired', async () => {
      authenticator = createMockAuthenticator({ expired: true });
      manager = new ConnectorManager(store, authenticator, alertService);

      const config = createConnectorConfig();
      // Need to register with a working authenticator first
      const workingAuth = createMockAuthenticator({ expired: false });
      const setupManager = new ConnectorManager(store, workingAuth, alertService);
      const registered = await setupManager.registerConnector('tenant-1', config);

      // Now check with the expired authenticator
      await manager.checkCredentialExpiry();

      expect(store.updateStatus).toHaveBeenCalledWith(
        registered.id,
        'tenant-1',
        'CREDENTIAL_EXPIRED'
      );
      expect(alertService.raiseAlert).toHaveBeenCalledWith(
        'tenant-1',
        'CREDENTIAL_EXPIRED',
        expect.stringContaining('credentials have expired')
      );
    });

    it('should not alert when credentials are valid', async () => {
      authenticator = createMockAuthenticator({ expired: false });
      manager = new ConnectorManager(store, authenticator, alertService);

      const config = createConnectorConfig();
      await manager.registerConnector('tenant-1', config);

      await manager.checkCredentialExpiry();

      expect(alertService.raiseAlert).not.toHaveBeenCalled();
    });

    it('should handle multiple connectors with mixed credential states', async () => {
      // Register two connectors
      const config1 = createConnectorConfig({ name: 'Connector A' });
      const config2 = createConnectorConfig({ name: 'Connector B' });
      await manager.registerConnector('tenant-1', config1);
      await manager.registerConnector('tenant-1', config2);

      // Set up authenticator that reports expired for all
      authenticator = createMockAuthenticator({ expired: true });
      manager = new ConnectorManager(store, authenticator, alertService);

      await manager.checkCredentialExpiry();

      // Should alert for both connectors
      expect(alertService.raiseAlert).toHaveBeenCalledTimes(2);
    });
  });
});
