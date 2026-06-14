import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MemoryLayer } from './memory-layer.js';
import { MemoryLayerConfig } from './memory-layer-config.js';

// Shared mock functions that all mock instances will use
const mockSearchMemories = vi.fn();
const mockAdd = vi.fn();

vi.mock('supermemory', () => {
  const MockSupermemory = vi.fn().mockImplementation(() => ({
    search: { memories: mockSearchMemories },
    add: mockAdd,
  }));
  return { default: MockSupermemory, Supermemory: MockSupermemory };
});

function createTestConfig(overrides?: Partial<MemoryLayerConfig>): MemoryLayerConfig {
  return {
    baseUrl: 'http://localhost:6767',
    apiKey: 'test-key',
    llmProvider: 'openai',
    llmApiKey: 'test-llm-key',
    llmModel: 'text-embedding-3-small',
    searchLimit: 10,
    timeoutMs: 5000,
    reconnectIntervalMs: 1000, // Short for testing
    similarityThreshold: 0.5,
    writeQueueMax: 100,
    ...overrides,
  };
}

describe('MemoryLayer', () => {
  let layer: MemoryLayer;
  let config: MemoryLayerConfig;

  beforeEach(() => {
    vi.useFakeTimers();
    config = createTestConfig();
    mockSearchMemories.mockReset();
    mockAdd.mockReset();
  });

  afterEach(async () => {
    if (layer) {
      await layer.shutdown();
    }
    vi.useRealTimers();
  });

  describe('constructor', () => {
    it('creates instance with correct config', () => {
      layer = new MemoryLayer(config);
      expect(layer).toBeInstanceOf(MemoryLayer);
    });
  });

  describe('initialize()', () => {
    it('connects successfully when Supermemory is available', async () => {
      mockSearchMemories.mockResolvedValueOnce({
        results: [],
        timing: 10,
        total: 0,
      });

      layer = new MemoryLayer(config);
      await layer.initialize();

      expect(layer.healthCheck()).toBe('connected');
      expect(mockSearchMemories).toHaveBeenCalledWith({ q: '', limit: 1 });
    });

    it('enters fallback mode when Supermemory is unavailable', async () => {
      mockSearchMemories.mockRejectedValueOnce(new Error('Connection refused'));

      layer = new MemoryLayer(config);
      await layer.initialize();

      expect(layer.healthCheck()).toBe('fallback');
    });

    it('starts reconnection timer on failure and recovers', async () => {
      // First call fails (initialization)
      mockSearchMemories.mockRejectedValueOnce(new Error('Connection refused'));

      layer = new MemoryLayer(config);
      await layer.initialize();

      expect(layer.healthCheck()).toBe('fallback');

      // Next call succeeds (reconnection probe)
      mockSearchMemories.mockResolvedValueOnce({
        results: [],
        timing: 10,
        total: 0,
      });

      // Advance timer past reconnection interval
      await vi.advanceTimersByTimeAsync(config.reconnectIntervalMs + 10);

      expect(layer.healthCheck()).toBe('connected');
    });
  });

  describe('shutdown()', () => {
    it('clears reconnection timer', async () => {
      mockSearchMemories.mockRejectedValueOnce(new Error('Connection refused'));

      layer = new MemoryLayer(config);
      await layer.initialize();
      expect(layer.healthCheck()).toBe('fallback');

      await layer.shutdown();

      // After shutdown, no reconnect timer → disconnected
      expect(layer.healthCheck()).toBe('disconnected');
    });

    it('completes without error when no pending writes', async () => {
      mockSearchMemories.mockResolvedValueOnce({
        results: [],
        timing: 10,
        total: 0,
      });

      layer = new MemoryLayer(config);
      await layer.initialize();

      await expect(layer.shutdown()).resolves.toBeUndefined();
    });
  });

  describe('healthCheck()', () => {
    it('returns "connected" when healthy', async () => {
      mockSearchMemories.mockResolvedValueOnce({
        results: [],
        timing: 10,
        total: 0,
      });

      layer = new MemoryLayer(config);
      await layer.initialize();

      expect(layer.healthCheck()).toBe('connected');
    });

    it('returns "fallback" when in fallback mode with reconnect timer', async () => {
      mockSearchMemories.mockRejectedValueOnce(new Error('Connection refused'));

      layer = new MemoryLayer(config);
      await layer.initialize();

      expect(layer.healthCheck()).toBe('fallback');
    });

    it('returns "disconnected" before initialization', () => {
      layer = new MemoryLayer(config);
      expect(layer.healthCheck()).toBe('disconnected');
    });
  });

  describe('stub methods', () => {
    beforeEach(() => {
      layer = new MemoryLayer(config);
    });

    it('semanticSearch returns empty array via circuit breaker fallback', async () => {
      const result = await layer.semanticSearch('tenant-1', 'query');
      expect(result).toEqual([]);
    });

    it('getEntityProfile returns null via circuit breaker fallback', async () => {
      const result = await layer.getEntityProfile('tenant-1', 'entity-1');
      expect(result).toBeNull();
    });

    it('getPatternSummary returns empty array via circuit breaker fallback', async () => {
      const result = await layer.getPatternSummary('tenant-1');
      expect(result).toEqual([]);
    });

    it('getMemoryEntriesByTenant returns empty array via circuit breaker fallback', async () => {
      const result = await layer.getMemoryEntriesByTenant('tenant-1');
      expect(result).toEqual([]);
    });

    it('insert validates tenant_id and stores via circuit breaker fallback', async () => {
      const record = {
        id: 'rec-1',
        tenant_id: 'tenant-1',
        threat_type: 'test',
        incident_id: 'inc-1',
        threat_description: 'Test threat',
        affected_asset_types: ['server'],
        mitre_technique_ids: ['T1078'],
        actions_taken: ['blocked'],
        outcome: 'ONGOING',
        embedding_text: 'test embedding',
        created_at: new Date().toISOString(),
      };
      await expect(layer.insert('memory', record)).resolves.toBeUndefined();
    });

    it('insert rejects missing tenant_id', async () => {
      await expect(layer.insert('table', {})).rejects.toThrow('tenant_id');
    });

    it('findById returns null via circuit breaker fallback', async () => {
      const result = await layer.findById('table', 'id', 'tenant');
      expect(result).toBeNull();
    });

    it('findByTenantId returns empty array via circuit breaker fallback', async () => {
      const result = await layer.findByTenantId('table', 'tenant');
      expect(result).toEqual([]);
    });

    it('update resolves via circuit breaker fallback', async () => {
      await expect(layer.update('table', 'id', 'tenant', {})).resolves.toBeUndefined();
    });

    it('deleteByTenantId returns 0 via circuit breaker fallback', async () => {
      const result = await layer.deleteByTenantId('table', 'tenant');
      expect(result).toBe(0);
    });
  });
});
