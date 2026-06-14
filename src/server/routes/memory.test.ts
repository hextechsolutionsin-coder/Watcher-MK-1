import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response } from 'express';

// Mock the memoryLayer instance before importing the route
vi.mock('../memory-layer-instance.js', () => ({
  memoryLayer: {
    healthCheck: vi.fn(),
  },
}));

import { memoryLayer } from '../memory-layer-instance.js';

describe('GET /api/v1/memory/health', () => {
  let mockRes: Partial<Response>;
  let jsonSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    jsonSpy = vi.fn();
    mockRes = {
      json: jsonSpy,
    };
  });

  it('returns connected status when Supermemory is healthy', async () => {
    vi.mocked(memoryLayer.healthCheck).mockReturnValue('connected');

    // Import fresh to get the route handler
    const { default: router } = await import('./memory.js');
    const layer = router.stack.find((l: any) => l.route?.path === '/health');
    const handler = layer?.route?.stack[0]?.handle;

    handler({} as Request, mockRes as Response, vi.fn());

    expect(jsonSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'connected',
        timestamp: expect.any(String),
      })
    );
  });

  it('returns fallback status when Supermemory is in fallback mode', async () => {
    vi.mocked(memoryLayer.healthCheck).mockReturnValue('fallback');

    const { default: router } = await import('./memory.js');
    const layer = router.stack.find((l: any) => l.route?.path === '/health');
    const handler = layer?.route?.stack[0]?.handle;

    handler({} as Request, mockRes as Response, vi.fn());

    expect(jsonSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'fallback',
        timestamp: expect.any(String),
      })
    );
  });

  it('returns disconnected status when Supermemory is unavailable', async () => {
    vi.mocked(memoryLayer.healthCheck).mockReturnValue('disconnected');

    const { default: router } = await import('./memory.js');
    const layer = router.stack.find((l: any) => l.route?.path === '/health');
    const handler = layer?.route?.stack[0]?.handle;

    handler({} as Request, mockRes as Response, vi.fn());

    expect(jsonSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'disconnected',
        timestamp: expect.any(String),
      })
    );
  });

  it('always returns a valid ISO timestamp', async () => {
    vi.mocked(memoryLayer.healthCheck).mockReturnValue('connected');

    const { default: router } = await import('./memory.js');
    const layer = router.stack.find((l: any) => l.route?.path === '/health');
    const handler = layer?.route?.stack[0]?.handle;

    handler({} as Request, mockRes as Response, vi.fn());

    const response = jsonSpy.mock.calls[0][0];
    const parsedDate = new Date(response.timestamp);
    expect(parsedDate.toISOString()).toBe(response.timestamp);
  });
});
