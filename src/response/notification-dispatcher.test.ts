import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  NotificationDispatcher,
  Notification,
  NotificationChannel,
  AuditLogWriter,
} from './notification-dispatcher.js';
import { IncidentSeverity, AuditLogEntry } from '../types/index.js';

// ============================================================================
// Test Helpers
// ============================================================================

function createNotification(overrides?: Partial<Notification>): Notification {
  return {
    tenant_id: 'tenant-1',
    incident_id: 'incident-1',
    action_plan_id: 'action-1',
    severity: IncidentSeverity.CRITICAL,
    message: 'Critical incident detected',
    ai_explanation: 'AI detected a critical threat.',
    recipients: ['analyst@example.com'],
    timestamp: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

function createMockChannel(type: NotificationChannel['type'], sendFn?: () => Promise<boolean>): NotificationChannel {
  return {
    type,
    send: sendFn ?? vi.fn().mockResolvedValue(true),
  };
}

function createMockAuditLogWriter(): AuditLogWriter & { entries: Partial<AuditLogEntry>[] } {
  const entries: Partial<AuditLogEntry>[] = [];
  return {
    entries,
    writeEntry: vi.fn(async (entry: Partial<AuditLogEntry>) => {
      entries.push(entry);
    }),
  };
}

// ============================================================================
// Tests
// ============================================================================

describe('NotificationDispatcher', () => {
  let auditLogWriter: ReturnType<typeof createMockAuditLogWriter>;
  let dispatcher: NotificationDispatcher;

  beforeEach(() => {
    auditLogWriter = createMockAuditLogWriter();
    // Use 0ms base delay for fast tests
    dispatcher = new NotificationDispatcher(auditLogWriter, { maxRetries: 3, baseDelayMs: 0 });
  });

  describe('All channels succeed on first attempt', () => {
    it('should return all channels in successes when all deliver successfully', async () => {
      const notification = createNotification();
      const channels: NotificationChannel[] = [
        createMockChannel('EMAIL'),
        createMockChannel('SLACK'),
        createMockChannel('PAGERDUTY'),
        createMockChannel('PAGERDUTY'),
      ];

      const result = await dispatcher.dispatch(notification, channels);

      expect(result.successes).toEqual(['EMAIL', 'SLACK', 'PAGERDUTY', 'PAGERDUTY']);
      expect(result.failures).toEqual([]);
    });

    it('should not log any audit entries when all channels succeed', async () => {
      const notification = createNotification();
      const channels: NotificationChannel[] = [
        createMockChannel('EMAIL'),
        createMockChannel('SLACK'),
      ];

      await dispatcher.dispatch(notification, channels);

      expect(auditLogWriter.entries).toHaveLength(0);
    });
  });

  describe('One channel fails, retries succeed', () => {
    it('should succeed after retry when channel fails initially then succeeds', async () => {
      const notification = createNotification();
      let callCount = 0;
      const flakySend = vi.fn(async () => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Temporary network error');
        }
        return true;
      });

      const channels: NotificationChannel[] = [
        createMockChannel('EMAIL'),
        createMockChannel('SLACK', flakySend),
      ];

      const result = await dispatcher.dispatch(notification, channels);

      expect(result.successes).toContain('EMAIL');
      expect(result.successes).toContain('SLACK');
      expect(result.failures).toEqual([]);
    });

    it('should log the initial failure attempt in the audit log', async () => {
      const notification = createNotification();
      let callCount = 0;
      const flakySend = vi.fn(async () => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Temporary failure');
        }
        return true;
      });

      const channels: NotificationChannel[] = [
        createMockChannel('SLACK', flakySend),
      ];

      await dispatcher.dispatch(notification, channels);

      // Should have logged the first failure
      expect(auditLogWriter.entries.length).toBeGreaterThanOrEqual(1);
      expect(auditLogWriter.entries[0].outcome).toBe('FAILURE');
      expect(auditLogWriter.entries[0].metadata).toMatchObject({
        channel_type: 'SLACK',
        error: 'Temporary failure',
        attempt: 1,
      });
    });
  });

  describe('One channel fails all retries (logged to audit)', () => {
    it('should report the channel as failed after exhausting all retries', async () => {
      const notification = createNotification();
      const failingSend = vi.fn(async () => {
        throw new Error('Permanent failure');
      });

      const channels: NotificationChannel[] = [
        createMockChannel('EMAIL'),
        createMockChannel('PAGERDUTY', failingSend),
      ];

      const result = await dispatcher.dispatch(notification, channels);

      expect(result.successes).toEqual(['EMAIL']);
      expect(result.failures).toHaveLength(1);
      expect(result.failures[0]).toEqual({
        channel: 'PAGERDUTY',
        error: 'Permanent failure',
        retries: 3,
      });
    });

    it('should log each retry failure in the audit log', async () => {
      const notification = createNotification();
      const failingSend = vi.fn(async () => {
        throw new Error('Service unavailable');
      });

      const channels: NotificationChannel[] = [
        createMockChannel('PAGERDUTY', failingSend),
      ];

      await dispatcher.dispatch(notification, channels);

      // 1 initial attempt + 3 retries = 4 total attempts, all logged
      expect(auditLogWriter.entries).toHaveLength(4);
      auditLogWriter.entries.forEach((entry, index) => {
        expect(entry.outcome).toBe('FAILURE');
        expect(entry.tenant_id).toBe('tenant-1');
        expect(entry.metadata).toMatchObject({
          channel_type: 'PAGERDUTY',
          incident_id: 'incident-1',
          error: 'Service unavailable',
          attempt: index + 1,
        });
      });
    });

    it('should handle channels returning false (non-exception failure)', async () => {
      const notification = createNotification();
      const falseSend = vi.fn(async () => false);

      const channels: NotificationChannel[] = [
        createMockChannel('PAGERDUTY', falseSend),
      ];

      const result = await dispatcher.dispatch(notification, channels);

      expect(result.successes).toEqual([]);
      expect(result.failures).toHaveLength(1);
      expect(result.failures[0].channel).toBe('PAGERDUTY');
      expect(result.failures[0].retries).toBe(3);
    });
  });

  describe('Parallel delivery (all channels attempted simultaneously)', () => {
    it('should attempt all channels in parallel using Promise.allSettled', async () => {
      const notification = createNotification();
      const callOrder: string[] = [];
      const resolveOrder: Array<() => void> = [];

      // Create channels that track when they're called
      const makeTrackedChannel = (type: NotificationChannel['type']): NotificationChannel => ({
        type,
        send: vi.fn(() => {
          callOrder.push(`${type}-start`);
          return new Promise<boolean>((resolve) => {
            resolveOrder.push(() => {
              callOrder.push(`${type}-end`);
              resolve(true);
            });
          });
        }),
      });

      const channels: NotificationChannel[] = [
        makeTrackedChannel('EMAIL'),
        makeTrackedChannel('SLACK'),
        makeTrackedChannel('PAGERDUTY'),
        makeTrackedChannel('PAGERDUTY'),
      ];

      const dispatchPromise = dispatcher.dispatch(notification, channels);

      // Allow microtasks to process so all sends are initiated
      await new Promise((resolve) => setTimeout(resolve, 0));

      // All channels should have started before any resolved
      expect(callOrder).toEqual([
        'EMAIL-start',
        'SLACK-start',
        'PAGERDUTY-start',
        'PAGERDUTY-start',
      ]);

      // Now resolve all
      resolveOrder.forEach((resolve) => resolve());

      const result = await dispatchPromise;

      expect(result.successes).toEqual(['EMAIL', 'SLACK', 'PAGERDUTY', 'PAGERDUTY']);
      expect(result.failures).toEqual([]);
    });

    it('should not block other channels when one channel is slow', async () => {
      const notification = createNotification();
      const sendTimestamps: Record<string, number> = {};

      const makeTimedChannel = (type: NotificationChannel['type'], delayMs: number): NotificationChannel => ({
        type,
        send: vi.fn(async () => {
          sendTimestamps[type] = Date.now();
          await new Promise((resolve) => setTimeout(resolve, delayMs));
          return true;
        }),
      });

      const channels: NotificationChannel[] = [
        makeTimedChannel('EMAIL', 0),
        makeTimedChannel('SLACK', 50),
        makeTimedChannel('PAGERDUTY', 0),
      ];

      const result = await dispatcher.dispatch(notification, channels);

      expect(result.successes).toContain('EMAIL');
      expect(result.successes).toContain('SLACK');
      expect(result.successes).toContain('PAGERDUTY');

      // All channels should have started at approximately the same time
      const timestamps = Object.values(sendTimestamps);
      const maxDiff = Math.max(...timestamps) - Math.min(...timestamps);
      // They should all start within 20ms of each other (parallel)
      expect(maxDiff).toBeLessThan(20);
    });

    it('should handle mixed success and failure across parallel channels', async () => {
      const notification = createNotification();

      const channels: NotificationChannel[] = [
        createMockChannel('EMAIL'),
        createMockChannel('SLACK', async () => { throw new Error('Slack down'); }),
        createMockChannel('PAGERDUTY'),
        createMockChannel('PAGERDUTY', async () => { throw new Error('Ticketing down'); }),
      ];

      const result = await dispatcher.dispatch(notification, channels);

      expect(result.successes).toContain('EMAIL');
      expect(result.successes).toContain('PAGERDUTY');
      expect(result.failures.map((f) => f.channel)).toContain('SLACK');
      expect(result.failures.map((f) => f.channel)).toContain('PAGERDUTY');
    });
  });
});
