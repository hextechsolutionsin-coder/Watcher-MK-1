import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WriteQueue } from './write-queue.js';
import { QueuedWrite } from './types.js';

function makeWrite(id: string, operation: 'add' | 'update' | 'forget' = 'add'): QueuedWrite {
  return {
    id,
    operation,
    tenantId: 'tenant-1',
    payload: { content: `payload-${id}` },
    timestamp: new Date().toISOString(),
    retryCount: 0,
  };
}

describe('WriteQueue', () => {
  let queue: WriteQueue;

  beforeEach(() => {
    queue = new WriteQueue(5);
  });

  describe('enqueue()', () => {
    it('should add items to the queue', () => {
      queue.enqueue(makeWrite('1'));
      queue.enqueue(makeWrite('2'));
      expect(queue.size()).toBe(2);
    });

    it('should drop oldest entry when maxSize is exceeded', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      for (let i = 1; i <= 6; i++) {
        queue.enqueue(makeWrite(String(i)));
      }

      // Max is 5, so after 6 enqueues the oldest (id=1) should be dropped
      expect(queue.size()).toBe(5);
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Queue overflow')
      );

      warnSpy.mockRestore();
    });

    it('should log a warning with the dropped entry details', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      for (let i = 1; i <= 6; i++) {
        queue.enqueue(makeWrite(String(i)));
      }

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('id=1')
      );

      warnSpy.mockRestore();
    });
  });

  describe('size()', () => {
    it('should return 0 for an empty queue', () => {
      expect(queue.size()).toBe(0);
    });

    it('should return the current number of items', () => {
      queue.enqueue(makeWrite('a'));
      queue.enqueue(makeWrite('b'));
      queue.enqueue(makeWrite('c'));
      expect(queue.size()).toBe(3);
    });
  });

  describe('clear()', () => {
    it('should empty the queue', () => {
      queue.enqueue(makeWrite('1'));
      queue.enqueue(makeWrite('2'));
      queue.clear();
      expect(queue.size()).toBe(0);
    });
  });

  describe('replayAll()', () => {
    it('should process items in FIFO order', async () => {
      const order: string[] = [];
      queue.enqueue(makeWrite('first'));
      queue.enqueue(makeWrite('second'));
      queue.enqueue(makeWrite('third'));

      await queue.replayAll(async (write) => {
        order.push(write.id);
      });

      expect(order).toEqual(['first', 'second', 'third']);
    });

    it('should return succeeded and failed counts', async () => {
      queue.enqueue(makeWrite('1'));
      queue.enqueue(makeWrite('2'));
      queue.enqueue(makeWrite('3'));

      const result = await queue.replayAll(async (write) => {
        if (write.id === '2') throw new Error('fail');
      });

      expect(result.succeeded).toBe(2);
      expect(result.failed).toBe(1);
    });

    it('should continue processing after a failure', async () => {
      const processed: string[] = [];
      queue.enqueue(makeWrite('1'));
      queue.enqueue(makeWrite('2'));
      queue.enqueue(makeWrite('3'));

      await queue.replayAll(async (write) => {
        if (write.id === '1') throw new Error('fail');
        processed.push(write.id);
      });

      expect(processed).toEqual(['2', '3']);
    });

    it('should increment retryCount on failure', async () => {
      const w = makeWrite('retry-me');
      queue.enqueue(w);

      await queue.replayAll(async () => {
        throw new Error('fail');
      });

      // The failed write is still in the queue with incremented retryCount
      expect(queue.size()).toBe(1);
      expect(w.retryCount).toBe(1);
    });

    it('should clear succeeded items from the queue after replay', async () => {
      queue.enqueue(makeWrite('ok-1'));
      queue.enqueue(makeWrite('fail-1'));
      queue.enqueue(makeWrite('ok-2'));

      await queue.replayAll(async (write) => {
        if (write.id === 'fail-1') throw new Error('fail');
      });

      // Only the failed write should remain
      expect(queue.size()).toBe(1);
    });

    it('should return all succeeded with empty failed when all succeed', async () => {
      queue.enqueue(makeWrite('1'));
      queue.enqueue(makeWrite('2'));

      const result = await queue.replayAll(async () => {});

      expect(result).toEqual({ succeeded: 2, failed: 0 });
      expect(queue.size()).toBe(0);
    });

    it('should handle an empty queue gracefully', async () => {
      const result = await queue.replayAll(async () => {});
      expect(result).toEqual({ succeeded: 0, failed: 0 });
    });
  });
});
