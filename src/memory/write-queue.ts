/**
 * WriteQueue — Queues memory write operations during fallback mode for replay
 * when Supermemory connectivity is restored.
 *
 * Implements a bounded FIFO queue that drops the oldest entries when the
 * configured max size is exceeded, and replays all queued writes in original
 * order upon recovery.
 */

import { QueuedWrite } from './types.js';

export class WriteQueue {
  private queue: QueuedWrite[] = [];
  private readonly maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  /**
   * Add a write operation to the end of the queue.
   * If the queue exceeds maxSize, the oldest entry is dropped and a warning is logged.
   */
  enqueue(write: QueuedWrite): void {
    this.queue.push(write);

    if (this.queue.length > this.maxSize) {
      const dropped = this.queue.shift();
      console.warn(
        `[WriteQueue] Queue overflow: dropped oldest entry (id=${dropped?.id}, operation=${dropped?.operation}). ` +
        `Queue size: ${this.queue.length}/${this.maxSize}`
      );
    }
  }

  /**
   * Replay all queued writes in FIFO order (oldest first).
   * For each item, calls the executor callback. Tracks succeeded/failed counts.
   * On failure, increments retryCount but continues with the next item.
   * After replay, clears all successfully processed items from the queue.
   */
  async replayAll(
    executor: (write: QueuedWrite) => Promise<void>
  ): Promise<{ succeeded: number; failed: number }> {
    let succeeded = 0;
    let failed = 0;
    const failedWrites: QueuedWrite[] = [];

    for (const write of this.queue) {
      try {
        await executor(write);
        succeeded++;
      } catch {
        write.retryCount++;
        failed++;
        failedWrites.push(write);
      }
    }

    // Keep only failed writes for potential future retry
    this.queue = failedWrites;

    return { succeeded, failed };
  }

  /** Return the current number of queued writes. */
  size(): number {
    return this.queue.length;
  }

  /** Clear all entries from the queue. */
  clear(): void {
    this.queue = [];
  }
}
