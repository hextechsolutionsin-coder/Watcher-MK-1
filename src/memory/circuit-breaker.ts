/**
 * Circuit Breaker for Supermemory connectivity management.
 *
 * Implements the circuit breaker pattern to gracefully degrade when
 * Supermemory is unavailable, routing operations to a fallback and
 * auto-recovering when connectivity returns.
 *
 * State transitions:
 *   closed → open       (after failureThreshold consecutive failures)
 *   open → half-open    (after recoveryTimeMs since last failure)
 *   half-open → closed  (on successful probe)
 *   half-open → open    (on failed probe)
 */

import { CircuitState } from './types.js';

export interface CircuitBreakerConfig {
  /** Number of consecutive failures before opening the circuit. Default: 3 */
  failureThreshold: number;
  /** Milliseconds to wait before transitioning from open to half-open. */
  recoveryTimeMs: number;
  /** Per-operation timeout in milliseconds. */
  timeoutMs: number;
}

export class CircuitBreaker {
  private state: CircuitState;
  private failureCount: number;
  private lastFailureTime: number;
  private readonly config: CircuitBreakerConfig;

  constructor(config: CircuitBreakerConfig) {
    this.config = config;
    this.state = 'closed';
    this.failureCount = 0;
    this.lastFailureTime = 0;
  }

  /**
   * Execute an operation through the circuit breaker.
   *
   * - In 'closed' state: runs the operation. On success, resets failure count.
   *   On failure/timeout, increments failures. If threshold reached, opens circuit.
   * - In 'open' state: uses fallback. If recoveryTimeMs has elapsed, transitions
   *   to 'half-open' and attempts the operation instead.
   * - In 'half-open' state: attempts the operation once. Success → closed + reset.
   *   Failure → open.
   */
  async execute<T>(
    operation: () => Promise<T>,
    fallback: () => Promise<T>
  ): Promise<T> {
    if (this.state === 'open') {
      // Check if recovery interval has elapsed
      if (this.shouldAttemptRecovery()) {
        this.state = 'half-open';
        return this.attemptOperation(operation, fallback);
      }
      // Still in open state — use fallback
      return fallback();
    }

    if (this.state === 'half-open') {
      return this.attemptOperation(operation, fallback);
    }

    // State is 'closed' — execute normally
    return this.attemptOperation(operation, fallback);
  }

  /** Returns the current circuit state. */
  getState(): CircuitState {
    return this.state;
  }

  /** Returns true when the circuit is closed (healthy). */
  isHealthy(): boolean {
    return this.state === 'closed';
  }

  /** Record a successful operation. Resets failure count and closes the circuit. */
  recordSuccess(): void {
    this.failureCount = 0;
    this.state = 'closed';
  }

  /** Record a failed operation. Increments failure count and opens circuit if threshold reached. */
  recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = 'open';
    }
  }

  /**
   * Check if enough time has passed since the last failure to attempt recovery.
   */
  private shouldAttemptRecovery(): boolean {
    const elapsed = Date.now() - this.lastFailureTime;
    return elapsed >= this.config.recoveryTimeMs;
  }

  /**
   * Attempt an operation with timeout enforcement.
   * On success: record success, return result.
   * On failure: record failure, return fallback result (or rethrow in half-open → open).
   */
  private async attemptOperation<T>(
    operation: () => Promise<T>,
    fallback: () => Promise<T>
  ): Promise<T> {
    try {
      const result = await this.executeWithTimeout(operation);
      this.recordSuccess();
      return result;
    } catch {
      this.recordFailure();
      return fallback();
    }
  }

  /**
   * Runs a promise with a timeout. Rejects with a timeout error if the
   * operation does not resolve within `timeoutMs`.
   */
  private executeWithTimeout<T>(operation: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        controller.abort();
        reject(new Error(`Operation timed out after ${this.config.timeoutMs}ms`));
      }, this.config.timeoutMs);

      operation()
        .then((result) => {
          clearTimeout(timeoutId);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(error);
        });
    });
  }
}
