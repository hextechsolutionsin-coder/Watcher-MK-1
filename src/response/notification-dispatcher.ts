import { IncidentSeverity, AuditLogEntry, AuditEventType } from '../types/index.js';

export interface Notification {
  tenant_id: string;
  incident_id: string;
  action_plan_id?: string;
  severity: IncidentSeverity;
  message: string;
  ai_explanation: string;
  recipients: string[];
  timestamp: string;
}

export interface NotificationChannel {
  type: 'EMAIL' | 'SLACK' | 'PAGERDUTY';
  send(notification: Notification): Promise<boolean>;
}

export interface AuditLogWriter {
  writeEntry(entry: Partial<AuditLogEntry>): Promise<void>;
}

export interface NotificationResult {
  successes: string[];
  failures: Array<{ channel: string; error: string; retries: number }>;
}

/**
 * Delivers notifications in parallel across all configured channels.
 * Retries failed channels up to 3 times with exponential backoff.
 * Logs each failure in the Audit Log.
 */
export class NotificationDispatcher {
  private readonly auditLogWriter: AuditLogWriter;
  private readonly maxRetries: number;
  private readonly baseDelayMs: number;

  constructor(auditLogWriter: AuditLogWriter, options?: { maxRetries?: number; baseDelayMs?: number }) {
    this.auditLogWriter = auditLogWriter;
    this.maxRetries = options?.maxRetries ?? 3;
    this.baseDelayMs = options?.baseDelayMs ?? 1000;
  }

  async dispatch(notification: Notification, channels: NotificationChannel[]): Promise<NotificationResult> {
    const results = await Promise.allSettled(
      channels.map((channel) => this.sendWithRetry(notification, channel))
    );

    const successes: string[] = [];
    const failures: NotificationResult['failures'] = [];

    results.forEach((result, index) => {
      const channel = channels[index]!;
      if (result.status === 'fulfilled') {
        if (result.value.success) {
          successes.push(channel.type);
        } else {
          failures.push({ channel: channel.type, error: result.value.error, retries: result.value.retries });
        }
      } else {
        failures.push({ channel: channel.type, error: result.reason?.message ?? 'Unknown error', retries: 0 });
      }
    });

    return { successes, failures };
  }

  private async sendWithRetry(
    notification: Notification,
    channel: NotificationChannel
  ): Promise<{ success: boolean; error: string; retries: number }> {
    let lastError = '';

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const success = await channel.send(notification);
        if (success) return { success: true, error: '', retries: attempt };
        lastError = `Channel ${channel.type} returned false`;
      } catch (err: unknown) {
        lastError = err instanceof Error ? err.message : String(err);
      }

      await this.auditLogWriter.writeEntry({
        tenant_id: notification.tenant_id,
        event_type: AuditEventType.ACTION_FAILED,
        timestamp: new Date().toISOString(),
        actor: { type: 'SYSTEM', id: 'notification-dispatcher' },
        action_taken: `Notification delivery failed on channel ${channel.type} (attempt ${attempt + 1}/${this.maxRetries + 1})`,
        outcome: 'FAILURE',
        metadata: {
          channel_type: channel.type,
          incident_id: notification.incident_id,
          action_plan_id: notification.action_plan_id,
          error: lastError,
          attempt: attempt + 1,
        },
      });

      if (attempt < this.maxRetries) {
        await this.sleep(this.baseDelayMs * Math.pow(2, attempt));
      }
    }

    return { success: false, error: lastError, retries: this.maxRetries };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
