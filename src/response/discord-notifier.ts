/**
 * Discord Notification Channel
 *
 * Sends approval requests and threat alerts to a Discord webhook.
 * Uses Discord embeds for rich formatting — color-coded by severity,
 * with AI reasoning, blast radius, and a direct link to the approval.
 */

import type { NotificationChannel, Notification } from './notification-dispatcher.js';

const SEVERITY_COLORS: Record<string, number> = {
  CRITICAL: 0xFF0000,  // Red
  HIGH:     0xFF6600,  // Orange
  MEDIUM:   0xFFAA00,  // Amber
  LOW:      0x00AAFF,  // Blue
  INFORMATIONAL: 0x888888, // Gray
};

const SEVERITY_EMOJI: Record<string, string> = {
  CRITICAL: '🚨',
  HIGH:     '⚠️',
  MEDIUM:   '🔶',
  LOW:      '🔵',
  INFORMATIONAL: 'ℹ️',
};

export class DiscordNotificationChannel implements NotificationChannel {
  readonly type = 'SLACK' as const; // reuse SLACK type slot — Discord is the impl

  private readonly webhookUrl: string;
  private readonly dashboardUrl: string;

  constructor(webhookUrl: string, dashboardUrl = 'http://localhost:5173') {
    this.webhookUrl = webhookUrl;
    this.dashboardUrl = dashboardUrl;
  }

  async send(notification: Notification): Promise<boolean> {
    const severity = String(notification.severity).toUpperCase();
    const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS['MEDIUM']!;
    const emoji = SEVERITY_EMOJI[severity] ?? '⚠️';

    const embed = {
      title: `${emoji} ${severity} — Approval Required`,
      description: notification.ai_explanation.slice(0, 2000),
      color,
      fields: [
        {
          name: '📋 Incident ID',
          value: `\`${notification.incident_id}\``,
          inline: true,
        },
        {
          name: '🎯 Severity',
          value: severity,
          inline: true,
        },
        {
          name: '🔗 Action Required',
          value: `[Open Approval Queue](${this.dashboardUrl}/approvals)`,
          inline: true,
        },
      ],
      footer: {
        text: 'Watcher MK-1 · Autonomous AWS Security',
      },
      timestamp: notification.timestamp,
    };

    try {
      const response = await fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'Watcher MK-1',
          avatar_url: 'https://cdn-icons-png.flaticon.com/512/2092/2092663.png',
          embeds: [embed],
        }),
      });

      // Discord returns 204 No Content on success
      return response.status === 204 || response.ok;
    } catch (err) {
      console.error('[Discord] Failed to send notification:', err);
      return false;
    }
  }
}
