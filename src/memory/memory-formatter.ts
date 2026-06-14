/**
 * MemoryFormatter — Converts between Watcher MK1 typed data structures
 * and Supermemory's text-based memory format.
 *
 * Handles serialization of incidents/memory entries to structured natural language
 * optimized for Supermemory's embedding engine, and parsing that format back into
 * typed objects.
 */

import {
  Incident,
  ReasoningResponse,
  ReasoningMemoryEntry,
  AnalystFeedback,
  NormalizedEvent,
} from '../types/index.js';

/**
 * Metadata stored alongside memory content in Supermemory.
 */
export interface SupermemoryMetadata {
  type: 'incident' | 'memory_entry' | 'feedback';
  incident_id: string;
  tenant_id: string;
  threat_type: string;
  severity: string;
  mitre_techniques: string; // comma-separated technique IDs
  outcome: string;
  has_feedback: boolean;
  created_at: string;
}

export class MemoryFormatter {
  /**
   * Formats an Incident (with optional reasoning) into structured natural language
   * for storage in Supermemory.
   */
  static formatIncidentForStorage(incident: Incident, reasoning?: ReasoningResponse): string {
    const lines: string[] = [];

    lines.push(`[Incident ID: ${incident.id}]`);
    lines.push(`Threat Type: ${incident.threat_type}`);
    lines.push(`Severity: ${incident.severity}`);
    lines.push(`Description: ${incident.description}`);
    lines.push(`Affected Assets: ${incident.affected_assets.join(', ')}`);

    const mitreLine = incident.mitre_techniques
      .map((t) => `${t.technique_id} (${t.technique_name})`)
      .join(', ');
    lines.push(`MITRE Techniques: ${mitreLine}`);

    // Actor info is not directly on the Incident type, use explanation as proxy
    lines.push(`Actor: ${incident.explanation}`);

    if (reasoning) {
      const summary = reasoning.explanation.length > 500
        ? reasoning.explanation.slice(0, 500) + '...'
        : reasoning.explanation;
      lines.push(`AI Reasoning Summary: ${summary}`);
    } else {
      lines.push(`AI Reasoning Summary: N/A`);
    }

    lines.push(`Actions Taken: N/A`);
    lines.push(`Outcome: ${incident.status}`);
    lines.push(`Analyst Feedback: N/A`);

    return lines.join('\n');
  }

  /**
   * Formats a ReasoningMemoryEntry into structured natural language for storage.
   */
  static formatMemoryEntryForStorage(entry: ReasoningMemoryEntry): string {
    const lines: string[] = [];

    lines.push(`[Incident ID: ${entry.incident_id}]`);
    lines.push(`Threat Type: ${entry.threat_type}`);
    lines.push(`Severity: N/A`);
    lines.push(`Description: ${entry.threat_description}`);
    lines.push(`Affected Assets: ${entry.affected_asset_types.join(', ')}`);
    lines.push(`MITRE Techniques: ${entry.mitre_technique_ids.join(', ')}`);
    lines.push(`Actor: N/A`);
    lines.push(`AI Reasoning Summary: ${entry.embedding_text}`);
    lines.push(`Actions Taken: ${entry.actions_taken.join(', ')}`);
    lines.push(`Outcome: ${entry.outcome}`);

    if (entry.analyst_feedback) {
      const feedbackStr = entry.analyst_feedback.notes
        ? `${entry.analyst_feedback.verdict} - ${entry.analyst_feedback.notes}`
        : entry.analyst_feedback.verdict;
      lines.push(`Analyst Feedback: ${feedbackStr}`);
    } else {
      lines.push(`Analyst Feedback: N/A`);
    }

    return lines.join('\n');
  }

  /**
   * Formats analyst feedback for updating an existing memory entry's content.
   */
  static formatFeedbackUpdate(feedback: AnalystFeedback): string {
    const parts: string[] = [`Analyst Feedback: ${feedback.verdict}`];
    if (feedback.notes) {
      parts[0] += ` - ${feedback.notes}`;
    }
    parts.push(`Submitted By: ${feedback.submitted_by}`);
    parts.push(`Submitted At: ${feedback.submitted_at}`);
    return parts.join('\n');
  }

  /**
   * Parses structured natural language content + metadata back into a
   * ReasoningMemoryEntry object.
   */
  static parseMemoryContent(
    content: string,
    metadata: Record<string, unknown>
  ): ReasoningMemoryEntry {
    const meta = metadata as unknown as SupermemoryMetadata;

    // Extract fields from structured text using regex
    const incidentId = MemoryFormatter.extractField(content, /\[Incident ID:\s*(.+?)\]/) ?? meta.incident_id;
    const threatType = MemoryFormatter.extractField(content, /^Threat Type:\s*(.+)$/m) ?? meta.threat_type;
    const description = MemoryFormatter.extractField(content, /^Description:\s*(.+)$/m) ?? '';
    const affectedAssets = MemoryFormatter.extractField(content, /^Affected Assets:\s*(.+)$/m) ?? '';
    const mitreTechniques = MemoryFormatter.extractField(content, /^MITRE Techniques:\s*(.+)$/m) ?? meta.mitre_techniques ?? '';
    const reasoningSummary = MemoryFormatter.extractField(content, /^AI Reasoning Summary:\s*(.+)$/m) ?? '';
    const actionsTaken = MemoryFormatter.extractField(content, /^Actions Taken:\s*(.+)$/m) ?? '';
    const outcome = MemoryFormatter.extractField(content, /^Outcome:\s*(.+)$/m) ?? meta.outcome ?? 'ONGOING';
    const feedbackLine = MemoryFormatter.extractField(content, /^Analyst Feedback:\s*(.+)$/m);

    // Parse affected assets into array
    const affectedAssetTypes = affectedAssets && affectedAssets !== 'N/A'
      ? affectedAssets.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

    // Parse MITRE technique IDs from content
    const mitreTechniqueIds = MemoryFormatter.parseMitreTechniqueIds(mitreTechniques);

    // Parse actions taken into array
    const actionsArray = actionsTaken && actionsTaken !== 'N/A'
      ? actionsTaken.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

    // Parse outcome to valid enum value
    const validOutcome = MemoryFormatter.parseOutcome(outcome);

    // Parse analyst feedback if present
    const analystFeedback = MemoryFormatter.parseFeedbackLine(feedbackLine, content);

    return {
      id: (metadata['id'] as string) ?? `mem_${incidentId}`,
      tenant_id: meta.tenant_id ?? '',
      incident_id: incidentId,
      threat_type: threatType,
      threat_description: description,
      affected_asset_types: affectedAssetTypes,
      mitre_technique_ids: mitreTechniqueIds,
      actions_taken: actionsArray,
      outcome: validOutcome,
      analyst_feedback: analystFeedback,
      embedding_text: reasoningSummary !== 'N/A' ? reasoningSummary : description,
      created_at: (meta.created_at as string) ?? new Date().toISOString(),
    };
  }

  /**
   * Constructs a search query string from a NormalizedEvent including key
   * threat context for semantic similarity matching.
   */
  static buildSearchQuery(event: NormalizedEvent): string {
    const parts: string[] = [];

    if (event.attack_surface) {
      parts.push(event.attack_surface);
    }
    if (event.event_type) {
      parts.push(event.event_type);
    }
    if (event.actor?.identifier) {
      parts.push(`by ${event.actor.identifier}`);
    }
    if (event.target?.resource_type) {
      parts.push(`targeting ${event.target.resource_type}`);
    }
    if (event.target?.resource_id) {
      parts.push(event.target.resource_id);
    }

    return parts.join(' ');
  }

  /**
   * Constructs a pattern search query for finding memories matching a specific
   * threat category or MITRE technique across a tenant's history.
   */
  static buildPatternQuery(threatCategory?: string, mitreTechnique?: string): string {
    const parts: string[] = [];

    if (threatCategory) {
      parts.push(threatCategory);
    }
    if (mitreTechnique) {
      parts.push(mitreTechnique);
    }

    if (parts.length === 0) {
      return 'unresolved security patterns';
    }

    return parts.join(' ');
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private static extractField(content: string, pattern: RegExp): string | null {
    const match = content.match(pattern);
    return match ? match[1].trim() : null;
  }

  private static parseMitreTechniqueIds(raw: string): string[] {
    if (!raw || raw === 'N/A') return [];

    // Match technique IDs like T1078, T1078.004, etc.
    const ids = raw.match(/T\d{4}(?:\.\d{3})?/g);
    if (ids && ids.length > 0) {
      return ids;
    }

    // Fallback: split by comma and return trimmed non-empty values
    return raw.split(',').map((s) => s.trim()).filter(Boolean);
  }

  private static parseOutcome(raw: string): 'RESOLVED' | 'ESCALATED' | 'FALSE_POSITIVE' | 'ONGOING' {
    const normalized = raw.toUpperCase().trim();
    switch (normalized) {
      case 'RESOLVED':
        return 'RESOLVED';
      case 'ESCALATED':
        return 'ESCALATED';
      case 'FALSE_POSITIVE':
        return 'FALSE_POSITIVE';
      default:
        return 'ONGOING';
    }
  }

  private static parseFeedbackLine(
    feedbackLine: string | null,
    content: string
  ): AnalystFeedback | undefined {
    if (!feedbackLine || feedbackLine === 'N/A') {
      return undefined;
    }

    // Parse "VERDICT - notes" format
    const dashIndex = feedbackLine.indexOf(' - ');
    let verdict: string;
    let notes: string | undefined;

    if (dashIndex > -1) {
      verdict = feedbackLine.slice(0, dashIndex).trim();
      notes = feedbackLine.slice(dashIndex + 3).trim() || undefined;
    } else {
      verdict = feedbackLine.trim();
    }

    // Validate verdict against known values
    const validVerdicts = ['CORRECT', 'INCORRECT', 'FALSE_POSITIVE', 'SEVERITY_WRONG', 'ACTION_WRONG'];
    if (!validVerdicts.includes(verdict)) {
      return undefined;
    }

    // Try to extract submitted_by and submitted_at from content
    const submittedBy = MemoryFormatter.extractField(content, /^Submitted By:\s*(.+)$/m) ?? 'unknown';
    const submittedAt = MemoryFormatter.extractField(content, /^Submitted At:\s*(.+)$/m) ?? new Date().toISOString();

    return {
      verdict: verdict as AnalystFeedback['verdict'],
      notes,
      submitted_by: submittedBy,
      submitted_at: submittedAt,
    };
  }
}
