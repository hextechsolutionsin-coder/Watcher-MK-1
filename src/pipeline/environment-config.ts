/**
 * Environment Configuration
 *
 * Stores permanent facts about the customer's environment that the AI
 * should always know. These facts are injected into every AI prompt
 * to provide context and help the AI quickly dismiss benign events.
 *
 * Two types of context:
 * 1. Free-text facts — general statements about the environment
 * 2. Known IPs — trusted IP addresses with owner/role metadata
 *    The AI uses these to distinguish legitimate admin activity from attacks
 */

// ============================================================================
// Known IPs
// ============================================================================

export interface KnownIp {
  id: string;
  ip: string;
  label: string;           // e.g. "Office Network", "Admin VPN", "CI/CD Pipeline"
  owner: string;           // e.g. "DevOps Team", "John Smith"
  notes?: string;          // optional extra context
  created_at: string;
  created_by: string;
}

const knownIps: KnownIp[] = [];

export function getKnownIps(): KnownIp[] {
  return [...knownIps];
}

export function addKnownIp(entry: Omit<KnownIp, 'id' | 'created_at'>): KnownIp {
  // Prevent duplicates
  const existing = knownIps.find((k) => k.ip === entry.ip);
  if (existing) {
    // Update existing entry
    Object.assign(existing, { ...entry, id: existing.id, created_at: existing.created_at });
    console.log(`[EnvConfig] Updated known IP: ${entry.ip} (${entry.label})`);
    return existing;
  }

  const newEntry: KnownIp = {
    id: `ip-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    ...entry,
    created_at: new Date().toISOString(),
  };
  knownIps.push(newEntry);
  console.log(`[EnvConfig] Added known IP: ${entry.ip} (${entry.label} — ${entry.owner})`);
  return newEntry;
}

export function removeKnownIp(id: string): boolean {
  const idx = knownIps.findIndex((k) => k.id === id);
  if (idx === -1) return false;
  const removed = knownIps.splice(idx, 1)[0]!;
  console.log(`[EnvConfig] Removed known IP: ${removed.ip}`);
  return true;
}

export function isKnownIp(ip: string): KnownIp | null {
  return knownIps.find((k) => k.ip === ip) ?? null;
}

/**
 * Builds the known IPs section for AI prompt injection.
 * Returns a formatted string describing all trusted IPs.
 */
export function buildKnownIpsContext(): string {
  if (knownIps.length === 0) return '';

  return knownIps
    .map((k) => `IP ${k.ip} is a trusted address belonging to "${k.label}" (${k.owner})${k.notes ? ` — ${k.notes}` : ''}. Activity from this IP by known identities is expected and lower risk, but unusual actions or off-hours activity should still be investigated.`)
    .join('\n');
}

// ============================================================================
// Free-text Environment Facts
// ============================================================================

const environmentFacts: string[] = [
  'Account 851725296885 is the Watcher MK1 platform account — all activity from this account is self-generated and benign.',
  'Account 245987718854 is the monitored customer account.',
  'The WatcherMK1ConnectorRole is used by the platform to read CloudTrail, GuardDuty, and Security Hub data — its activity is always benign.',
  'Service-linked roles (paths containing /aws-service-role/) are automated AWS activity and not human-initiated.',
];

export function getEnvironmentFacts(): string[] {
  return [...environmentFacts];
}

export function addEnvironmentFact(fact: string): void {
  environmentFacts.push(fact);
  console.log(`[EnvConfig] Added fact: ${fact}`);
}

export function removeEnvironmentFact(index: number): boolean {
  if (index < 0 || index >= environmentFacts.length) return false;
  environmentFacts.splice(index, 1);
  return true;
}

/**
 * Returns all context for AI prompt injection — facts + known IPs combined.
 */
export function getAllEnvironmentContext(): string[] {
  const ipFacts = knownIps.map(
    (k) => `IP ${k.ip} belongs to "${k.label}" (${k.owner}) — trusted address.${k.notes ? ` ${k.notes}` : ''}`
  );
  return [...environmentFacts, ...ipFacts];
}
