import { useState, useEffect } from 'react';
import { Plus, Trash2, Loader2, ShieldOff, RefreshCw, Wifi, Brain } from 'lucide-react';
import {
  fetchSuppressions, createSuppression, deleteSuppression,
  fetchKnownIps, addKnownIp, deleteKnownIp,
  fetchEnvironmentFacts, addEnvironmentFact, deleteEnvironmentFact,
} from '../api/client';

// ── Types ─────────────────────────────────────────────────────────────────────

interface SuppressionRule {
  id: string;
  type: string;
  value: string;
  reason: string;
  created_by: string;
  created_at: string;
}

interface KnownIp {
  id: string;
  ip: string;
  label: string;
  owner: string;
  notes?: string;
  created_by: string;
  created_at: string;
}

interface EnvironmentFact {
  index: number;
  fact: string;
}

// ── Suppression type labels ───────────────────────────────────────────────────

const TYPE_LABELS: Record<string, string> = {
  ACCOUNT: 'AWS Account ID',
  ROLE_ARN: 'IAM Role ARN',
  EVENT_NAME: 'CloudTrail Event Name',
  IP: 'Source IP Address',
};

const TYPE_PLACEHOLDERS: Record<string, string> = {
  ACCOUNT: '123456789012',
  ROLE_ARN: 'arn:aws:iam::123456789012:role/MyRole',
  EVENT_NAME: 'DescribeInstances',
  IP: '10.0.0.1',
};

// ── Tab type ──────────────────────────────────────────────────────────────────

type Tab = 'suppressions' | 'known-ips' | 'facts';

// ============================================================================
// Main Page
// ============================================================================

export default function Suppressions() {
  const [tab, setTab] = useState<Tab>('suppressions');

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-gray-100">AI Context & Suppressions</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Control what the AI knows about your environment and what it ignores
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-gray-800">
        {([
          { key: 'suppressions', label: 'Suppressions', icon: <ShieldOff size={14} /> },
          { key: 'known-ips', label: 'Known IPs', icon: <Wifi size={14} /> },
          { key: 'facts', label: 'Environment Facts', icon: <Brain size={14} /> },
        ] as { key: Tab; label: string; icon: React.ReactNode }[]).map(({ key, label, icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === key
                ? 'text-cyan-400 border-cyan-400'
                : 'text-gray-500 border-transparent hover:text-gray-300'
            }`}
          >
            {icon}
            {label}
          </button>
        ))}
      </div>

      {tab === 'suppressions' && <SuppressionsTab />}
      {tab === 'known-ips' && <KnownIpsTab />}
      {tab === 'facts' && <FactsTab />}
    </div>
  );
}

// ============================================================================
// Suppressions Tab
// ============================================================================

function SuppressionsTab() {
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formType, setFormType] = useState('EVENT_NAME');
  const [formValue, setFormValue] = useState('');
  const [formReason, setFormReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    try {
      const data = await fetchSuppressions();
      setRules(data as SuppressionRule[]);
    } catch { } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formValue.trim() || !formReason.trim()) { setError('Value and reason are required'); return; }
    setSubmitting(true); setError('');
    try {
      await createSuppression({ type: formType, value: formValue.trim(), reason: formReason.trim(), created_by: 'analyst-001' });
      setFormValue(''); setFormReason(''); setShowForm(false);
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : 'Failed'); }
    finally { setSubmitting(false); }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Remove this suppression rule?')) return;
    try { await deleteSuppression(id); await load(); } catch { }
  };

  if (loading) return <div className="flex items-center gap-2 text-gray-400"><Loader2 size={16} className="animate-spin" /> Loading…</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">{rules.length} active rules — events matching these rules are silently dropped before reaching the AI</p>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600">
            <RefreshCw size={13} /> Refresh
          </button>
          {!showForm && (
            <button onClick={() => setShowForm(true)} className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30">
              <Plus size={14} /> Add Rule
            </button>
          )}
        </div>
      </div>

      {showForm && (
        <div className="glass-panel p-5 border-cyan-500/30">
          <h2 className="text-sm font-semibold text-gray-200 mb-4">New Suppression Rule</h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Type</label>
                <select value={formType} onChange={(e) => setFormType(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none">
                  {Object.entries(TYPE_LABELS).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Value</label>
                <input type="text" value={formValue} onChange={(e) => setFormValue(e.target.value)}
                  placeholder={TYPE_PLACEHOLDERS[formType]}
                  className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none font-mono" required />
              </div>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Reason</label>
              <input type="text" value={formReason} onChange={(e) => setFormReason(e.target.value)}
                placeholder="e.g. Known CI/CD pipeline activity"
                className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none" required />
            </div>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-3">
              <button type="submit" disabled={submitting}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 disabled:opacity-50">
                {submitting ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Create Rule
              </button>
              <button type="button" onClick={() => setShowForm(false)}
                className="px-4 py-2 text-gray-400 border border-gray-700 rounded-lg text-sm hover:border-gray-600">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="glass-panel p-12 text-center">
          <ShieldOff size={32} className="text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No suppression rules configured.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map((rule) => (
            <div key={rule.id} className="glass-panel p-4 flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="px-2 py-0.5 text-xs rounded bg-gray-800 text-gray-400 font-medium">{TYPE_LABELS[rule.type] ?? rule.type}</span>
                  <span className="text-sm text-gray-200 font-mono truncate">{rule.value}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-500">
                  <span>{rule.reason}</span>
                  <span>· by {rule.created_by}</span>
                  <span>· {new Date(rule.created_at).toLocaleDateString()}</span>
                </div>
              </div>
              <button onClick={() => handleDelete(rule.id)}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/10 flex-shrink-0">
                <Trash2 size={12} /> Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="glass-panel p-4">
        <p className="text-xs text-gray-500 leading-relaxed">
          Suppression rules are checked before any event reaches the AI. Suppressed events are silently dropped — no incidents, no AI tokens, no dashboard entries.
        </p>
      </div>
    </div>
  );
}

// ============================================================================
// Known IPs Tab
// ============================================================================

function KnownIpsTab() {
  const [ips, setIps] = useState<KnownIp[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formIp, setFormIp] = useState('');
  const [formLabel, setFormLabel] = useState('');
  const [formOwner, setFormOwner] = useState('');
  const [formNotes, setFormNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    try { const data = await fetchKnownIps(); setIps(data as KnownIp[]); }
    catch { } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formIp.trim() || !formLabel.trim() || !formOwner.trim()) { setError('IP, label, and owner are required'); return; }
    setSubmitting(true); setError('');
    try {
      await addKnownIp({ ip: formIp.trim(), label: formLabel.trim(), owner: formOwner.trim(), notes: formNotes.trim() || undefined });
      setFormIp(''); setFormLabel(''); setFormOwner(''); setFormNotes(''); setShowForm(false);
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : 'Failed'); }
    finally { setSubmitting(false); }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Remove this known IP? The AI will no longer treat it as trusted.')) return;
    try { await deleteKnownIp(id); await load(); } catch { }
  };

  if (loading) return <div className="flex items-center gap-2 text-gray-400"><Loader2 size={16} className="animate-spin" /> Loading…</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">{ips.length} trusted IPs — the AI uses these to reduce false positives for known admin activity</p>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600">
            <RefreshCw size={13} /> Refresh
          </button>
          {!showForm && (
            <button onClick={() => setShowForm(true)} className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30">
              <Plus size={14} /> Add IP
            </button>
          )}
        </div>
      </div>

      {showForm && (
        <div className="glass-panel p-5 border-cyan-500/30">
          <h2 className="text-sm font-semibold text-gray-200 mb-1">Add Trusted IP</h2>
          <p className="text-xs text-gray-500 mb-4">
            The AI will lower its threat confidence for activity from this IP, but will still flag dangerous actions regardless of source.
          </p>
          <form onSubmit={handleCreate} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">IP Address <span className="text-red-400">*</span></label>
                <input type="text" value={formIp} onChange={(e) => setFormIp(e.target.value)}
                  placeholder="157.35.3.83"
                  className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none font-mono" required />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Label <span className="text-red-400">*</span></label>
                <input type="text" value={formLabel} onChange={(e) => setFormLabel(e.target.value)}
                  placeholder="e.g. Office Network, Admin VPN"
                  className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none" required />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Owner <span className="text-red-400">*</span></label>
                <input type="text" value={formOwner} onChange={(e) => setFormOwner(e.target.value)}
                  placeholder="e.g. DevOps Team, John Smith"
                  className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none" required />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Notes (optional)</label>
                <input type="text" value={formNotes} onChange={(e) => setFormNotes(e.target.value)}
                  placeholder="e.g. Used for AWS console access only"
                  className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none" />
              </div>
            </div>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-3">
              <button type="submit" disabled={submitting}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 disabled:opacity-50">
                {submitting ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Add Trusted IP
              </button>
              <button type="button" onClick={() => setShowForm(false)}
                className="px-4 py-2 text-gray-400 border border-gray-700 rounded-lg text-sm hover:border-gray-600">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {ips.length === 0 ? (
        <div className="glass-panel p-12 text-center">
          <Wifi size={32} className="text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No trusted IPs configured.</p>
          <p className="text-gray-600 text-xs mt-1">Add your office IP, VPN, or admin workstation IPs to reduce false positives.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {ips.map((ip) => (
            <div key={ip.id} className="glass-panel p-4 flex items-center gap-4">
              <div className="w-8 h-8 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center flex-shrink-0">
                <Wifi size={14} className="text-emerald-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-0.5">
                  <span className="text-sm font-mono text-gray-200">{ip.ip}</span>
                  <span className="px-2 py-0.5 text-xs rounded bg-emerald-500/10 text-emerald-400">{ip.label}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-500">
                  <span>Owner: {ip.owner}</span>
                  {ip.notes && <span>· {ip.notes}</span>}
                  <span>· Added {new Date(ip.created_at).toLocaleDateString()}</span>
                </div>
              </div>
              <button onClick={() => handleDelete(ip.id)}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/10 flex-shrink-0">
                <Trash2 size={12} /> Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="glass-panel p-4">
        <p className="text-xs text-gray-500 leading-relaxed">
          <strong className="text-gray-400">Important:</strong> Known IPs reduce false positives but do NOT suppress detections.
          The AI will still flag dangerous actions (CreateUser, StopLogging, AttachUserPolicy) from trusted IPs —
          it just won't treat the IP itself as a threat indicator. Off-hours activity from trusted IPs is still noted.
        </p>
      </div>
    </div>
  );
}

// ============================================================================
// Environment Facts Tab
// ============================================================================

function FactsTab() {
  const [facts, setFacts] = useState<EnvironmentFact[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formFact, setFormFact] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    try { const data = await fetchEnvironmentFacts(); setFacts(data as EnvironmentFact[]); }
    catch { } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formFact.trim()) { setError('Fact cannot be empty'); return; }
    setSubmitting(true); setError('');
    try {
      await addEnvironmentFact(formFact.trim());
      setFormFact(''); setShowForm(false);
      await load();
    } catch (err) { setError(err instanceof Error ? err.message : 'Failed'); }
    finally { setSubmitting(false); }
  };

  const handleDelete = async (index: number) => {
    if (!confirm('Remove this environment fact?')) return;
    try { await deleteEnvironmentFact(index); await load(); } catch { }
  };

  if (loading) return <div className="flex items-center gap-2 text-gray-400"><Loader2 size={16} className="animate-spin" /> Loading…</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">{facts.length} facts injected into every AI prompt</p>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600">
            <RefreshCw size={13} /> Refresh
          </button>
          {!showForm && (
            <button onClick={() => setShowForm(true)} className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30">
              <Plus size={14} /> Add Fact
            </button>
          )}
        </div>
      </div>

      {showForm && (
        <div className="glass-panel p-5 border-cyan-500/30">
          <h2 className="text-sm font-semibold text-gray-200 mb-1">Add Environment Fact</h2>
          <p className="text-xs text-gray-500 mb-4">Write a plain English statement about your environment. The AI reads this before analyzing every event.</p>
          <form onSubmit={handleCreate} className="space-y-3">
            <textarea
              value={formFact}
              onChange={(e) => setFormFact(e.target.value)}
              placeholder="e.g. The CI/CD pipeline runs from IP 10.0.1.50 and regularly creates and deletes IAM roles — this is expected behavior."
              rows={3}
              className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none resize-none"
              required
            />
            {error && <p className="text-xs text-red-400">{error}</p>}
            <div className="flex gap-3">
              <button type="submit" disabled={submitting}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 disabled:opacity-50">
                {submitting ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Add Fact
              </button>
              <button type="button" onClick={() => setShowForm(false)}
                className="px-4 py-2 text-gray-400 border border-gray-700 rounded-lg text-sm hover:border-gray-600">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {facts.length === 0 ? (
        <div className="glass-panel p-12 text-center">
          <Brain size={32} className="text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No environment facts configured.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {facts.map(({ index, fact }) => (
            <div key={index} className="glass-panel p-4 flex items-start gap-4">
              <div className="w-6 h-6 rounded-full bg-gray-800 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Brain size={12} className="text-gray-500" />
              </div>
              <p className="text-sm text-gray-300 flex-1 leading-relaxed">{fact}</p>
              <button onClick={() => handleDelete(index)}
                className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/10 flex-shrink-0">
                <Trash2 size={12} /> Remove
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="glass-panel p-4">
        <p className="text-xs text-gray-500 leading-relaxed">
          Environment facts are injected into every AI prompt. Use them to describe your infrastructure, known automation, trusted accounts, and expected behavior patterns. The more context the AI has, the fewer false positives it generates.
        </p>
      </div>
    </div>
  );
}
