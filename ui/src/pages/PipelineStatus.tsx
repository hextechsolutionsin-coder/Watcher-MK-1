import { useState, useEffect, useCallback } from 'react';
import {
  Activity, Brain, Shield, Zap, RotateCcw, CheckCircle, XCircle,
  Loader2, ChevronRight, RefreshCw, Wifi, Clock, Radio,
} from 'lucide-react';
import TrustLevelBadge from '../components/TrustLevelBadge';
import { fetchPipelineStatus, fetchTrustLevel, fetchRollbacks } from '../api/client';
import type { TrustLevelInfo, RollbackEntry } from '../types';

interface PipelineStatusData {
  status: string;
  components: Record<string, string>;
  ai_model: string;
  bedrock_region: string;
  bedrock_connected: boolean;
  connectors: Array<{
    id: string;
    account_id: string;
    status: string;
    last_poll_at: string | null;
    regions: string[];
    data_sources: string[];
  }>;
  correlator: {
    processed_event_ids: number;
    actor_incident_mappings: number;
    open_incidents: number;
  };
  store_summary: {
    incidents: number;
    open_incidents: number;
    pending_approvals: number;
    total_actions: number;
  };
  timestamp: string;
}

const componentIcons: Record<string, React.ReactNode> = {
  fast_filter: <Zap size={14} />,
  ai_reasoning_engine: <Brain size={14} />,
  safety_gate: <Shield size={14} />,
  action_executor: <Activity size={14} />,
  rollback_registry: <RotateCcw size={14} />,
  approval_workflow: <CheckCircle size={14} />,
};

const componentLabels: Record<string, string> = {
  fast_filter: 'Fast Filter',
  ai_reasoning_engine: 'AI Reasoning Engine (Claude Sonnet 4.6)',
  safety_gate: 'Safety Gate',
  action_executor: 'Action Executor',
  rollback_registry: 'Rollback Registry',
  approval_workflow: 'Approval Workflow',
};

function formatLastPoll(ts: string | null): string {
  if (!ts) return 'Not yet polled';
  const diff = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  return `${Math.floor(diff / 60)}m ${diff % 60}s ago`;
}

export default function PipelineStatus() {
  const [status, setStatus] = useState<PipelineStatusData | null>(null);
  const [trust, setTrust] = useState<TrustLevelInfo | null>(null);
  const [rollbacks, setRollbacks] = useState<RollbackEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const load = useCallback(async () => {
    try {
      const [s, t, r] = await Promise.all([
        fetchPipelineStatus(),
        fetchTrustLevel(),
        fetchRollbacks(),
      ]);
      setStatus(s as PipelineStatusData);
      setTrust(t as TrustLevelInfo);
      setRollbacks(r as RollbackEntry[]);
      setLastRefresh(new Date());
    } catch { }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(load, 10_000);
    return () => clearInterval(interval);
  }, [load]);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <div className="flex items-center gap-3 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span>Loading pipeline status...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">AI Pipeline</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Real-time status · Last updated {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors">
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Live Stats Bar */}
      {status && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Incidents', value: status.store_summary.incidents, color: 'text-gray-100' },
            { label: 'Open Incidents', value: status.store_summary.open_incidents, color: 'text-red-400' },
            { label: 'Pending Approvals', value: status.store_summary.pending_approvals, color: 'text-amber-400' },
            { label: 'Events Deduplicated', value: status.correlator.processed_event_ids, color: 'text-cyan-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="glass-panel p-4">
              <p className="text-xs text-gray-500 mb-1">{label}</p>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: Pipeline + Connectors */}
        <div className="xl:col-span-2 space-y-4">

          {/* Pipeline Components */}
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-4">Pipeline Components</h2>
            <div className="space-y-2">
              {Object.entries(status?.components ?? {}).map(([key, componentStatus], idx, arr) => (
                <div key={key}>
                  <div className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${
                      componentStatus === 'active' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-gray-700 text-gray-400'
                    }`}>
                      {componentIcons[key] ?? <Activity size={14} />}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm text-gray-200">{componentLabels[key] ?? key}</p>
                      <p className="text-xs text-gray-500 capitalize">{componentStatus}</p>
                    </div>
                    <div className={`w-2 h-2 rounded-full ${
                      componentStatus === 'active' ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'
                    }`} />
                  </div>
                  {idx < arr.length - 1 && (
                    <div className="flex justify-center py-1">
                      <ChevronRight size={14} className="text-gray-600 rotate-90" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Connectors + Polling Status */}
          <div className="glass-panel p-5">
            <div className="flex items-center gap-2 mb-4">
              <Radio size={14} className="text-cyan-400" />
              <h2 className="text-sm font-semibold text-gray-200">Connectors & Polling</h2>
            </div>

            {!status?.connectors?.length ? (
              <p className="text-sm text-gray-500">No connectors registered. Go to Connectors to add an AWS account.</p>
            ) : (
              <div className="space-y-3">
                {status.connectors.map((c) => (
                  <div key={c.id} className="p-4 bg-gray-800/50 rounded-lg">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`w-2 h-2 rounded-full ${c.status === 'ACTIVE' ? 'bg-emerald-400 animate-pulse' : c.status === 'ERROR' ? 'bg-red-400' : 'bg-gray-500'}`} />
                        <span className="text-sm font-mono text-gray-200">{c.account_id}</span>
                        <span className={`px-2 py-0.5 text-xs rounded ${
                          c.status === 'ACTIVE' ? 'bg-emerald-500/10 text-emerald-400' :
                          c.status === 'ERROR' ? 'bg-red-500/10 text-red-400' :
                          'bg-gray-700 text-gray-400'
                        }`}>{c.status}</span>
                      </div>
                      <div className="flex items-center gap-1 text-xs text-gray-500">
                        <Clock size={11} />
                        <span>{formatLastPoll(c.last_poll_at)}</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <p className="text-gray-500 mb-1">Regions</p>
                        <p className="text-gray-300">{c.regions.join(', ')}</p>
                      </div>
                      <div>
                        <p className="text-gray-500 mb-1">Data Sources</p>
                        <div className="flex flex-wrap gap-1">
                          {c.data_sources.map((ds) => (
                            <span key={ds} className="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-xs">{ds}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* AI Model Info */}
          <div className="glass-panel p-5">
            <div className="flex items-center gap-2 mb-4">
              <Brain size={16} className="text-cyan-400" />
              <h2 className="text-sm font-semibold text-gray-200">AI Reasoning Engine</h2>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-gray-800/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Model</p>
                <p className="text-sm text-gray-200 font-mono">Claude Sonnet 4.6</p>
                <p className="text-xs text-gray-500 mt-0.5">via AWS Bedrock</p>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Region</p>
                <p className="text-sm text-gray-200 font-mono">{status?.bedrock_region ?? '—'}</p>
                <div className="flex items-center gap-1 mt-0.5">
                  {status?.bedrock_connected ? (
                    <><CheckCircle size={11} className="text-emerald-400" /><span className="text-xs text-emerald-400">Connected</span></>
                  ) : (
                    <><XCircle size={11} className="text-amber-400" /><span className="text-xs text-amber-400">Set AWS_REGION</span></>
                  )}
                </div>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Actor→Incident Mappings</p>
                <p className="text-sm text-gray-200">{status?.correlator.actor_incident_mappings ?? 0} active</p>
                <p className="text-xs text-gray-500 mt-0.5">30-min TTL</p>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Reasoning Modes</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {['REACTIVE', 'PROACTIVE', 'PREDICTIVE'].map((mode) => (
                    <span key={mode} className="px-1.5 py-0.5 text-xs bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded">
                      {mode}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Rollbacks */}
          {rollbacks.length > 0 && (
            <div className="glass-panel p-5">
              <div className="flex items-center gap-2 mb-4">
                <RotateCcw size={16} className="text-amber-400" />
                <h2 className="text-sm font-semibold text-gray-200">Available Rollbacks</h2>
                <span className="ml-auto text-xs text-gray-500">{rollbacks.length} available</span>
              </div>
              <div className="space-y-2">
                {rollbacks.map((rb) => (
                  <div key={rb.id} className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-gray-200">{rb.action_description}</p>
                      <p className="text-xs text-gray-500 mt-0.5">Undo: {rb.rollback_description}</p>
                    </div>
                    <span className={`px-1.5 py-0.5 text-xs rounded ${
                      rb.blast_radius === 'LOW' ? 'bg-emerald-500/10 text-emerald-400' :
                      rb.blast_radius === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400' :
                      'bg-red-500/10 text-red-400'
                    }`}>{rb.blast_radius}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: Trust Level */}
        <div className="space-y-4">
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-4">AI Trust Level</h2>
            <TrustLevelBadge trust={trust} />
            {trust && (
              <div className="mt-4 space-y-3">
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 mb-2">Autonomy by blast radius</p>
                  {[
                    { label: 'Read-only (NONE)', auto: true },
                    { label: 'Single resource (LOW)', auto: trust.trust_level >= 2 },
                    { label: 'Multi-resource (MEDIUM)', auto: trust.trust_level >= 3 },
                    { label: 'Environment-wide (HIGH)', auto: false },
                  ].map(({ label, auto }) => (
                    <div key={label} className="flex items-center justify-between py-1">
                      <span className="text-xs text-gray-400">{label}</span>
                      {auto ? (
                        <span className="text-xs text-emerald-400 flex items-center gap-1"><CheckCircle size={11} /> Auto</span>
                      ) : (
                        <span className="text-xs text-amber-400 flex items-center gap-1"><Shield size={11} /> Human</span>
                      )}
                    </div>
                  ))}
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 mb-1">Approval rate (30d)</p>
                  <p className="text-lg font-bold text-gray-100">{trust.approval_rate_30d}%</p>
                  <p className="text-xs text-gray-500">{trust.approved_actions_30d} / {trust.total_actions_30d} actions</p>
                </div>
              </div>
            )}
          </div>

          {/* Polling config info */}
          <div className="glass-panel p-5">
            <div className="flex items-center gap-2 mb-3">
              <Wifi size={14} className="text-cyan-400" />
              <h2 className="text-sm font-semibold text-gray-200">Polling Configuration</h2>
            </div>
            <div className="space-y-2 text-xs">
              {[
                { label: 'Poll interval', value: '60s (configurable via POLL_INTERVAL_SECONDS)' },
                { label: 'Event filter', value: 'Write events only (readOnly: false)' },
                { label: 'Max events/cycle', value: '500 (10 pages × 50)' },
                { label: 'Lookback on start', value: '10 minutes' },
                { label: 'Correlation window', value: '30 minutes' },
                { label: 'Re-analysis threshold', value: 'Every 5 correlated events' },
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between py-1 border-b border-gray-800/50">
                  <span className="text-gray-500">{label}</span>
                  <span className="text-gray-300 text-right">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
