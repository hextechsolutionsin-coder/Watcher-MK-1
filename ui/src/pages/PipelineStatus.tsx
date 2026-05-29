import { useState, useEffect } from 'react';
import { Activity, Brain, Shield, Zap, RotateCcw, CheckCircle, XCircle, Loader2, ChevronRight } from 'lucide-react';
import TrustLevelBadge from '../components/TrustLevelBadge';
import { fetchPipelineStatus, fetchTrustLevel, fetchRollbacks } from '../api/client';
import type { PipelineStatus, TrustLevelInfo, RollbackEntry } from '../types';

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
  ai_reasoning_engine: 'AI Reasoning Engine',
  safety_gate: 'Safety Gate',
  action_executor: 'Action Executor',
  rollback_registry: 'Rollback Registry',
  approval_workflow: 'Approval Workflow',
};

export default function PipelineStatus() {
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [trust, setTrust] = useState<TrustLevelInfo | null>(null);
  const [rollbacks, setRollbacks] = useState<RollbackEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetchPipelineStatus().then((d) => setStatus(d as PipelineStatus)),
      fetchTrustLevel().then((d) => setTrust(d as TrustLevelInfo)),
      fetchRollbacks().then((d) => setRollbacks(d as RollbackEntry[])),
    ])
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

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
      <div>
        <h1 className="text-xl font-bold text-gray-100">AI Pipeline</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Real-time status of the autonomous reasoning and response pipeline
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Pipeline Components */}
        <div className="xl:col-span-2 space-y-4">
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-4">Pipeline Components</h2>

            {/* Flow diagram */}
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
                    <><XCircle size={11} className="text-amber-400" /><span className="text-xs text-amber-400">Set AWS_REGION env var</span></>
                  )}
                </div>
              </div>
              <div className="p-3 bg-gray-800/50 rounded-lg col-span-2">
                <p className="text-xs text-gray-500 mb-2">Reasoning Modes</p>
                <div className="flex flex-wrap gap-2">
                  {['REACTIVE', 'PROACTIVE', 'PREDICTIVE', 'INVESTIGATIVE'].map((mode) => (
                    <span key={mode} className="px-2 py-0.5 text-xs bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded">
                      {mode}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Available Rollbacks */}
          <div className="glass-panel p-5">
            <div className="flex items-center gap-2 mb-4">
              <RotateCcw size={16} className="text-amber-400" />
              <h2 className="text-sm font-semibold text-gray-200">Available Rollbacks</h2>
              <span className="ml-auto text-xs text-gray-500">{rollbacks.length} available</span>
            </div>

            {rollbacks.length === 0 ? (
              <p className="text-sm text-gray-500">No rollbacks available.</p>
            ) : (
              <div className="space-y-2">
                {rollbacks.map((rb) => (
                  <div key={rb.id} className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-gray-200">{rb.action_description}</p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        Undo: {rb.rollback_description}
                      </p>
                      <p className="text-xs text-gray-600 mt-0.5">
                        Expires {new Date(rb.expires_at).toLocaleTimeString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className={`px-1.5 py-0.5 text-xs rounded ${
                        rb.blast_radius === 'LOW' ? 'bg-emerald-500/10 text-emerald-400' :
                        rb.blast_radius === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400' :
                        'bg-red-500/10 text-red-400'
                      }`}>
                        {rb.blast_radius}
                      </span>
                      <button className="flex items-center gap-1 px-2 py-1 bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded text-xs hover:bg-amber-500/20 transition-colors">
                        <RotateCcw size={11} />
                        Undo
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
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
                        <span className="text-xs text-emerald-400 flex items-center gap-1">
                          <CheckCircle size={11} /> Auto
                        </span>
                      ) : (
                        <span className="text-xs text-amber-400 flex items-center gap-1">
                          <Shield size={11} /> Human
                        </span>
                      )}
                    </div>
                  ))}
                </div>

                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 mb-1">Last change</p>
                  <p className="text-xs text-gray-300">{trust.last_level_change_reason}</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {new Date(trust.last_level_change).toLocaleDateString()}
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* How to connect AWS */}
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-3">Connect AWS Account</h2>
            <div className="space-y-3 text-xs text-gray-400">
              <div className="flex gap-2">
                <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center flex-shrink-0 text-xs">1</span>
                <p>Deploy CloudFormation template in customer account to create cross-account IAM role</p>
              </div>
              <div className="flex gap-2">
                <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center flex-shrink-0 text-xs">2</span>
                <p>Register connector via <code className="text-cyan-400">POST /api/v1/connectors</code> with the role ARN</p>
              </div>
              <div className="flex gap-2">
                <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center flex-shrink-0 text-xs">3</span>
                <p>Set <code className="text-cyan-400">AWS_REGION</code> env var on Watcher server for Bedrock access</p>
              </div>
              <div className="flex gap-2">
                <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center flex-shrink-0 text-xs">4</span>
                <p>CloudTrail, GuardDuty, and Security Hub events start flowing to the AI</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
