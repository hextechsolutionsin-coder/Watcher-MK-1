import { useState, useEffect } from 'react';
import { Filter, Loader2, RotateCcw, RefreshCw, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import ApprovalCard from '../components/ApprovalCard';
import { fetchApprovals, approveAction, rejectAction, retryAction, fetchActions } from '../api/client';
import { SeverityLevel } from '../types';
import type { RemediationAction } from '../types';
import SeverityBadge from '../components/SeverityBadge';

interface ActionWithAI extends RemediationAction {
  ai_reasoning?: string;
  ai_params?: Record<string, unknown>;
  blast_radius?: string;
  rollback_description?: string;
  outcome?: string;
}

export default function ApprovalQueue() {
  const [pendingActions, setPendingActions] = useState<ActionWithAI[]>([]);
  const [failedActions, setFailedActions] = useState<ActionWithAI[]>([]);
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'pending' | 'failed'>('pending');

  async function loadData() {
    try {
      setLoading(true);
      const [approvals, allActions] = await Promise.all([
        fetchApprovals(),
        fetchActions(),
      ]);
      setPendingActions(approvals as ActionWithAI[]);
      setFailedActions((allActions as ActionWithAI[]).filter((a) => a.status === 'FAILED'));
      setError(null);
    } catch (err) {
      setError('Unable to load approvals. Make sure the API server is running.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(loadData, 10_000);
    return () => clearInterval(interval);
  }, []);

  const filteredPending = pendingActions
    .filter((a) => severityFilter === 'ALL' || a.severity_level === severityFilter)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const filteredFailed = failedActions
    .filter((a) => severityFilter === 'ALL' || a.severity_level === severityFilter)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const handleApprove = async (id: string) => {
    try {
      await approveAction(id, 'analyst-001');
      await loadData();
    } catch (err) {
      console.error('Failed to approve action:', err);
    }
  };

  const handleReject = async (id: string) => {
    try {
      const reason = prompt('Rejection reason:');
      if (!reason) return;
      await rejectAction(id, 'analyst-001', reason);
      await loadData();
    } catch (err) {
      console.error('Failed to reject action:', err);
    }
  };

  const handleRetry = async (id: string) => {
    try {
      await retryAction(id);
      await loadData();
    } catch (err) {
      console.error('Failed to retry action:', err);
    }
  };

  if (loading && pendingActions.length === 0) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <div className="flex items-center gap-3 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span>Loading approvals...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="glass-panel p-8 text-center">
          <p className="text-red-400 mb-2">⚠ Connection Error</p>
          <p className="text-gray-400 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Approval Queue</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {pendingActions.length} pending · {failedActions.length} failed
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
        >
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-gray-800 pb-0">
        <button
          onClick={() => setTab('pending')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            tab === 'pending'
              ? 'text-cyan-400 border-cyan-400'
              : 'text-gray-500 border-transparent hover:text-gray-300'
          }`}
        >
          Pending Approval ({pendingActions.length})
        </button>
        <button
          onClick={() => setTab('failed')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            tab === 'failed'
              ? 'text-red-400 border-red-400'
              : 'text-gray-500 border-transparent hover:text-gray-300'
          }`}
        >
          Failed ({failedActions.length})
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Filter size={14} />
          <span>Severity:</span>
        </div>
        <div className="flex gap-1">
          {['ALL', ...Object.values(SeverityLevel)].map((level) => (
            <button
              key={level}
              onClick={() => setSeverityFilter(level as SeverityLevel | 'ALL')}
              className={`px-3 py-1 text-xs rounded-full transition-colors ${
                severityFilter === level
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800 border border-transparent'
              }`}
            >
              {level === 'ALL' ? 'All' : level}
            </button>
          ))}
        </div>
      </div>

      {/* Pending Tab */}
      {tab === 'pending' && (
        <div className="space-y-3">
          {filteredPending.length === 0 ? (
            <div className="glass-panel p-12 text-center">
              <CheckCircle size={32} className="text-emerald-400 mx-auto mb-3 opacity-50" />
              <p className="text-gray-400">No pending approvals.</p>
              <p className="text-gray-600 text-xs mt-1">Actions will appear here when the AI detects threats and recommends responses.</p>
            </div>
          ) : (
            filteredPending.map((action) => (
              <ApprovalCard
                key={action.id}
                action={action}
                onApprove={handleApprove}
                onReject={handleReject}
              />
            ))
          )}
        </div>
      )}

      {/* Failed Tab */}
      {tab === 'failed' && (
        <div className="space-y-3">
          {filteredFailed.length === 0 ? (
            <div className="glass-panel p-12 text-center">
              <p className="text-gray-400">No failed actions.</p>
            </div>
          ) : (
            filteredFailed.map((action) => (
              <div key={action.id} className="glass-panel p-4 border-l-2 border-l-red-500/50">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <XCircle size={14} className="text-red-400" />
                      <SeverityBadge severity={action.severity_level} />
                      <span className="text-sm font-semibold text-gray-200">
                        {action.action_type.replace(/aws:/g, '').replace(/[_:]/g, ' ').toUpperCase()}
                      </span>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs text-gray-400">
                        Target: <span className="text-gray-300 font-mono">{action.affected_asset?.identifier ?? 'unknown'}</span>
                      </p>
                      {action.outcome && (
                        <div className="flex items-start gap-2 p-2 bg-red-500/10 border border-red-500/20 rounded text-xs text-red-400 mt-2">
                          <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
                          <span>{action.outcome}</span>
                        </div>
                      )}
                      {action.ai_reasoning && (
                        <p className="text-xs text-gray-500 mt-1">AI: {action.ai_reasoning}</p>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRetry(action.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded-lg text-xs font-medium hover:bg-amber-500/20 transition-colors flex-shrink-0"
                  >
                    <RotateCcw size={14} />
                    Retry
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
