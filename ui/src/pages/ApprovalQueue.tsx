import { useState, useEffect } from 'react';
import { Filter, Loader2 } from 'lucide-react';
import ApprovalCard from '../components/ApprovalCard';
import { fetchApprovals, approveAction, rejectAction } from '../api/client';
import { SeverityLevel } from '../types';
import type { RemediationAction } from '../types';

export default function ApprovalQueue() {
  const [actions, setActions] = useState<RemediationAction[]>([]);
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadApprovals() {
    try {
      setLoading(true);
      const data = await fetchApprovals();
      setActions(data as RemediationAction[]);
      setError(null);
    } catch (err) {
      setError('Unable to load approvals. Make sure the API server is running.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadApprovals();
  }, []);

  const pendingActions = actions
    .filter((a) => severityFilter === 'ALL' || a.severity_level === severityFilter)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

  const handleApprove = async (id: string) => {
    try {
      await approveAction(id, 'analyst-001');
      // Refresh the list
      await loadApprovals();
    } catch (err) {
      console.error('Failed to approve action:', err);
    }
  };

  const handleReject = async (id: string) => {
    try {
      await rejectAction(id, 'analyst-001', 'Rejected by analyst');
      // Refresh the list
      await loadApprovals();
    } catch (err) {
      console.error('Failed to reject action:', err);
    }
  };

  if (loading) {
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
            {pendingActions.length} actions awaiting analyst approval
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Filter size={14} />
          <span>Filter by severity:</span>
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

      {/* Approval Cards */}
      <div className="space-y-3">
        {pendingActions.length === 0 ? (
          <div className="glass-panel p-12 text-center">
            <p className="text-gray-400">No pending approvals matching the current filter.</p>
          </div>
        ) : (
          pendingActions.map((action) => (
            <ApprovalCard
              key={action.id}
              action={action}
              onApprove={handleApprove}
              onReject={handleReject}
            />
          ))
        )}
      </div>
    </div>
  );
}
