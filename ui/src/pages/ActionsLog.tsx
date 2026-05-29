import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Filter, RefreshCw, Loader2 } from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { fetchActions } from '../api/client';
import { SeverityLevel } from '../types';
import type { RemediationAction } from '../types';

// Action types for filter dropdown
const ACTION_TYPES = [
  'BLOCK_IP', 'ISOLATE_HOST', 'REVOKE_CREDENTIALS', 'ROTATE_CREDENTIALS',
  'QUARANTINE_FILE', 'DISABLE_USER_ACCOUNT', 'CREATE_TICKET', 'SEND_ALERT',
  'TERMINATE_PROCESS', 'PUSH_FIREWALL_RULE', 'SEGMENT_NETWORK', 'SCAN_ENDPOINT',
];

function formatDateTime(timestamp: string): string {
  return new Date(timestamp).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function getOutcomeStyle(outcome?: string): string {
  switch (outcome) {
    case 'SUCCESS': return 'bg-emerald-500/10 text-emerald-400';
    case 'FAILURE': return 'bg-red-500/10 text-red-400';
    case 'ESCALATED': return 'bg-amber-500/10 text-amber-400';
    default: return 'bg-gray-500/10 text-gray-400';
  }
}

export default function ActionsLog() {
  const [allActions, setAllActions] = useState<RemediationAction[]>([]);
  const [actionTypeFilter, setActionTypeFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadActions() {
      try {
        setLoading(true);
        const data = await fetchActions();
        setAllActions(data as RemediationAction[]);
        setError(null);
      } catch (err) {
        setError('Unable to load actions. Make sure the API server is running.');
      } finally {
        setLoading(false);
      }
    }
    loadActions();
  }, []);

  const filteredActions = allActions
    .filter((a) => a.execution_timestamp || a.outcome)
    .filter((a) => actionTypeFilter === 'ALL' || a.action_type === actionTypeFilter)
    .filter((a) => severityFilter === 'ALL' || a.severity_level === severityFilter)
    .filter((a) => outcomeFilter === 'ALL' || a.outcome === outcomeFilter)
    .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <div className="flex items-center gap-3 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span>Loading actions log...</span>
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
          <h1 className="text-xl font-bold text-gray-100">Autonomous Actions Log</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            History of all executed remediation actions
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <Filter size={14} />
          <span>Filters:</span>
        </div>

        {/* Action Type */}
        <select
          value={actionTypeFilter}
          onChange={(e) => setActionTypeFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-1.5 focus:border-cyan-500 focus:outline-none"
        >
          <option value="ALL">All Action Types</option>
          {ACTION_TYPES.map((type) => (
            <option key={type} value={type}>{type.replace(/_/g, ' ')}</option>
          ))}
        </select>

        {/* Severity */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as SeverityLevel | 'ALL')}
          className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-1.5 focus:border-cyan-500 focus:outline-none"
        >
          <option value="ALL">All Severities</option>
          {Object.values(SeverityLevel).map((level) => (
            <option key={level} value={level}>{level}</option>
          ))}
        </select>

        {/* Outcome */}
        <select
          value={outcomeFilter}
          onChange={(e) => setOutcomeFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-1.5 focus:border-cyan-500 focus:outline-none"
        >
          <option value="ALL">All Outcomes</option>
          <option value="SUCCESS">SUCCESS</option>
          <option value="FAILURE">FAILURE</option>
          <option value="ESCALATED">ESCALATED</option>
        </select>
      </div>

      {/* Table */}
      <div className="glass-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800 bg-gray-900/50">
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Action Type</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Incident</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Target Asset</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Executed</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Outcome</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Retries</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {filteredActions.map((action) => (
                <tr key={action.id} className="hover:bg-gray-800/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-200 font-medium">
                      {action.action_type.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/incidents/${action.incident_id}`}
                      className="text-sm font-mono text-cyan-400 hover:text-cyan-300"
                    >
                      {action.incident_id}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={action.severity_level} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-400 truncate block max-w-[200px]">
                      {action.affected_asset.identifier}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-gray-500">
                      {action.execution_timestamp ? formatDateTime(action.execution_timestamp) : '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getOutcomeStyle(action.outcome)}`}>
                      {action.outcome || 'PENDING'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {action.retry_count > 0 && <RefreshCw size={12} className="text-amber-400" />}
                      <span className={`text-xs ${action.retry_count > 0 ? 'text-amber-400' : 'text-gray-500'}`}>
                        {action.retry_count}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredActions.length === 0 && (
          <div className="p-12 text-center text-gray-400">
            No actions match the current filters.
          </div>
        )}
      </div>
    </div>
  );
}
