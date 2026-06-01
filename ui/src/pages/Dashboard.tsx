import { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, ShieldAlert, Clock, Zap, Loader2, RefreshCw, Brain, Radio } from 'lucide-react';
import { Link } from 'react-router-dom';
import StatCard from '../components/StatCard';
import RiskGauge from '../components/RiskGauge';
import IncidentRow from '../components/IncidentRow';
import { fetchIncidents, fetchRiskScore, fetchApprovals, fetchActions, fetchPolledEventStats } from '../api/client';
import { IncidentStatus, SeverityLevel, getIncidentSeverity } from '../types';
import type { Incident } from '../types';

interface PolledStats {
  total: number;
  by_status: { PROCESSED: number; CORRELATED: number; SKIPPED: number };
}

export default function Dashboard() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [riskScore, setRiskScore] = useState<number>(0);
  const [pendingApprovals, setPendingApprovals] = useState<number>(0);
  const [autonomousActions, setAutonomousActions] = useState<number>(0);
  const [polledStats, setPolledStats] = useState<PolledStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const loadData = useCallback(async () => {
    try {
      const [incidentsData, riskData, approvalsData, actionsData, polledData] = await Promise.all([
        fetchIncidents(),
        fetchRiskScore(),
        fetchApprovals(),
        fetchActions(),
        fetchPolledEventStats().catch(() => null),
      ]);
      setIncidents(incidentsData as Incident[]);
      setRiskScore((riskData as any).score);
      setPendingApprovals((approvalsData as any[]).length);
      setAutonomousActions((actionsData as any[]).filter((a: any) => a.status === 'COMPLETED').length);
      if (polledData) setPolledStats(polledData as PolledStats);
      setError(null);
      setLastRefresh(new Date());
    } catch {
      setError('Unable to connect to API server. Make sure the server is running on port 4000.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  // Auto-refresh every 15 seconds
  useEffect(() => {
    const interval = setInterval(loadData, 15_000);
    return () => clearInterval(interval);
  }, [loadData]);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <div className="flex items-center gap-3 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span>Loading dashboard...</span>
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

  const criticalHigh = incidents.filter((i) => {
    const sev = getIncidentSeverity(i);
    return sev === SeverityLevel.CRITICAL || sev === SeverityLevel.HIGH;
  }).length;

  const filteredIncidents = statusFilter === 'ALL'
    ? incidents
    : incidents.filter((i) => i.status === statusFilter);

  // Sort: open/critical first, then by time
  const sortedIncidents = [...filteredIncidents].sort((a, b) => {
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };
    const aSev = sevOrder[getIncidentSeverity(a) as keyof typeof sevOrder] ?? 5;
    const bSev = sevOrder[getIncidentSeverity(b) as keyof typeof sevOrder] ?? 5;
    if (aSev !== bSev) return aSev - bSev;
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Security Operations</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Last updated {lastRefresh.toLocaleTimeString()}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
            <span>Live · auto-refresh 15s</span>
          </div>
          <button
            onClick={loadData}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Bar + Risk Gauge */}
      <div className="flex gap-6">
        <div className="flex-1 grid grid-cols-4 gap-4">
          <StatCard
            title="Total Incidents"
            value={incidents.length}
            subtitle={`${incidents.filter((i) => i.status === 'OPEN').length} open`}
            icon={<AlertTriangle size={16} />}
            accentColor="cyan"
          />
          <StatCard
            title="Critical / High"
            value={criticalHigh}
            subtitle="need attention"
            icon={<ShieldAlert size={16} />}
            accentColor="red"
          />
          <StatCard
            title="Pending Approvals"
            value={pendingApprovals}
            subtitle="awaiting review"
            icon={<Clock size={16} />}
            accentColor="amber"
          />
          <StatCard
            title="Actions Executed"
            value={autonomousActions}
            subtitle="this session"
            icon={<Zap size={16} />}
            accentColor="emerald"
          />
        </div>
        <div className="flex-shrink-0">
          <RiskGauge score={riskScore} size="sm" label="Overall Risk" />
        </div>
      </div>

      {/* Polling Activity Bar */}
      {polledStats && (
        <div className="glass-panel p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Radio size={14} className="text-cyan-400" />
              <span className="text-sm font-medium text-gray-200">Polling Activity</span>
              <span className="text-xs text-gray-500">this session</span>
            </div>
            <Link to="/events" className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
              View all events →
            </Link>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-3 bg-cyan-500/5 rounded-lg border border-cyan-500/10">
              <p className="text-2xl font-bold text-cyan-400">{polledStats.by_status.PROCESSED}</p>
              <p className="text-xs text-gray-500 mt-0.5">Sent to AI</p>
            </div>
            <div className="text-center p-3 bg-amber-500/5 rounded-lg border border-amber-500/10">
              <p className="text-2xl font-bold text-amber-400">{polledStats.by_status.CORRELATED}</p>
              <p className="text-xs text-gray-500 mt-0.5">Correlated</p>
            </div>
            <div className="text-center p-3 bg-gray-800/50 rounded-lg border border-gray-700/50">
              <p className="text-2xl font-bold text-gray-400">{polledStats.by_status.SKIPPED}</p>
              <p className="text-xs text-gray-500 mt-0.5">Skipped (noise)</p>
            </div>
          </div>
        </div>
      )}

      {/* Live Incident Feed */}
      <div className="glass-panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <Brain size={14} className="text-cyan-400" />
            <h2 className="text-sm font-semibold text-gray-200">Incident Feed</h2>
            <span className="text-xs text-gray-500">{filteredIncidents.length} shown</span>
          </div>
          <div className="flex gap-1">
            {['ALL', ...Object.values(IncidentStatus)].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 text-xs rounded-full transition-colors ${
                  statusFilter === status
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800 border border-transparent'
                }`}
              >
                {status === 'ALL' ? 'All' : status.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>

        {/* Column Headers */}
        <div className="flex items-center gap-4 px-4 py-2 text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800/50 bg-gray-900/50">
          <div className="w-20 flex-shrink-0">Severity</div>
          <div className="w-36 flex-shrink-0">Incident ID</div>
          <div className="w-28 flex-shrink-0">Surface</div>
          <div className="flex-1">Threat / MITRE</div>
          <div className="w-20 flex-shrink-0 text-right">Detected</div>
          <div className="w-28 flex-shrink-0 text-right">Status</div>
          <div className="w-48 flex-shrink-0 text-right hidden xl:block">Asset</div>
        </div>

        {/* Incident Rows */}
        <div className="max-h-[480px] overflow-y-auto">
          {sortedIncidents.length === 0 ? (
            <div className="p-12 text-center">
              <Brain size={32} className="text-gray-700 mx-auto mb-3" />
              <p className="text-gray-400">No incidents detected yet.</p>
              <p className="text-gray-600 text-xs mt-1">
                Watcher is monitoring your AWS account. Incidents will appear here when threats are detected.
              </p>
            </div>
          ) : (
            sortedIncidents.map((incident) => (
              <IncidentRow key={incident.id} incident={incident} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
