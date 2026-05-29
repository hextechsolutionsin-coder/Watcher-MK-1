import { useState, useEffect } from 'react';
import { AlertTriangle, ShieldAlert, Clock, Zap, Loader2 } from 'lucide-react';
import StatCard from '../components/StatCard';
import RiskGauge from '../components/RiskGauge';
import IncidentRow from '../components/IncidentRow';
import { fetchIncidents, fetchRiskScore, fetchApprovals, fetchActions } from '../api/client';
import { IncidentStatus, SeverityLevel, getIncidentSeverity } from '../types';
import type { Incident } from '../types';

export default function Dashboard() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [riskScore, setRiskScore] = useState<number>(0);
  const [pendingApprovals, setPendingApprovals] = useState<number>(0);
  const [autonomousActions, setAutonomousActions] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [incidentsData, riskData, approvalsData, actionsData] = await Promise.all([
          fetchIncidents(),
          fetchRiskScore(),
          fetchApprovals(),
          fetchActions(),
        ]);
        setIncidents(incidentsData as Incident[]);
        setRiskScore(riskData.score);
        setPendingApprovals(approvalsData.length);
        setAutonomousActions(actionsData.filter((a: any) => a.status === 'COMPLETED').length);
        setError(null);
      } catch (err) {
        setError('Unable to connect to API server. Make sure the server is running on port 4000.');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

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

  const criticalHigh = incidents.filter(
    (i) => {
      const sev = getIncidentSeverity(i);
      return sev === SeverityLevel.CRITICAL || sev === SeverityLevel.HIGH;
    }
  ).length;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Security Operations Dashboard</h1>
          <p className="text-sm text-gray-500 mt-0.5">Real-time threat monitoring and incident management</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
          <span>Live</span>
          <span className="text-gray-600">|</span>
          <span>{new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Stats Bar + Risk Gauge */}
      <div className="flex gap-6">
        <div className="flex-1 grid grid-cols-4 gap-4">
          <StatCard
            title="Total Incidents"
            value={incidents.length}
            subtitle="today"
            icon={<AlertTriangle size={16} />}
            accentColor="cyan"
          />
          <StatCard
            title="Critical / High"
            value={criticalHigh}
            subtitle="active"
            icon={<ShieldAlert size={16} />}
            accentColor="red"
          />
          <StatCard
            title="Pending Approvals"
            value={pendingApprovals}
            subtitle="awaiting"
            icon={<Clock size={16} />}
            accentColor="amber"
          />
          <StatCard
            title="Autonomous Actions"
            value={autonomousActions}
            subtitle="today"
            icon={<Zap size={16} />}
            accentColor="emerald"
          />
        </div>
        <div className="flex-shrink-0">
          <RiskGauge score={riskScore} size="sm" label="Overall Risk" />
        </div>
      </div>

      {/* Live Incident Feed */}
      <div className="glass-panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-200">Live Incident Feed</h2>
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500">{incidents.length} incidents</span>
            <div className="flex gap-1">
              {Object.values(IncidentStatus).map((status) => (
                <button
                  key={status}
                  className="px-2 py-0.5 text-xs text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded transition-colors"
                >
                  {status.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Column Headers */}
        <div className="flex items-center gap-4 px-4 py-2 text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800/50 bg-gray-900/50">
          <div className="w-20 flex-shrink-0">Severity</div>
          <div className="w-36 flex-shrink-0">Incident ID</div>
          <div className="w-28 flex-shrink-0">Surface</div>
          <div className="flex-1">MITRE ATT&CK</div>
          <div className="w-20 flex-shrink-0 text-right">Detected</div>
          <div className="w-28 flex-shrink-0 text-right">Status</div>
          <div className="w-48 flex-shrink-0 text-right hidden xl:block">Asset</div>
        </div>

        {/* Incident Rows */}
        <div className="max-h-[480px] overflow-y-auto">
          {incidents.length === 0 ? (
            <div className="p-12 text-center text-gray-400">No incidents found.</div>
          ) : (
            incidents.map((incident) => (
              <IncidentRow key={incident.id} incident={incident} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
