import { useState, useEffect } from 'react';
import { TrendingDown, TrendingUp, Minus, Loader2 } from 'lucide-react';
import RiskGauge from '../components/RiskGauge';
import SeverityBadge from '../components/SeverityBadge';
import KpiChart from '../components/KpiChart';
import { fetchKpis, fetchTrends, fetchRiskScore } from '../api/client';
import type { KpiMetric, ChartDataPoint } from '../types';

function KpiCard({ metric }: { metric: KpiMetric }) {
  const trendColors = {
    up: metric.label.includes('Resolution') ? 'text-emerald-400' : 'text-red-400',
    down: metric.label.includes('Resolution') ? 'text-red-400' : 'text-emerald-400',
    stable: 'text-gray-400',
  };

  return (
    <div className="glass-panel p-5">
      <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">{metric.label}</p>
      <div className="flex items-baseline gap-2">
        <span className="text-3xl font-bold text-gray-100">{metric.value}</span>
        <span className="text-sm text-gray-500">{metric.unit}</span>
      </div>
      <div className={`flex items-center gap-1 mt-2 text-xs ${trendColors[metric.trend]}`}>
        {metric.trend === 'up' && <TrendingUp size={12} />}
        {metric.trend === 'down' && <TrendingDown size={12} />}
        {metric.trend === 'stable' && <Minus size={12} />}
        <span>{metric.trendValue > 0 ? '+' : ''}{metric.trendValue}% vs last period</span>
      </div>
    </div>
  );
}

interface TrendData {
  mttd: ChartDataPoint[];
  mttr: ChartDataPoint[];
  falsePositiveRate: ChartDataPoint[];
  autonomousResolution: ChartDataPoint[];
  topThreats: { techniqueId: string; techniqueName: string; count: number; severity: string }[];
}

export default function ExecutiveView() {
  const [timeWindow, setTimeWindow] = useState<'7d' | '30d' | '90d'>('30d');
  const [riskScore, setRiskScore] = useState<number>(0);
  const [kpis, setKpis] = useState<any>(null);
  const [trendData, setTrendData] = useState<TrendData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [riskData, kpisData, trendsData] = await Promise.all([
          fetchRiskScore(),
          fetchKpis(),
          fetchTrends(),
        ]);
        setRiskScore(riskData.score);
        setKpis(kpisData);
        setTrendData(trendsData as TrendData);
        setError(null);
      } catch (err) {
        setError('Unable to load executive metrics. Make sure the API server is running.');
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
          <span>Loading executive metrics...</span>
        </div>
      </div>
    );
  }

  if (error || !kpis || !trendData) {
    return (
      <div className="p-6">
        <div className="glass-panel p-8 text-center">
          <p className="text-red-400 mb-2">⚠ Connection Error</p>
          <p className="text-gray-400 text-sm">{error || 'Failed to load metrics'}</p>
        </div>
      </div>
    );
  }

  // Build KPI metrics from API data
  const metrics = {
    riskScore,
    mttd: { label: 'Mean Time to Detect', value: +(kpis.mttd_seconds / 60).toFixed(1), unit: 'min', trend: 'stable' as const, trendValue: 0 },
    mttr: { label: 'Mean Time to Respond', value: +(kpis.mttr_seconds / 60).toFixed(1), unit: 'min', trend: 'stable' as const, trendValue: 0 },
    falsePositiveRate: { label: 'False Positive Rate', value: kpis.false_positive_rate, unit: '%', trend: 'stable' as const, trendValue: 0 },
    autonomousResolutionRate: { label: 'Autonomous Resolution', value: kpis.autonomous_resolution_pct, unit: '%', trend: 'stable' as const, trendValue: 0 },
  };

  // Slice trend data based on time window
  const windowDays = { '7d': 7, '30d': 30, '90d': 90 }[timeWindow];
  const slicedTrend = {
    mttd: trendData.mttd.slice(-windowDays),
    mttr: trendData.mttr.slice(-windowDays),
    falsePositiveRate: trendData.falsePositiveRate.slice(-windowDays),
    autonomousResolution: trendData.autonomousResolution.slice(-windowDays),
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Executive Risk View</h1>
          <p className="text-sm text-gray-500 mt-0.5">Business risk posture and operational KPIs</p>
        </div>
        <div className="flex gap-1 bg-gray-800 rounded-lg p-0.5">
          {(['7d', '30d', '90d'] as const).map((window) => (
            <button
              key={window}
              onClick={() => setTimeWindow(window)}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
                timeWindow === window
                  ? 'bg-cyan-500/20 text-cyan-400'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {window}
            </button>
          ))}
        </div>
      </div>

      {/* Risk Score + KPIs */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="glass-panel p-6 flex items-center justify-center">
          <RiskGauge score={metrics.riskScore} size="lg" label="Business Risk Score" />
        </div>
        <div className="lg:col-span-4 grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard metric={metrics.mttd} />
          <KpiCard metric={metrics.mttr} />
          <KpiCard metric={metrics.falsePositiveRate} />
          <KpiCard metric={metrics.autonomousResolutionRate} />
        </div>
      </div>

      {/* Trend Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <KpiChart title="Mean Time to Detect (minutes)" data={slicedTrend.mttd} color="#06b6d4" unit=" min" />
        <KpiChart title="Mean Time to Respond (minutes)" data={slicedTrend.mttr} color="#8b5cf6" unit=" min" />
        <KpiChart title="False Positive Rate (%)" data={slicedTrend.falsePositiveRate} color="#f97316" unit="%" />
        <KpiChart title="Autonomous Resolution Rate (%)" data={slicedTrend.autonomousResolution} color="#22c55e" unit="%" />
      </div>

      {/* Top Threats Table */}
      <div className="glass-panel">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-200">Top Observed MITRE ATT&CK Techniques</h2>
          <p className="text-xs text-gray-500 mt-0.5">Most frequently detected techniques in the selected time window</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800/50 bg-gray-900/30">
                <th className="text-left px-5 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Technique ID</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Occurrences</th>
                <th className="text-left px-5 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Frequency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {trendData.topThreats.map((threat) => {
                const maxCount = trendData.topThreats[0]?.count || 1;
                const barWidth = (threat.count / maxCount) * 100;
                return (
                  <tr key={threat.techniqueId} className="hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3">
                      <span className="text-sm font-mono text-cyan-400">{threat.techniqueId}</span>
                    </td>
                    <td className="px-5 py-3">
                      <span className="text-sm text-gray-200">{threat.techniqueName}</span>
                    </td>
                    <td className="px-5 py-3">
                      <SeverityBadge severity={threat.severity as any} />
                    </td>
                    <td className="px-5 py-3">
                      <span className="text-sm font-medium text-gray-300">{threat.count}</span>
                    </td>
                    <td className="px-5 py-3 w-48">
                      <div className="w-full bg-gray-800 rounded-full h-2">
                        <div
                          className="h-2 rounded-full bg-gradient-to-r from-cyan-500 to-cyan-400"
                          style={{ width: `${barWidth}%` }}
                        />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
