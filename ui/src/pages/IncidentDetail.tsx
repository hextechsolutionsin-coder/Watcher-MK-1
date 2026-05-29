import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ExternalLink, Brain, Loader2, Target, TrendingUp } from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import TimelineEventComponent from '../components/TimelineEvent';
import { fetchIncidentById, fetchIncidentTimeline } from '../api/client';
import {
  getIncidentSeverity, getIncidentConfidence, getIncidentDescription,
  getMitreTechniqueIds, type Incident, type TimelineEvent,
} from '../types';

function formatDateTime(timestamp?: string): string {
  if (!timestamp) return '—';
  return new Date(timestamp).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    Promise.all([fetchIncidentById(id), fetchIncidentTimeline(id)])
      .then(([inc, tl]) => {
        setIncident(inc as Incident);
        setTimeline(tl as TimelineEvent[]);
        setError(null);
      })
      .catch(() => setError('Failed to load incident details.'))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-96">
        <div className="flex items-center gap-3 text-gray-400">
          <Loader2 size={20} className="animate-spin" />
          <span>Loading incident details...</span>
        </div>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="p-6">
        <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-cyan-400 mb-4">
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <div className="glass-panel p-8 text-center">
          <p className="text-red-400">{error || 'Incident not found'}</p>
        </div>
      </div>
    );
  }

  const severity = getIncidentSeverity(incident);
  const confidence = getIncidentConfidence(incident);
  const description = getIncidentDescription(incident);
  const techniqueIds = getMitreTechniqueIds(incident);
  const timestamp = incident.detection_timestamp ?? incident.created_at;

  // Affected assets — handle both string[] (new) and Asset[] (legacy)
  const assets = incident.affected_assets ?? [];

  return (
    <div className="p-6 space-y-6">
      {/* Back + Header */}
      <div>
        <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-cyan-400 transition-colors mb-4">
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-4">
            <SeverityBadge severity={severity} size="md" />
            <div>
              <h1 className="text-lg font-bold text-gray-100 font-mono">{incident.id}</h1>
              <p className="text-sm text-gray-500 mt-0.5">Detected {formatDateTime(timestamp)}</p>
            </div>
          </div>
          <StatusBadge status={incident.status} />
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: Timeline + AI Reasoning */}
        <div className="xl:col-span-2 space-y-6">

          {/* AI Explanation Panel */}
          {(incident.explanation || incident.threat_type) && (
            <div className="glass-panel p-5 border-l-2 border-l-cyan-500/50">
              <div className="flex items-center gap-2 mb-3">
                <Brain size={16} className="text-cyan-400" />
                <h2 className="text-sm font-semibold text-gray-200">AI Analysis</h2>
                <span className="ml-auto text-xs text-gray-500">
                  Confidence: <span className={confidence >= 80 ? 'text-red-400' : confidence >= 60 ? 'text-amber-400' : 'text-gray-400'}>
                    {confidence}%
                  </span>
                </span>
              </div>

              {incident.threat_type && (
                <p className="text-xs text-cyan-400 font-medium mb-2">{incident.threat_type}</p>
              )}

              <p className="text-sm text-gray-300 leading-relaxed mb-3">
                {incident.explanation ?? incident.description ?? description}
              </p>

              {/* Kill chain stage */}
              {incident.kill_chain_stage && (
                <div className="flex items-center gap-2 text-xs text-gray-500 mb-3">
                  <Target size={12} />
                  <span>Kill chain stage: <span className="text-amber-400">{incident.kill_chain_stage}</span></span>
                </div>
              )}

              {/* Predictions */}
              {incident.predictions && (
                <div className="p-3 bg-gray-800/50 rounded-lg mb-3">
                  <div className="flex items-center gap-2 text-xs text-gray-400 mb-2">
                    <TrendingUp size={12} className="text-amber-400" />
                    <span className="text-amber-400">Predicted next action ({incident.predictions.probability}% probability)</span>
                  </div>
                  <p className="text-sm text-gray-300">{incident.predictions.next_likely_action}</p>
                  <p className="text-xs text-gray-500 mt-1">
                    Recommended: {incident.predictions.recommended_preemption}
                  </p>
                </div>
              )}

              {/* MITRE techniques (new format) */}
              {incident.mitre_techniques && incident.mitre_techniques.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {incident.mitre_techniques.map((t) => (
                    <a
                      key={t.technique_id}
                      href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="group flex items-center gap-1.5 px-2 py-1 bg-red-500/10 border border-red-500/20 rounded hover:bg-red-500/20 transition-colors"
                    >
                      <span className="text-xs font-mono text-red-400">{t.technique_id}</span>
                      <span className="text-xs text-gray-500 group-hover:text-gray-300">{t.technique_name}</span>
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Timeline */}
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-4">Incident Timeline</h2>
            {timeline.length === 0 ? (
              <p className="text-gray-500 text-sm">No timeline events recorded yet.</p>
            ) : (
              <div className="space-y-0">
                {timeline.map((event, idx) => (
                  <TimelineEventComponent key={event.id} event={event} isLast={idx === timeline.length - 1} />
                ))}
              </div>
            )}
          </div>

          {/* Evidence (legacy) */}
          {incident.evidence && incident.evidence.length > 0 && (
            <div className="glass-panel p-5">
              <h2 className="text-sm font-semibold text-gray-200 mb-4">Contributing Evidence</h2>
              <div className="space-y-3">
                {incident.evidence.map((ev, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-3 bg-gray-800/50 rounded-lg">
                    <div className="w-8 h-8 rounded-full bg-cyan-400/10 border border-cyan-400/30 flex items-center justify-center flex-shrink-0">
                      <ExternalLink size={14} className="text-cyan-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-gray-200">{ev.description}</p>
                      <div className="flex items-center gap-3 mt-1.5 text-xs text-gray-500">
                        <span>Surface: <span className="text-gray-400">{ev.attack_surface}</span></span>
                        <span>Connector: <span className="text-gray-400">{ev.connector_id}</span></span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: Assets + MITRE + Actions */}
        <div className="space-y-6">
          {/* Affected Assets */}
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-gray-200 mb-3">Affected Assets</h2>
            <div className="space-y-2">
              {/* New format: string ARNs */}
              {Array.isArray(assets) && assets.length > 0 && typeof assets[0] === 'string' && (
                (assets as string[]).map((arn, idx) => (
                  <div key={idx} className="p-2.5 bg-gray-800/50 rounded-lg">
                    <p className="text-xs text-gray-300 font-mono break-all">{arn}</p>
                  </div>
                ))
              )}
              {/* Legacy format: Asset objects */}
              {Array.isArray(assets) && assets.length > 0 && typeof assets[0] === 'object' && (
                (assets as any[]).map((asset: any) => (
                  <div key={asset.id ?? asset.identifier} className="flex items-center justify-between p-2.5 bg-gray-800/50 rounded-lg">
                    <div>
                      <p className="text-sm text-gray-200">{asset.identifier}</p>
                      <p className="text-xs text-gray-500">{asset.class}</p>
                    </div>
                    {asset.criticality && (
                      <span className={`text-sm font-bold ${asset.criticality >= 8 ? 'text-red-400' : asset.criticality >= 5 ? 'text-amber-400' : 'text-gray-400'}`}>
                        {asset.criticality}/10
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* MITRE ATT&CK (legacy format) */}
          {techniqueIds.length > 0 && !incident.mitre_techniques?.length && (
            <div className="glass-panel p-5">
              <h2 className="text-sm font-semibold text-gray-200 mb-3">MITRE ATT&CK</h2>
              <div className="flex flex-wrap gap-2">
                {techniqueIds.map((id) => (
                  <a
                    key={id}
                    href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2.5 py-1 text-xs font-mono bg-red-500/10 text-red-400 border border-red-500/20 rounded hover:bg-red-500/20 transition-colors"
                  >
                    {id}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions (legacy) */}
          {incident.recommended_actions && incident.recommended_actions.length > 0 && (
            <div className="glass-panel p-5">
              <div className="flex items-center gap-2 mb-3">
                <Brain size={16} className="text-cyan-400" />
                <h2 className="text-sm font-semibold text-gray-200">Recommended Actions</h2>
              </div>
              <div className="space-y-2">
                {incident.recommended_actions.map((action, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2.5 bg-gray-800/50 rounded-lg">
                    <span className="text-sm text-gray-300">{action.replace(/_/g, ' ')}</span>
                    <span className="text-xs text-cyan-400">{Math.round(90 - idx * 8)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
