import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, ExternalLink, Brain, Loader2, Target, TrendingUp, ThumbsUp, ThumbsDown, AlertTriangle as TriangleIcon } from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import TimelineEventComponent from '../components/TimelineEvent';
import { fetchIncidentById, fetchIncidentTimeline, submitFeedback } from '../api/client';
import {
  getIncidentSeverity, getIncidentConfidence, getIncidentDescription,
  getMitreTechniqueIds, SeverityLevel, type Incident, type TimelineEvent,
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

          {/* Evidence — correlated events with full details */}
          {incident.evidence && incident.evidence.length > 0 && (
            <div className="glass-panel p-5">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-gray-200">
                  Correlated Events ({incident.evidence.length})
                </h2>
                <Link
                  to={`/events?incident_id=${incident.id}`}
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <ExternalLink size={12} />
                  View in Polled Events
                </Link>
              </div>
              <div className="space-y-2">
                {(incident.evidence as any[]).map((ev: any, idx: number) => {
                  const eventName = ev.description?.split(' at ')?.[0] ?? ev.description ?? 'Unknown event';
                  const eventTime = ev.timestamp ?? ev.description?.split(' at ')?.[1];
                  const eventId = ev.raw_event_id;

                  return (
                    <div key={idx} className="p-3 bg-gray-800/50 rounded-lg">
                      <div className="flex items-center justify-between gap-3 mb-1">
                        <span className="text-sm font-mono text-gray-200">{eventName}</span>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {eventTime && (
                            <span className="text-xs text-gray-500">
                              {new Date(eventTime).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                            </span>
                          )}
                          {eventId && eventId !== `evt-${Date.now()}` && !eventId.startsWith('evt-') && (
                            <Link
                              to={`/events?event_id=${eventId}&incident_id=${incident.id}`}
                              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                              title="View full event details"
                            >
                              <ExternalLink size={11} />
                              Details
                            </Link>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span>Surface: <span className="text-gray-400">{ev.attack_surface}</span></span>
                        {ev.raw_event_id && (
                          <span className="font-mono">ID: {String(ev.raw_event_id).slice(0, 8)}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
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

          {/* Analyst Feedback */}
          <FeedbackPanel incidentId={incident.id} currentStatus={incident.status} onFeedbackSubmitted={() => {
            // Reload incident data
            if (id) {
              Promise.all([fetchIncidentById(id), fetchIncidentTimeline(id)])
                .then(([inc, tl]) => {
                  setIncident(inc as Incident);
                  setTimeline(tl as TimelineEvent[]);
                })
                .catch(() => {});
            }
          }} />
        </div>
      </div>
    </div>
  );
}

// ── Feedback Panel Component ──────────────────────────────────────────────────

interface FeedbackPanelProps {
  incidentId: string;
  currentStatus: string;
  onFeedbackSubmitted: () => void;
}

function FeedbackPanel({ incidentId, currentStatus, onFeedbackSubmitted }: FeedbackPanelProps) {
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [showSeverityPicker, setShowSeverityPicker] = useState(false);
  const [notes, setNotes] = useState('');

  if (currentStatus === 'FALSE_POSITIVE') {
    return (
      <div className="glass-panel p-4">
        <p className="text-xs text-gray-500">This incident was marked as a false positive.</p>
      </div>
    );
  }

  if (submitted) {
    return (
      <div className="glass-panel p-4 border-l-2 border-l-emerald-500/50">
        <p className="text-sm text-emerald-400">Feedback submitted. The AI will learn from this.</p>
      </div>
    );
  }

  const handleFeedback = async (verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'SEVERITY_WRONG', correctSeverity?: string) => {
    setSubmitting(true);
    try {
      await submitFeedback(incidentId, {
        verdict,
        correct_severity: correctSeverity,
        notes: notes || undefined,
        analyst_id: 'analyst-001',
      });
      setSubmitted(true);
      onFeedbackSubmitted();
    } catch (err) {
      console.error('Failed to submit feedback:', err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="glass-panel p-4">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Analyst Feedback</h3>
      <p className="text-xs text-gray-500 mb-3">Help the AI learn — was this detection correct?</p>

      <div className="space-y-2 mb-3">
        <input
          type="text"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Optional notes (e.g. 'This is our CI/CD pipeline')"
          className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none"
        />
      </div>

      <div className="flex flex-col gap-2">
        <button
          onClick={() => handleFeedback('TRUE_POSITIVE')}
          disabled={submitting}
          className="flex items-center gap-2 px-3 py-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg text-xs hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
        >
          <ThumbsUp size={12} />
          Correct Detection
        </button>
        <button
          onClick={() => handleFeedback('FALSE_POSITIVE')}
          disabled={submitting}
          className="flex items-center gap-2 px-3 py-2 bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg text-xs hover:bg-red-500/20 transition-colors disabled:opacity-50"
        >
          <ThumbsDown size={12} />
          False Positive
        </button>
        <button
          onClick={() => setShowSeverityPicker(!showSeverityPicker)}
          disabled={submitting}
          className="flex items-center gap-2 px-3 py-2 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-lg text-xs hover:bg-amber-500/20 transition-colors disabled:opacity-50"
        >
          <TriangleIcon size={12} />
          Wrong Severity
        </button>

        {showSeverityPicker && (
          <div className="flex flex-wrap gap-1 p-2 bg-gray-800/50 rounded-lg">
            {Object.values(SeverityLevel).map((level) => (
              <button
                key={level}
                onClick={() => handleFeedback('SEVERITY_WRONG', level)}
                className="px-2 py-1 text-xs rounded bg-gray-700 text-gray-300 hover:bg-gray-600 transition-colors"
              >
                {level}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
