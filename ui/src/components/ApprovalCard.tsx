import { Link } from 'react-router-dom';
import { CheckCircle, XCircle, Clock, Brain, Shield, ChevronDown, ChevronUp } from 'lucide-react';
import { useState } from 'react';
import { type RemediationAction, type ApprovalRequest } from '../types';
import SeverityBadge from './SeverityBadge';

function formatTimePending(createdAt: string): string {
  const diff = Date.now() - new Date(createdAt).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

const blastColors: Record<string, string> = {
  NONE: 'text-gray-400 bg-gray-800',
  LOW: 'text-emerald-400 bg-emerald-500/10',
  MEDIUM: 'text-amber-400 bg-amber-500/10',
  HIGH: 'text-red-400 bg-red-500/10',
};

// ── Legacy approval card (for seed data) ─────────────────────────────────────

interface LegacyApprovalCardProps {
  action: RemediationAction;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

export function LegacyApprovalCard({ action, onApprove, onReject }: LegacyApprovalCardProps) {
  return (
    <div className="glass-panel p-4 hover:border-gray-700 transition-colors">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <SeverityBadge severity={action.severity_level} />
            <span className="text-sm font-semibold text-gray-200">
              {action.action_type.replace(/_/g, ' ')}
            </span>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span>Incident:</span>
              <Link to={`/incidents/${action.incident_id}`} className="text-cyan-400 hover:text-cyan-300 font-mono">
                {action.incident_id}
              </Link>
            </div>
            <div className="text-xs text-gray-400">
              Target: <span className="text-gray-300">{action.affected_asset.identifier}</span>
            </div>
            <div className="flex items-center gap-1 text-xs text-gray-500">
              <Clock size={12} />
              <span>Pending for {formatTimePending(action.created_at)}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => onApprove?.(action.id)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-medium hover:bg-emerald-500/20 transition-colors"
          >
            <CheckCircle size={14} />
            Approve
          </button>
          <button
            onClick={() => onReject?.(action.id)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium hover:bg-red-500/20 transition-colors"
          >
            <XCircle size={14} />
            Reject
          </button>
        </div>
      </div>
    </div>
  );
}

// ── AI-generated approval card ────────────────────────────────────────────────

interface AiApprovalCardProps {
  request: ApprovalRequest;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

export function AiApprovalCard({ request, onApprove, onReject }: AiApprovalCardProps) {
  const [showReasoning, setShowReasoning] = useState(false);

  const maxBlastRadius = request.actions.reduce((max, a) => {
    const order = ['NONE', 'LOW', 'MEDIUM', 'HIGH'];
    return order.indexOf(a.blast_radius) > order.indexOf(max) ? a.blast_radius : max;
  }, 'NONE');

  return (
    <div className="glass-panel p-4 hover:border-gray-700 transition-colors border-l-2 border-l-cyan-500/50">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex items-center gap-3">
          <Brain size={16} className="text-cyan-400 flex-shrink-0" />
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity={request.threat_assessment.severity} />
              <span className="text-sm font-semibold text-gray-200">
                {request.threat_assessment.threat_type}
              </span>
              <span className={`px-1.5 py-0.5 text-xs rounded font-medium ${blastColors[maxBlastRadius]}`}>
                {maxBlastRadius} blast
              </span>
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
              <Link to={`/incidents/${request.incident_id}`} className="text-cyan-400 hover:text-cyan-300 font-mono">
                {request.incident_id.slice(0, 16)}…
              </Link>
              <span className="flex items-center gap-1">
                <Clock size={11} />
                Pending {formatTimePending(request.created_at)}
              </span>
              <span className="text-amber-400">
                Expires {new Date(request.expires_at).toLocaleTimeString()}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => onApprove?.(request.id)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-medium hover:bg-emerald-500/20 transition-colors"
          >
            <CheckCircle size={14} />
            Approve
          </button>
          <button
            onClick={() => onReject?.(request.id)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium hover:bg-red-500/20 transition-colors"
          >
            <XCircle size={14} />
            Reject
          </button>
        </div>
      </div>

      {/* AI Explanation */}
      <div className="bg-gray-800/50 rounded-lg p-3 mb-3">
        <p className="text-sm text-gray-300 leading-relaxed">{request.ai_explanation}</p>
      </div>

      {/* Planned Actions */}
      <div className="space-y-2 mb-3">
        {request.actions.map((action, idx) => (
          <div key={action.id} className="flex items-center gap-3 p-2 bg-gray-800/30 rounded-lg">
            <span className="w-5 h-5 rounded-full bg-gray-700 text-gray-400 text-xs flex items-center justify-center flex-shrink-0">
              {idx + 1}
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-gray-200">{action.description}</p>
              <p className="text-xs text-gray-500 mt-0.5">{action.reasoning}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className={`px-1.5 py-0.5 text-xs rounded ${blastColors[action.blast_radius]}`}>
                {action.blast_radius}
              </span>
              {action.rollback_spec && (
                <span className="text-xs text-gray-500" title={action.rollback_spec.description}>
                  ↩ reversible
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Confidence + MITRE */}
      <div className="flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <Shield size={11} />
            AI confidence: <span className="text-gray-300 ml-1">{request.threat_assessment.confidence}%</span>
          </span>
          <div className="flex gap-1">
            {request.threat_assessment.mitre_techniques.slice(0, 2).map((t) => (
              <span key={t.technique_id} className="px-1.5 py-0.5 font-mono bg-red-500/10 text-red-400 rounded">
                {t.technique_id}
              </span>
            ))}
          </div>
        </div>

        <button
          onClick={() => setShowReasoning(!showReasoning)}
          className="flex items-center gap-1 text-gray-500 hover:text-gray-300 transition-colors"
        >
          {showReasoning ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {showReasoning ? 'Hide' : 'Show'} reasoning
        </button>
      </div>

      {/* Reasoning Trace (expandable) */}
      {showReasoning && (
        <div className="mt-3 p-3 bg-gray-900/50 rounded-lg border border-gray-700/50">
          <p className="text-xs text-gray-500 font-mono leading-relaxed whitespace-pre-wrap">
            {request.ai_reasoning_trace}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Default export — handles both legacy and AI approval cards ────────────────

interface ApprovalCardProps {
  action: RemediationAction;
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

export default function ApprovalCard({ action, onApprove, onReject }: ApprovalCardProps) {
  return <LegacyApprovalCard action={action} onApprove={onApprove} onReject={onReject} />;
}
