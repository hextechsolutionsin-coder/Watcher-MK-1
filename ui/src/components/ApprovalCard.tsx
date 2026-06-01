import { Link } from 'react-router-dom';
import { CheckCircle, XCircle, Clock, Brain, Shield, ChevronDown, ChevronUp, AlertTriangle, Undo2, RotateCcw } from 'lucide-react';
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

/** Maps action_type to a human-readable description of what will happen */
function describeAction(actionType: string, target: string): string {
  const map: Record<string, string> = {
    'aws:iam:disable-access-key': `Disable all active access keys for "${target}" — the user will lose programmatic access immediately`,
    'DISABLE_ACCESS_KEY': `Disable all active access keys for "${target}" — the user will lose programmatic access immediately`,
    'REVOKE_CREDENTIALS': `Disable all active access keys for "${target}" — the user will lose programmatic access immediately`,
    'aws:ec2:stop-instance': `Stop EC2 instance "${target}" — running workloads will be interrupted`,
    'STOP_INSTANCE': `Stop EC2 instance "${target}" — running workloads will be interrupted`,
    'ISOLATE_HOST': `Stop EC2 instance "${target}" — running workloads will be interrupted`,
    'aws:iam:attach-deny-policy': `Attach AWSDenyAll policy to "${target}" — the user will be completely locked out of all AWS actions`,
    'DISABLE_USER_ACCOUNT': `Attach AWSDenyAll policy to "${target}" — the user will be completely locked out of all AWS actions`,
    'aws:ec2:revoke-sg-ingress': `Remove inbound security group rules to block network access for "${target}"`,
    'BLOCK_IP': `Block IP address via security group rule modification`,
  };
  return map[actionType] ?? `Execute ${actionType.replace(/_/g, ' ').toLowerCase()} on "${target}"`;
}

// ── Enhanced approval card (shows AI reasoning + action details) ──────────────

interface EnhancedApprovalCardProps {
  action: RemediationAction & {
    ai_reasoning?: string;
    ai_params?: Record<string, unknown>;
    blast_radius?: string;
    rollback_description?: string;
  };
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

export function EnhancedApprovalCard({ action, onApprove, onReject }: EnhancedApprovalCardProps) {
  const [showDetails, setShowDetails] = useState(false);

  const blastRadius = action.blast_radius ?? 'NONE';
  const target = action.affected_asset?.identifier ?? 'unknown';

  return (
    <div className="glass-panel p-4 hover:border-gray-700 transition-colors border-l-2 border-l-cyan-500/50">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <Brain size={14} className="text-cyan-400 flex-shrink-0" />
            <SeverityBadge severity={action.severity_level} />
            <span className="text-sm font-semibold text-gray-200">
              {action.action_type.replace(/aws:/g, '').replace(/[_:]/g, ' ').toUpperCase()}
            </span>
            <span className={`px-1.5 py-0.5 text-xs rounded font-medium ${blastColors[blastRadius]}`}>
              {blastRadius} blast
            </span>
            {action.retry_count > 0 && (
              <span className="flex items-center gap-1 px-1.5 py-0.5 text-xs rounded bg-amber-500/10 text-amber-400">
                <RotateCcw size={10} />
                retry #{action.retry_count}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-gray-500">
            <Link to={`/incidents/${action.incident_id}`} className="text-cyan-400 hover:text-cyan-300 font-mono">
              {action.incident_id.slice(0, 16)}…
            </Link>
            <span className="flex items-center gap-1">
              <Clock size={11} />
              Pending {formatTimePending(action.created_at)}
            </span>
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

      {/* What will happen — always visible */}
      <div className="bg-gray-800/50 rounded-lg p-3 mb-3">
        <p className="text-xs text-gray-500 uppercase tracking-wider mb-1 font-medium">What will happen if approved</p>
        <p className="text-sm text-gray-200 leading-relaxed">
          {describeAction(action.action_type, target)}
        </p>
      </div>

      {/* AI Reasoning — always visible if present */}
      {action.ai_reasoning && (
        <div className="bg-cyan-500/5 border border-cyan-500/10 rounded-lg p-3 mb-3">
          <p className="text-xs text-cyan-400 uppercase tracking-wider mb-1 font-medium flex items-center gap-1">
            <Brain size={11} /> AI Reasoning
          </p>
          <p className="text-sm text-gray-300 leading-relaxed">{action.ai_reasoning}</p>
        </div>
      )}

      {/* Target + Rollback summary */}
      <div className="flex items-center justify-between text-xs text-gray-500">
        <div className="flex items-center gap-3">
          <span>Target: <span className="text-gray-300 font-mono">{target}</span></span>
          {action.rollback_description && (
            <span className="flex items-center gap-1 text-gray-500" title={action.rollback_description}>
              <Undo2 size={11} /> reversible
            </span>
          )}
        </div>

        <button
          onClick={() => setShowDetails(!showDetails)}
          className="flex items-center gap-1 text-gray-500 hover:text-gray-300 transition-colors"
        >
          {showDetails ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          {showDetails ? 'Hide' : 'Show'} details
        </button>
      </div>

      {/* Expanded details */}
      {showDetails && (
        <div className="mt-3 space-y-3 border-t border-gray-800 pt-3">
          {/* API Parameters */}
          {action.ai_params && Object.keys(action.ai_params).length > 0 && (
            <div className="p-3 bg-gray-900/50 rounded-lg">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-2 font-medium">API Parameters</p>
              <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap">
                {JSON.stringify(action.ai_params, null, 2)}
              </pre>
            </div>
          )}

          {/* Rollback plan */}
          {action.rollback_description && (
            <div className="p-3 bg-gray-900/50 rounded-lg">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-1 font-medium flex items-center gap-1">
                <Undo2 size={11} /> Rollback Plan
              </p>
              <p className="text-xs text-gray-400">{action.rollback_description}</p>
            </div>
          )}

          {/* Blast radius warning */}
          {(blastRadius === 'MEDIUM' || blastRadius === 'HIGH') && (
            <div className={`flex items-start gap-2 p-3 rounded-lg ${blastRadius === 'HIGH' ? 'bg-red-500/10 border border-red-500/20' : 'bg-amber-500/10 border border-amber-500/20'}`}>
              <AlertTriangle size={14} className={blastRadius === 'HIGH' ? 'text-red-400' : 'text-amber-400'} />
              <p className={`text-xs ${blastRadius === 'HIGH' ? 'text-red-400' : 'text-amber-400'}`}>
                {blastRadius === 'HIGH'
                  ? 'High blast radius — this action may affect multiple services or users. Review carefully.'
                  : 'Medium blast radius — this action will interrupt the target resource. Confirm the target is correct.'}
              </p>
            </div>
          )}
        </div>
      )}
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

// ── Default export — uses enhanced card that shows AI reasoning ───────────────

interface ApprovalCardProps {
  action: RemediationAction & {
    ai_reasoning?: string;
    ai_params?: Record<string, unknown>;
    blast_radius?: string;
    rollback_description?: string;
  };
  onApprove?: (id: string) => void;
  onReject?: (id: string) => void;
}

export default function ApprovalCard({ action, onApprove, onReject }: ApprovalCardProps) {
  return <EnhancedApprovalCard action={action} onApprove={onApprove} onReject={onReject} />;
}
