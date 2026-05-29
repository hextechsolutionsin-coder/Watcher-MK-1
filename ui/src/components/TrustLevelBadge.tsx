import { Shield, ShieldCheck, ShieldAlert } from 'lucide-react';
import type { TrustLevelInfo } from '../types';

interface TrustLevelBadgeProps {
  trust?: TrustLevelInfo | null;
  compact?: boolean;
}

const levelConfig = {
  1: {
    icon: <ShieldAlert size={14} />,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10 border-amber-500/30',
    label: 'Supervised',
    description: 'All writes need approval',
  },
  2: {
    icon: <Shield size={14} />,
    color: 'text-cyan-400',
    bg: 'bg-cyan-500/10 border-cyan-500/30',
    label: 'Semi-Auto',
    description: 'Low-risk actions autonomous',
  },
  3: {
    icon: <ShieldCheck size={14} />,
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10 border-emerald-500/30',
    label: 'Autonomous',
    description: 'Medium-risk actions autonomous',
  },
};

export default function TrustLevelBadge({ trust, compact = false }: TrustLevelBadgeProps) {
  if (!trust) {
    return (
      <div className="flex items-center gap-1.5 text-xs text-gray-500">
        <Shield size={12} />
        <span>Trust: —</span>
      </div>
    );
  }

  const level = trust.trust_level as 1 | 2 | 3;
  const cfg = levelConfig[level];

  if (compact) {
    return (
      <div className={`flex items-center gap-1.5 px-2 py-1 rounded border text-xs ${cfg.bg} ${cfg.color}`}>
        {cfg.icon}
        <span>Level {level}</span>
      </div>
    );
  }

  return (
    <div className={`p-3 rounded-lg border ${cfg.bg}`}>
      <div className={`flex items-center gap-2 ${cfg.color} mb-2`}>
        {cfg.icon}
        <span className="text-xs font-semibold">Trust Level {level} — {cfg.label}</span>
      </div>

      {/* Approval rate bar */}
      <div className="mb-2">
        <div className="flex justify-between text-xs text-gray-500 mb-1">
          <span>Approval rate (30d)</span>
          <span className="text-gray-300">{trust.approval_rate_30d.toFixed(1)}%</span>
        </div>
        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${trust.approval_rate_30d >= 90 ? 'bg-emerald-400' : trust.approval_rate_30d >= 80 ? 'bg-amber-400' : 'bg-red-400'}`}
            style={{ width: `${trust.approval_rate_30d}%` }}
          />
        </div>
      </div>

      {/* Path to next level */}
      {trust.path_to_level_2 && level === 1 && (
        <div className="text-xs text-gray-500">
          <span className="text-gray-400">{trust.path_to_level_2.days_remaining}d</span> until Level 2 eligible
        </div>
      )}

      <div className="text-xs text-gray-500 mt-1">
        {trust.total_actions_30d} actions · {trust.approved_actions_30d} approved
      </div>
    </div>
  );
}
