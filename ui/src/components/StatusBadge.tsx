import { IncidentStatus } from '../types';

const statusConfig: Record<IncidentStatus, { bg: string; text: string; dot: string }> = {
  [IncidentStatus.OPEN]: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-400' },
  [IncidentStatus.IN_PROGRESS]: { bg: 'bg-amber-500/10', text: 'text-amber-400', dot: 'bg-amber-400' },
  [IncidentStatus.RESOLVED]: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', dot: 'bg-emerald-400' },
  [IncidentStatus.SUPPRESSED]: { bg: 'bg-gray-500/10', text: 'text-gray-400', dot: 'bg-gray-400' },
  [IncidentStatus.FALSE_POSITIVE]: { bg: 'bg-blue-500/10', text: 'text-blue-400', dot: 'bg-blue-400' },
};

interface StatusBadgeProps {
  status: IncidentStatus;
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status];

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bg} ${config.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {status.replace('_', ' ')}
    </span>
  );
}
