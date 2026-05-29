import { SeverityLevel } from '../types';

const severityConfig: Record<SeverityLevel, { bg: string; text: string; label: string }> = {
  [SeverityLevel.CRITICAL]: { bg: 'bg-red-500/20', text: 'text-red-400', label: 'CRITICAL' },
  [SeverityLevel.HIGH]: { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'HIGH' },
  [SeverityLevel.MEDIUM]: { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'MEDIUM' },
  [SeverityLevel.LOW]: { bg: 'bg-blue-500/20', text: 'text-blue-400', label: 'LOW' },
  [SeverityLevel.INFORMATIONAL]: { bg: 'bg-gray-500/20', text: 'text-gray-400', label: 'INFO' },
};

interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md';
}

export default function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span className={`inline-flex items-center font-semibold rounded-full ${config.bg} ${config.text} ${sizeClasses}`}>
      {config.label}
    </span>
  );
}
