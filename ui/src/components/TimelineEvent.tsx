import { AlertTriangle, Link2, Search, ShieldCheck, Zap, ArrowUpCircle } from 'lucide-react';
import type { TimelineEvent as TimelineEventType } from '../types';

const typeConfig: Record<TimelineEventType['type'], { icon: React.ReactNode; color: string }> = {
  detection: { icon: <AlertTriangle size={16} />, color: 'text-red-400 bg-red-400/10 border-red-400/30' },
  correlation: { icon: <Link2 size={16} />, color: 'text-amber-400 bg-amber-400/10 border-amber-400/30' },
  enrichment: { icon: <Search size={16} />, color: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30' },
  approval: { icon: <ShieldCheck size={16} />, color: 'text-purple-400 bg-purple-400/10 border-purple-400/30' },
  remediation: { icon: <Zap size={16} />, color: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30' },
  escalation: { icon: <ArrowUpCircle size={16} />, color: 'text-orange-400 bg-orange-400/10 border-orange-400/30' },
};

function formatTime(timestamp: string): string {
  return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

interface TimelineEventProps {
  event: TimelineEventType;
  isLast?: boolean;
}

export default function TimelineEventComponent({ event, isLast = false }: TimelineEventProps) {
  const config = typeConfig[event.type];

  return (
    <div className="flex gap-4">
      {/* Timeline connector */}
      <div className="flex flex-col items-center">
        <div className={`w-8 h-8 rounded-full border flex items-center justify-center ${config.color}`}>
          {config.icon}
        </div>
        {!isLast && <div className="w-px flex-1 bg-gray-800 my-1" />}
      </div>

      {/* Content */}
      <div className="flex-1 pb-6">
        <div className="flex items-center gap-3 mb-1">
          <span className="text-sm font-medium text-gray-200">{event.title}</span>
          <span className="text-xs text-gray-500">{formatTime(event.timestamp)}</span>
        </div>
        <p className="text-sm text-gray-400">{event.description}</p>
        {event.actor && (
          <span className="text-xs text-gray-600 mt-1 inline-block">by {event.actor}</span>
        )}
      </div>
    </div>
  );
}
