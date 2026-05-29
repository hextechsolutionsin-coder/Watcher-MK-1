import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: 'up' | 'down' | 'stable';
  trendValue?: string;
  icon?: React.ReactNode;
  accentColor?: string;
}

export default function StatCard({ title, value, subtitle, trend, trendValue, icon, accentColor = 'cyan' }: StatCardProps) {
  const trendColors = {
    up: 'text-emerald-400',
    down: 'text-red-400',
    stable: 'text-gray-400',
  };

  const accentBorder = {
    cyan: 'border-l-cyan-400',
    red: 'border-l-red-400',
    amber: 'border-l-amber-400',
    emerald: 'border-l-emerald-400',
  }[accentColor] || 'border-l-cyan-400';

  return (
    <div className={`stat-card border-l-2 ${accentBorder}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">{title}</span>
        {icon && <span className="text-gray-500">{icon}</span>}
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-2xl font-bold text-gray-100">{value}</span>
        {subtitle && <span className="text-xs text-gray-500">{subtitle}</span>}
      </div>
      {trend && trendValue && (
        <div className={`flex items-center gap-1 text-xs ${trendColors[trend]}`}>
          {trend === 'up' && <TrendingUp size={12} />}
          {trend === 'down' && <TrendingDown size={12} />}
          {trend === 'stable' && <Minus size={12} />}
          <span>{trendValue}</span>
        </div>
      )}
    </div>
  );
}
