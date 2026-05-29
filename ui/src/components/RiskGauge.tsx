interface RiskGaugeProps {
  score: number;
  size?: 'sm' | 'lg';
  label?: string;
}

export default function RiskGauge({ score, size = 'sm', label = 'Risk Score' }: RiskGaugeProps) {
  const dimensions = size === 'lg' ? { width: 200, height: 200, radius: 80, stroke: 12 } : { width: 120, height: 120, radius: 48, stroke: 8 };
  const { width, height, radius, stroke } = dimensions;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference * 0.75; // 270 degrees
  const rotation = 135; // Start from bottom-left

  const getColor = (value: number) => {
    if (value >= 80) return '#ef4444'; // red
    if (value >= 60) return '#f97316'; // orange
    if (value >= 40) return '#eab308'; // yellow
    return '#22c55e'; // green
  };

  const color = getColor(score);

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width, height }}>
        <svg width={width} height={height} className="transform" style={{ transform: `rotate(${rotation}deg)` }}>
          {/* Background arc */}
          <circle
            cx={width / 2}
            cy={height / 2}
            r={radius}
            fill="none"
            stroke="#1f2937"
            strokeWidth={stroke}
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <circle
            cx={width / 2}
            cy={height / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={`${progress} ${circumference - progress}`}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
            style={{ filter: `drop-shadow(0 0 6px ${color}40)` }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-bold ${size === 'lg' ? 'text-4xl' : 'text-2xl'}`} style={{ color }}>
            {score}
          </span>
          {size === 'lg' && <span className="text-xs text-gray-500 mt-1">/ 100</span>}
        </div>
      </div>
      <span className={`text-gray-400 ${size === 'lg' ? 'text-sm' : 'text-xs'}`}>{label}</span>
    </div>
  );
}
