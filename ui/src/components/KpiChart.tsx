import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import type { ChartDataPoint } from '../types';

interface KpiChartProps {
  title: string;
  data: ChartDataPoint[];
  color?: string;
  unit?: string;
}

export default function KpiChart({ title, data, color = '#06b6d4', unit = '' }: KpiChartProps) {
  return (
    <div className="glass-panel p-4">
      <h3 className="text-sm font-medium text-gray-400 mb-4">{title}</h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis
              dataKey="date"
              tick={{ fill: '#6b7280', fontSize: 10 }}
              tickFormatter={(value: string) => {
                const d = new Date(value);
                return `${d.getMonth() + 1}/${d.getDate()}`;
              }}
              stroke="#374151"
            />
            <YAxis
              tick={{ fill: '#6b7280', fontSize: 10 }}
              stroke="#374151"
              tickFormatter={(value: number) => `${value.toFixed(1)}${unit}`}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#111827',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#f3f4f6',
                fontSize: '12px',
              }}
              formatter={(value: number) => [`${value.toFixed(2)}${unit}`, title]}
              labelFormatter={(label: string) => new Date(label).toLocaleDateString()}
            />
            <Line
              type="monotone"
              dataKey="value"
              stroke={color}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, fill: color }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
