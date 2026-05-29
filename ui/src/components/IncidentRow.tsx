import { Link } from 'react-router-dom';
import { Cloud, Monitor, Network, Globe, Key, GitBranch, Database, Box, Cpu, Code } from 'lucide-react';
import { type Incident, getIncidentSeverity, getMitreTechniqueIds } from '../types';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';

const surfaceIcons: Record<string, React.ReactNode> = {
  CLOUD_IAM: <Key size={14} />,
  CLOUD_COMPUTE: <Cpu size={14} />,
  CLOUD_STORAGE: <Box size={14} />,
  CLOUD_NETWORK: <Network size={14} />,
  CLOUD_SERVERLESS: <Code size={14} />,
  CLOUD_DATABASE: <Database size={14} />,
  CLOUD_CONTAINER: <Box size={14} />,
  CLOUD_CICD: <GitBranch size={14} />,
  // Legacy
  CLOUD: <Cloud size={14} />,
  ENDPOINT: <Monitor size={14} />,
  NETWORK: <Network size={14} />,
  SAAS: <Globe size={14} />,
  IAM: <Key size={14} />,
  CICD: <GitBranch size={14} />,
};

function formatRelativeTime(timestamp?: string): string {
  if (!timestamp) return '—';
  const diff = Date.now() - new Date(timestamp).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

interface IncidentRowProps {
  incident: Incident;
}

export default function IncidentRow({ incident }: IncidentRowProps) {
  const severity = getIncidentSeverity(incident);
  const techniqueIds = getMitreTechniqueIds(incident);
  const surface = incident.attack_surface ?? 'CLOUD';
  const timestamp = incident.detection_timestamp ?? incident.created_at;

  // Get primary asset display
  const primaryAsset = incident.affected_assets
    ? (typeof incident.affected_assets[0] === 'string'
        ? incident.affected_assets[0]
        : (incident.affected_assets[0] as any)?.identifier)
    : null;

  // AI explanation or threat type for display
  const displayText = incident.explanation ?? incident.threat_type ?? incident.description ?? '—';

  return (
    <Link
      to={`/incidents/${incident.id}`}
      className="flex items-center gap-4 px-4 py-3 hover:bg-gray-800/50 border-b border-gray-800/50 transition-colors group"
    >
      {/* Severity */}
      <div className="w-20 flex-shrink-0">
        <SeverityBadge severity={severity} />
      </div>

      {/* ID */}
      <div className="w-36 flex-shrink-0">
        <span className="text-sm font-mono text-gray-300 group-hover:text-cyan-400 transition-colors">
          {incident.id.length > 16 ? `${incident.id.slice(0, 16)}…` : incident.id}
        </span>
      </div>

      {/* Attack Surface */}
      <div className="w-28 flex-shrink-0 flex items-center gap-1.5 text-gray-400">
        {surfaceIcons[surface] ?? <Cloud size={14} />}
        <span className="text-xs truncate">{surface.replace('CLOUD_', '')}</span>
      </div>

      {/* MITRE Techniques or AI description */}
      <div className="flex-1 min-w-0">
        {techniqueIds.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {techniqueIds.slice(0, 3).map((id) => (
              <span key={id} className="px-1.5 py-0.5 text-xs font-mono bg-gray-800 text-gray-300 rounded">
                {id}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-xs text-gray-400 truncate block">{displayText.slice(0, 80)}</span>
        )}
      </div>

      {/* Timestamp */}
      <div className="w-20 flex-shrink-0 text-right">
        <span className="text-xs text-gray-500">{formatRelativeTime(timestamp)}</span>
      </div>

      {/* Status */}
      <div className="w-28 flex-shrink-0 flex justify-end">
        <StatusBadge status={incident.status} />
      </div>

      {/* Affected Asset */}
      <div className="w-48 flex-shrink-0 text-right hidden xl:block">
        <span className="text-xs text-gray-500 truncate block">
          {primaryAsset
            ? (typeof primaryAsset === 'string' ? primaryAsset.split('/').pop() ?? primaryAsset : '—')
            : '—'}
        </span>
      </div>
    </Link>
  );
}
