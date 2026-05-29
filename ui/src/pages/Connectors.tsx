import { useState, useEffect } from 'react';
import {
  Plus, RefreshCw, CheckCircle, XCircle, AlertTriangle,
  Cloud, Shield, Eye, Zap, Loader2, ChevronDown, ChevronUp,
  ExternalLink, Pause, Wifi,
} from 'lucide-react';
import { fetchConnectors, registerConnector, pauseConnector } from '../api/client';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Connector {
  id: string;
  tenant_id: string;
  account_id: string;
  regions: string[];
  data_sources: string[];
  status: 'ACTIVE' | 'ERROR' | 'PAUSED';
  registered_at: string;
  last_poll_at: string | null;
  error_message?: string;
}

// ── Capability descriptions ───────────────────────────────────────────────────

const DATA_SOURCE_INFO: Record<string, { label: string; description: string; icon: React.ReactNode; color: string }> = {
  CLOUDTRAIL: {
    label: 'CloudTrail',
    description: 'All AWS API activity — who did what, when, from where',
    icon: <Eye size={14} />,
    color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  },
  GUARDDUTY: {
    label: 'GuardDuty',
    description: 'Threat intelligence findings — malicious IPs, credential abuse, crypto mining',
    icon: <Shield size={14} />,
    color: 'text-red-400 bg-red-500/10 border-red-500/20',
  },
  SECURITY_HUB: {
    label: 'Security Hub',
    description: 'Aggregated findings — misconfigurations, vulnerabilities, compliance',
    icon: <AlertTriangle size={14} />,
    color: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  },
  CONFIG: {
    label: 'AWS Config',
    description: 'Configuration changes — resource drift, compliance violations',
    icon: <RefreshCw size={14} />,
    color: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  },
};

const RESPONSE_CAPABILITIES = [
  { action: 'Disable IAM access keys', blast: 'LOW', reversible: true },
  { action: 'Stop EC2 instances', blast: 'MEDIUM', reversible: true },
  { action: 'Block IPs via Security Groups', blast: 'MEDIUM', reversible: true },
  { action: 'Make S3 buckets private', blast: 'MEDIUM', reversible: true },
  { action: 'Attach deny policies to IAM users', blast: 'MEDIUM', reversible: true },
  { action: 'Create GuardDuty IP blocklists', blast: 'LOW', reversible: true },
];

const blastColors: Record<string, string> = {
  LOW: 'text-emerald-400 bg-emerald-500/10',
  MEDIUM: 'text-amber-400 bg-amber-500/10',
  HIGH: 'text-red-400 bg-red-500/10',
};

// ── Register Form ─────────────────────────────────────────────────────────────

interface RegisterFormProps {
  onSuccess: () => void;
  onCancel: () => void;
}

function RegisterForm({ onSuccess, onCancel }: RegisterFormProps) {
  const [roleArn, setRoleArn] = useState('');
  const [accountId, setAccountId] = useState('');
  const [tenantId] = useState('tenant-001');
  const [regions, setRegions] = useState('us-east-1');
  const [sources, setSources] = useState(['CLOUDTRAIL', 'GUARDDUTY', 'SECURITY_HUB']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const toggleSource = (source: string) => {
    setSources((prev) =>
      prev.includes(source) ? prev.filter((s) => s !== source) : [...prev, source]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleArn.startsWith('arn:aws:iam::')) {
      setError('Role ARN must start with arn:aws:iam::');
      return;
    }
    if (!accountId.match(/^\d{12}$/)) {
      setError('Account ID must be a 12-digit number');
      return;
    }
    if (sources.length === 0) {
      setError('Select at least one data source');
      return;
    }

    setLoading(true);
    setError('');

    try {
      await registerConnector({
        tenant_id: tenantId,
        role_arn: roleArn,
        account_id: accountId,
        regions: regions.split(',').map((r) => r.trim()).filter(Boolean),
        data_sources: sources,
      });
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel p-6 border-cyan-500/30">
      <h2 className="text-sm font-semibold text-gray-200 mb-1">Connect AWS Account</h2>
      <p className="text-xs text-gray-500 mb-5">
        Deploy the CloudFormation template in your AWS account first, then paste the Role ARN here.
      </p>

      {/* CloudFormation download link */}
      <div className="flex items-center gap-2 p-3 bg-gray-800/50 rounded-lg mb-5 text-xs">
        <Cloud size={14} className="text-cyan-400 flex-shrink-0" />
        <span className="text-gray-400">Step 1:</span>
        <span className="text-gray-300">Deploy the IAM role in your AWS account</span>
        <a
          href="https://console.aws.amazon.com/cloudformation/home#/stacks/create"
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
        >
          Open CloudFormation <ExternalLink size={11} />
        </a>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Role ARN <span className="text-red-400">*</span></label>
          <input
            type="text"
            value={roleArn}
            onChange={(e) => setRoleArn(e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/WatcherMK1-ConnectorRole"
            className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none font-mono"
            required
          />
          <p className="text-xs text-gray-600 mt-1">From the CloudFormation stack Outputs tab → RoleArn</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-gray-400 mb-1">AWS Account ID <span className="text-red-400">*</span></label>
            <input
              type="text"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              placeholder="123456789012"
              className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Regions</label>
            <input
              type="text"
              value={regions}
              onChange={(e) => setRegions(e.target.value)}
              placeholder="us-east-1, us-west-2"
              className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-2">Data Sources to Monitor</label>
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(DATA_SOURCE_INFO).map(([key, info]) => (
              <button
                key={key}
                type="button"
                onClick={() => toggleSource(key)}
                className={`flex items-center gap-2 p-2.5 rounded-lg border text-left transition-colors ${
                  sources.includes(key)
                    ? `${info.color} border-current`
                    : 'border-gray-700 text-gray-500 hover:border-gray-600'
                }`}
              >
                {info.icon}
                <div>
                  <p className="text-xs font-medium">{info.label}</p>
                  <p className="text-[10px] opacity-70 leading-tight">{info.description.slice(0, 40)}…</p>
                </div>
                {sources.includes(key) && <CheckCircle size={12} className="ml-auto flex-shrink-0" />}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-400">
            <XCircle size={14} />
            {error}
          </div>
        )}

        <div className="flex gap-3 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
          >
            {loading ? <><Loader2 size={14} className="animate-spin" /> Verifying role & connecting…</> : <><Plus size={14} /> Connect Account</>}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2.5 text-gray-400 border border-gray-700 rounded-lg text-sm hover:border-gray-600 transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

// ── Connector Card ────────────────────────────────────────────────────────────

interface ConnectorCardProps {
  connector: Connector;
  onPause: (id: string) => void;
}

function ConnectorCard({ connector, onPause }: ConnectorCardProps) {
  const [expanded, setExpanded] = useState(false);

  const statusConfig = {
    ACTIVE: { color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20', dot: 'bg-emerald-400', label: 'Active' },
    ERROR: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20', dot: 'bg-red-400', label: 'Error' },
    PAUSED: { color: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/20', dot: 'bg-gray-400', label: 'Paused' },
  }[connector.status];

  const lastPoll = connector.last_poll_at
    ? `${Math.round((Date.now() - new Date(connector.last_poll_at).getTime()) / 1000)}s ago`
    : 'Not yet polled';

  return (
    <div className="glass-panel overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-4 p-4">
        <div className="w-10 h-10 rounded-full bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center flex-shrink-0">
          <Cloud size={18} className="text-cyan-400" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-semibold text-gray-200 font-mono">{connector.account_id}</p>
            <span className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border ${statusConfig.bg} ${statusConfig.color}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${statusConfig.dot} ${connector.status === 'ACTIVE' ? 'animate-pulse' : ''}`} />
              {statusConfig.label}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-xs text-gray-500">
            <span>Regions: {connector.regions.join(', ')}</span>
            <span>·</span>
            <span className="flex items-center gap-1">
              <Wifi size={10} />
              Last poll: {lastPoll}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {connector.status === 'ACTIVE' && (
            <button
              onClick={() => onPause(connector.id)}
              className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
            >
              <Pause size={12} /> Pause
            </button>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
          >
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            {expanded ? 'Less' : 'Details'}
          </button>
        </div>
      </div>

      {/* Data Sources */}
      <div className="px-4 pb-3 flex flex-wrap gap-2">
        {connector.data_sources.map((source) => {
          const info = DATA_SOURCE_INFO[source];
          if (!info) return null;
          return (
            <span key={source} className={`flex items-center gap-1.5 px-2 py-1 rounded border text-xs ${info.color}`}>
              {info.icon}
              {info.label}
            </span>
          );
        })}
      </div>

      {/* Error message */}
      {connector.status === 'ERROR' && connector.error_message && (
        <div className="mx-4 mb-3 p-2.5 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-400">
          {connector.error_message}
        </div>
      )}

      {/* Expanded: capabilities */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* What Watcher can read */}
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
              What Watcher Monitors
            </p>
            <div className="space-y-2">
              {connector.data_sources.map((source) => {
                const info = DATA_SOURCE_INFO[source];
                if (!info) return null;
                return (
                  <div key={source} className="flex items-start gap-2.5 p-2.5 bg-gray-800/50 rounded-lg">
                    <span className={`mt-0.5 ${info.color.split(' ')[0]}`}>{info.icon}</span>
                    <div>
                      <p className="text-xs font-medium text-gray-200">{info.label}</p>
                      <p className="text-xs text-gray-500">{info.description}</p>
                    </div>
                    <CheckCircle size={12} className="text-emerald-400 ml-auto mt-0.5 flex-shrink-0" />
                  </div>
                );
              })}
            </div>
          </div>

          {/* What Watcher can do */}
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
              Response Actions Available
            </p>
            <div className="space-y-1.5">
              {RESPONSE_CAPABILITIES.map((cap) => (
                <div key={cap.action} className="flex items-center gap-2 p-2 bg-gray-800/30 rounded-lg">
                  <Zap size={12} className="text-cyan-400 flex-shrink-0" />
                  <span className="text-xs text-gray-300 flex-1">{cap.action}</span>
                  <span className={`px-1.5 py-0.5 text-xs rounded ${blastColors[cap.blast]}`}>
                    {cap.blast}
                  </span>
                  {cap.reversible && (
                    <span className="text-xs text-gray-500">↩ reversible</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Connector metadata */}
          <div className="p-3 bg-gray-800/30 rounded-lg space-y-1 text-xs text-gray-500">
            <div className="flex justify-between">
              <span>Connector ID</span>
              <span className="font-mono text-gray-400">{connector.id}</span>
            </div>
            <div className="flex justify-between">
              <span>Tenant</span>
              <span className="font-mono text-gray-400">{connector.tenant_id}</span>
            </div>
            <div className="flex justify-between">
              <span>Registered</span>
              <span className="text-gray-400">{new Date(connector.registered_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function Connectors() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try {
      const data = await fetchConnectors();
      setConnectors(data as Connector[]);
    } catch {
      // API not available yet
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  // Auto-refresh every 15 seconds to show polling status updates
  useEffect(() => {
    const interval = setInterval(load, 15_000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => { setRefreshing(true); load(); };

  const handlePause = async (id: string) => {
    try {
      await pauseConnector(id);
      load();
    } catch (err) {
      console.error('Failed to pause connector:', err);
    }
  };

  const handleRegistered = () => {
    setShowForm(false);
    setTimeout(load, 1000); // Give server a moment to register
  };

  const activeCount = connectors.filter((c) => c.status === 'ACTIVE').length;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">AWS Connectors</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Connect AWS accounts for Watcher to monitor and respond to threats
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
            Refresh
          </button>
          {!showForm && (
            <button
              onClick={() => setShowForm(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors"
            >
              <Plus size={14} />
              Connect Account
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      {connectors.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="glass-panel p-4">
            <p className="text-xs text-gray-500 mb-1">Connected Accounts</p>
            <p className="text-2xl font-bold text-gray-100">{connectors.length}</p>
          </div>
          <div className="glass-panel p-4">
            <p className="text-xs text-gray-500 mb-1">Active Monitoring</p>
            <p className="text-2xl font-bold text-emerald-400">{activeCount}</p>
          </div>
          <div className="glass-panel p-4">
            <p className="text-xs text-gray-500 mb-1">Data Sources</p>
            <p className="text-2xl font-bold text-cyan-400">
              {[...new Set(connectors.flatMap((c) => c.data_sources))].length}
            </p>
          </div>
        </div>
      )}

      {/* Register Form */}
      {showForm && (
        <RegisterForm onSuccess={handleRegistered} onCancel={() => setShowForm(false)} />
      )}

      {/* Connector List */}
      {loading ? (
        <div className="flex items-center justify-center h-48">
          <div className="flex items-center gap-3 text-gray-400">
            <Loader2 size={20} className="animate-spin" />
            <span>Loading connectors…</span>
          </div>
        </div>
      ) : connectors.length === 0 && !showForm ? (
        <div className="glass-panel p-12 text-center">
          <Cloud size={40} className="text-gray-600 mx-auto mb-4" />
          <p className="text-gray-300 font-medium mb-2">No AWS accounts connected</p>
          <p className="text-gray-500 text-sm mb-6 max-w-md mx-auto">
            Connect your first AWS account to start monitoring CloudTrail, GuardDuty,
            and Security Hub events with AI-powered threat detection.
          </p>
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 transition-colors"
          >
            <Plus size={16} />
            Connect Your First Account
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {connectors.map((connector) => (
            <ConnectorCard
              key={connector.id}
              connector={connector}
              onPause={handlePause}
            />
          ))}
        </div>
      )}

      {/* How it works */}
      {connectors.length === 0 && !showForm && (
        <div className="glass-panel p-5">
          <h2 className="text-sm font-semibold text-gray-200 mb-4">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              {
                step: '1',
                title: 'Deploy IAM Role',
                desc: 'Run the CloudFormation template in your AWS account. It creates a cross-account IAM role with read + response permissions.',
                color: 'text-cyan-400',
              },
              {
                step: '2',
                title: 'Connect Here',
                desc: 'Paste the Role ARN from the CloudFormation output. Watcher verifies it can assume the role, then starts monitoring.',
                color: 'text-emerald-400',
              },
              {
                step: '3',
                title: 'AI Takes Over',
                desc: 'Every 60 seconds, Watcher polls CloudTrail, GuardDuty, and Security Hub. Claude reasons about every event and responds automatically.',
                color: 'text-amber-400',
              },
            ].map(({ step, title, desc, color }) => (
              <div key={step} className="flex gap-3">
                <span className={`w-6 h-6 rounded-full border flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5 ${color} border-current bg-current/10`}>
                  {step}
                </span>
                <div>
                  <p className="text-sm font-medium text-gray-200">{title}</p>
                  <p className="text-xs text-gray-500 mt-1 leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
