import { useState, useEffect, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  RefreshCw, Loader2, ChevronDown, ChevronUp, ExternalLink,
  CheckCircle, GitMerge, XCircle, Filter, Activity,
} from 'lucide-react';
import { fetchPolledEvents, fetchPolledEventStats } from '../api/client';

// ── Types ─────────────────────────────────────────────────────────────────────

interface PolledEvent {
  id: string;
  event_name: string;
  event_time: string;
  received_at: string;
  source: string;
  account_id: string;
  region: string;
  actor_arn: string;
  actor_type: string;
  actor_short: string;
  source_ip: string | null;
  status: 'PROCESSED' | 'CORRELATED' | 'SKIPPED';
  reason: string;
  incident_id: string | null;
  error_code: string | null;
  raw_payload: Record<string, unknown>;
}

interface EventStats {
  total: number;
  by_status: { PROCESSED: number; CORRELATED: number; SKIPPED: number };
  by_source: Record<string, number>;
}

// ── Status config ─────────────────────────────────────────────────────────────

const STATUS_CONFIG = {
  PROCESSED: {
    label: 'Processed',
    icon: <CheckCircle size={12} />,
    color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    dot: 'bg-cyan-400',
  },
  CORRELATED: {
    label: 'Correlated',
    icon: <GitMerge size={12} />,
    color: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    dot: 'bg-amber-400',
  },
  SKIPPED: {
    label: 'Skipped',
    icon: <XCircle size={12} />,
    color: 'text-gray-500 bg-gray-500/10 border-gray-500/20',
    dot: 'bg-gray-500',
  },
};

const SOURCE_COLORS: Record<string, string> = {
  CLOUDTRAIL: 'text-cyan-400 bg-cyan-500/10',
  GUARDDUTY: 'text-red-400 bg-red-500/10',
  SECURITY_HUB: 'text-amber-400 bg-amber-500/10',
};

function formatTime(ts: string) {
  return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDateTime(ts: string) {
  return new Date(ts).toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

// ── Event Row ─────────────────────────────────────────────────────────────────

function EventRow({ event, highlight }: { event: PolledEvent; highlight?: boolean }) {
  const [expanded, setExpanded] = useState(highlight ?? false);
  const cfg = STATUS_CONFIG[event.status];

  return (
    <div
      id={`event-${event.id}`}
      className={`border rounded-lg transition-colors ${
        highlight
          ? 'border-cyan-500/50 bg-cyan-500/5'
          : 'border-gray-800 hover:border-gray-700'
      }`}
    >
      {/* Row header */}
      <div
        className="flex items-center gap-3 p-3 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Status badge */}
        <span className={`flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium flex-shrink-0 ${cfg.color}`}>
          {cfg.icon}
          {cfg.label}
        </span>

        {/* Event name */}
        <span className="text-sm font-mono text-gray-200 flex-shrink-0">{event.event_name}</span>

        {/* Source */}
        <span className={`px-1.5 py-0.5 text-xs rounded flex-shrink-0 ${SOURCE_COLORS[event.source] ?? 'text-gray-400 bg-gray-800'}`}>
          {event.source}
        </span>

        {/* Actor */}
        <span className="text-xs text-gray-400 truncate flex-1 min-w-0">
          {event.actor_short}
          {event.source_ip && <span className="text-gray-600 ml-2">{event.source_ip}</span>}
        </span>

        {/* Error code */}
        {event.error_code && (
          <span className="text-xs text-red-400 flex-shrink-0">{event.error_code}</span>
        )}

        {/* Time */}
        <span className="text-xs text-gray-600 flex-shrink-0">{formatTime(event.event_time)}</span>

        {/* Incident link */}
        {event.incident_id && (
          <Link
            to={`/incidents/${event.incident_id}`}
            onClick={(e) => e.stopPropagation()}
            className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 flex-shrink-0"
          >
            <ExternalLink size={11} />
            {event.incident_id.slice(0, 8)}
          </Link>
        )}

        <button className="text-gray-600 hover:text-gray-400 flex-shrink-0">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Reason */}
      <div className="px-3 pb-2 -mt-1">
        <p className="text-xs text-gray-500">{event.reason}</p>
      </div>

      {/* Expanded: full details */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* Metadata grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            {[
              { label: 'Event ID', value: event.id, mono: true },
              { label: 'Event Time', value: formatDateTime(event.event_time) },
              { label: 'Received At', value: formatDateTime(event.received_at) },
              { label: 'Account', value: event.account_id, mono: true },
              { label: 'Region', value: event.region },
              { label: 'Actor Type', value: event.actor_type },
              { label: 'Source IP', value: event.source_ip ?? 'AWS Internal' },
              { label: 'Error Code', value: event.error_code ?? '—' },
            ].map(({ label, value, mono }) => (
              <div key={label} className="p-2 bg-gray-800/50 rounded">
                <p className="text-gray-500 mb-0.5">{label}</p>
                <p className={`text-gray-200 break-all ${mono ? 'font-mono' : ''}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Full actor ARN */}
          <div className="p-2 bg-gray-800/50 rounded text-xs">
            <p className="text-gray-500 mb-0.5">Actor ARN</p>
            <p className="text-gray-200 font-mono break-all">{event.actor_arn}</p>
          </div>

          {/* Raw payload */}
          <div>
            <p className="text-xs text-gray-500 mb-2 font-medium uppercase tracking-wider">Raw CloudTrail Payload</p>
            <pre className="text-xs text-gray-400 font-mono bg-gray-900/50 rounded-lg p-3 overflow-auto max-h-64 whitespace-pre-wrap break-all">
              {JSON.stringify(
                // Hide internal Watcher metadata from display
                Object.fromEntries(
                  Object.entries(event.raw_payload).filter(([k]) => !k.startsWith('_watcher_'))
                ),
                null, 2
              )}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function PolledEvents() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [events, setEvents] = useState<PolledEvent[]>([]);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Read filters from URL params
  const statusFilter = searchParams.get('status') ?? 'ALL';
  const sourceFilter = searchParams.get('source') ?? 'ALL';
  const highlightEventId = searchParams.get('event_id') ?? null;
  const incidentFilter = searchParams.get('incident_id') ?? null;

  const load = useCallback(async () => {
    try {
      const [evts, st] = await Promise.all([
        fetchPolledEvents({
          status: statusFilter !== 'ALL' ? statusFilter : undefined,
          source: sourceFilter !== 'ALL' ? sourceFilter : undefined,
          incident_id: incidentFilter ?? undefined,
          event_id: highlightEventId ?? undefined,
          limit: 200,
        }),
        fetchPolledEventStats(),
      ]);
      setEvents(evts as PolledEvent[]);
      setStats(st as EventStats);
    } catch {
      // API not available
    } finally {
      setLoading(false);
    }
  }, [statusFilter, sourceFilter, incidentFilter, highlightEventId]);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh every 5 seconds
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(load, 5_000);
    return () => clearInterval(interval);
  }, [autoRefresh, load]);

  // Scroll to highlighted event after load
  useEffect(() => {
    if (highlightEventId && events.length > 0) {
      setTimeout(() => {
        document.getElementById(`event-${highlightEventId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 100);
    }
  }, [highlightEventId, events]);

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value === 'ALL' || value === '') {
      next.delete(key);
    } else {
      next.set(key, value);
    }
    setSearchParams(next);
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Polled Events</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Real-time view of every event Watcher has polled — with decision and reason
            {incidentFilter && (
              <span className="ml-2 text-cyan-400">
                · Filtered to incident {incidentFilter.slice(0, 8)}
                <button onClick={() => setFilter('incident_id', '')} className="ml-1 text-gray-500 hover:text-gray-300">✕</button>
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border transition-colors ${
              autoRefresh
                ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                : 'text-gray-400 border-gray-700 hover:border-gray-600'
            }`}
          >
            <Activity size={13} className={autoRefresh ? 'animate-pulse' : ''} />
            {autoRefresh ? 'Live' : 'Paused'}
          </button>
          <button
            onClick={load}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 border border-gray-700 rounded-lg hover:border-gray-600 transition-colors"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="glass-panel p-4">
            <p className="text-xs text-gray-500 mb-1">Total Polled</p>
            <p className="text-2xl font-bold text-gray-100">{stats.total}</p>
          </div>
          <div className="glass-panel p-4 cursor-pointer hover:border-cyan-500/30 transition-colors" onClick={() => setFilter('status', 'PROCESSED')}>
            <p className="text-xs text-gray-500 mb-1">Processed by AI</p>
            <p className="text-2xl font-bold text-cyan-400">{stats.by_status.PROCESSED}</p>
          </div>
          <div className="glass-panel p-4 cursor-pointer hover:border-amber-500/30 transition-colors" onClick={() => setFilter('status', 'CORRELATED')}>
            <p className="text-xs text-gray-500 mb-1">Correlated</p>
            <p className="text-2xl font-bold text-amber-400">{stats.by_status.CORRELATED}</p>
          </div>
          <div className="glass-panel p-4 cursor-pointer hover:border-gray-600 transition-colors" onClick={() => setFilter('status', 'SKIPPED')}>
            <p className="text-xs text-gray-500 mb-1">Skipped</p>
            <p className="text-2xl font-bold text-gray-400">{stats.by_status.SKIPPED}</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter size={14} className="text-gray-500" />
          <span className="text-xs text-gray-500">Status:</span>
          <div className="flex gap-1">
            {['ALL', 'PROCESSED', 'CORRELATED', 'SKIPPED'].map((s) => (
              <button
                key={s}
                onClick={() => setFilter('status', s)}
                className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${
                  statusFilter === s
                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                    : 'text-gray-400 border-transparent hover:border-gray-700'
                }`}
              >
                {s === 'ALL' ? 'All' : s.charAt(0) + s.slice(1).toLowerCase()}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">Source:</span>
          <div className="flex gap-1">
            {['ALL', 'CLOUDTRAIL', 'GUARDDUTY', 'SECURITY_HUB'].map((s) => (
              <button
                key={s}
                onClick={() => setFilter('source', s)}
                className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${
                  sourceFilter === s
                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                    : 'text-gray-400 border-transparent hover:border-gray-700'
                }`}
              >
                {s === 'ALL' ? 'All' : s.replace('_', ' ')}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Events list */}
      {loading ? (
        <div className="flex items-center justify-center h-48">
          <div className="flex items-center gap-3 text-gray-400">
            <Loader2 size={20} className="animate-spin" />
            <span>Loading events…</span>
          </div>
        </div>
      ) : events.length === 0 ? (
        <div className="glass-panel p-12 text-center">
          <Activity size={32} className="text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400">No events yet.</p>
          <p className="text-gray-600 text-xs mt-1">Events will appear here as Watcher polls CloudTrail.</p>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-gray-600">{events.length} events shown</p>
          {events.map((event) => (
            <EventRow
              key={`${event.id}-${event.received_at}`}
              event={event}
              highlight={event.id === highlightEventId}
            />
          ))}
        </div>
      )}
    </div>
  );
}
