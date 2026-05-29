import { Outlet, NavLink } from 'react-router-dom';
import { useEffect, useState } from 'react';
import {
  LayoutDashboard,
  AlertTriangle,
  ShieldCheck,
  Zap,
  BarChart3,
  Shield,
  Activity,
  Plug,
} from 'lucide-react';
import TrustLevelBadge from './TrustLevelBadge';
import { fetchTrustLevel, fetchApprovals } from '../api/client';
import type { TrustLevelInfo } from '../types';

const navItems = [
  { to: '/', icon: <LayoutDashboard size={18} />, label: 'Dashboard', end: true },
  { to: '/approvals', icon: <ShieldCheck size={18} />, label: 'Approvals' },
  { to: '/actions', icon: <Zap size={18} />, label: 'Actions Log' },
  { to: '/connectors', icon: <Plug size={18} />, label: 'Connectors' },
  { to: '/pipeline', icon: <Activity size={18} />, label: 'AI Pipeline' },
  { to: '/executive', icon: <BarChart3 size={18} />, label: 'Executive View' },
];

export default function Layout() {
  const [trust, setTrust] = useState<TrustLevelInfo | null>(null);
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    fetchTrustLevel().then((data) => setTrust(data as TrustLevelInfo)).catch(() => {});
    fetchApprovals().then((data) => setPendingCount((data as unknown[]).length)).catch(() => {});
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 border-r border-gray-800 bg-gray-950 flex flex-col">
        {/* Logo */}
        <div className="h-16 flex items-center gap-3 px-5 border-b border-gray-800">
          <div className="relative">
            <Shield size={24} className="text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 rounded-full animate-pulse" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-gray-100 tracking-wide">WATCHER MK-1</h1>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest">AI Security Agent</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'nav-link-active' : 'nav-link-inactive'}`
              }
            >
              {item.icon}
              <span>{item.label}</span>
              {item.label === 'Approvals' && pendingCount > 0 && (
                <span className="ml-auto px-1.5 py-0.5 text-xs bg-amber-500/20 text-amber-400 rounded-full">
                  {pendingCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Trust Level */}
        <div className="px-3 py-3 border-t border-gray-800">
          <TrustLevelBadge trust={trust} />
        </div>

        {/* System Status */}
        <div className="px-4 py-3 border-t border-gray-800">
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
            <span>AI reasoning active</span>
          </div>
          {pendingCount > 0 && (
            <div className="flex items-center gap-2 text-xs text-amber-500 mt-1">
              <AlertTriangle size={12} />
              <span>{pendingCount} pending approval{pendingCount !== 1 ? 's' : ''}</span>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
