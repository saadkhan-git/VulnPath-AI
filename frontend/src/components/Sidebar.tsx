import React from "react";
import { NavLink } from "react-router-dom";
import {
  Bug,
  Clock,
  Info,
  LayoutDashboard,
  ScanLine,
  Shield,
} from "lucide-react";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard", end: true },
  { to: "/scan/new", icon: ScanLine, label: "New Scan" },
  { to: "/findings", icon: Bug, label: "Findings" },
  { to: "/history", icon: Clock, label: "Scan History" },
  { to: "/about", icon: Info, label: "About" },
];

export const Sidebar: React.FC = () => (
  <aside className="border-b border-slate-800 bg-[#0D1322] md:fixed md:inset-y-0 md:left-0 md:z-30 md:flex md:w-60 md:flex-col md:border-b-0 md:border-r">
    <div className="hidden items-center gap-3 border-b border-slate-800 px-5 py-5 md:flex">
      <div className="rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-2">
        <Shield className="h-5 w-5 text-cyan-400" />
      </div>
      <div>
        <div className="text-sm font-bold tracking-tight text-white">VulnPath AI</div>
        <div className="text-[10px] uppercase tracking-widest text-slate-500">
          Trace the path.
        </div>
      </div>
    </div>
    <nav className="overflow-x-auto px-3 py-3 md:flex-1 md:overflow-y-auto md:py-4">
      <ul className="flex min-w-max gap-1 md:min-w-0 md:flex-col">
        {navItems.map(({ to, icon: Icon, label, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors md:gap-3 ${
                  isActive
                    ? "border border-cyan-400/20 bg-cyan-400/10 text-cyan-400"
                    : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
    <div className="hidden border-t border-slate-800 px-5 py-4 md:block">
      <p className="text-[10px] text-slate-600">© Mohammad Saad Khan</p>
      <p className="mt-0.5 text-[10px] text-slate-700">v0.1.0 · Local-first SAST</p>
    </div>
  </aside>
);
