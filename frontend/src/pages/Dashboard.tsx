import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowUpRight,
  Bug,
  CheckCircle2,
  ScanLine,
  ShieldAlert,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { listScans } from "../api/client";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { MetricCard } from "../components/MetricCard";
import { StatusBadge } from "../components/StatusBadge";
import { SeverityBadge } from "../components/SeverityBadge";
import type { ScanRead, SeverityLevel } from "../types";

const severityColors: Record<SeverityLevel, string> = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#F59E0B",
  low: "#06B6D4",
  info: "#64748B",
};

export const Dashboard: React.FC = () => {
  const [scans, setScans] = useState<ScanRead[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setScans(await listScans());
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load scan history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const metrics = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed");
    const total = scans.reduce((sum, scan) => sum + scan.summary.total_findings, 0);
    const critical = scans.reduce((sum, scan) => sum + scan.summary.critical_count, 0);
    const high = scans.reduce((sum, scan) => sum + scan.summary.high_count, 0);
    const newest = completed[0];
    return { completed, total, critical, high, newest };
  }, [scans]);

  if (loading) return <LoadingSpinner message="Loading local scan history…" />;
  if (error) return <ErrorState message={error} retry={() => void load()} />;

  const severityData = (["critical", "high", "medium", "low", "info"] as SeverityLevel[])
    .map((severity) => ({
      severity,
      count: scans.reduce((sum, scan) => {
        const key = `${severity}_count` as
          | "critical_count"
          | "high_count"
          | "medium_count"
          | "low_count"
          | "info_count";
        return sum + scan.summary[key];
      }, 0),
    }))
    .filter((entry) => entry.count > 0);
  const recent = [...scans]
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
    .slice(0, 6);

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-br from-[#101B2D] via-[#0D1322] to-[#070A11] p-6 sm:p-8">
        <div className="pointer-events-none absolute -right-10 -top-20 h-72 w-72 rounded-full bg-cyan-500/5 blur-3xl" />
        <div className="relative flex flex-col justify-between gap-6 sm:flex-row sm:items-end">
          <div className="max-w-2xl">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">
              Local security workbench
            </p>
            <h1 className="mt-3 text-2xl font-bold tracking-tight text-white sm:text-3xl">
              Trace the path. Fix the flaw.
            </h1>
            <p className="mt-3 text-sm leading-6 text-slate-400">
              Review Python code with AST-based security detectors, optional Bandit checks,
              explainable evidence, and local SARIF / JSON / Markdown reports.
            </p>
          </div>
          <Link
            to="/scan/new"
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-cyan-400 px-4 py-3 text-sm font-bold text-[#070A11] transition hover:bg-cyan-300"
          >
            <ScanLine className="h-4 w-4" />
            Start a scan
          </Link>
        </div>
      </section>

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <MetricCard label="Scans" value={scans.length} icon={ScanLine} color="text-cyan-400" />
        <MetricCard label="Findings" value={metrics.total} icon={Bug} color="text-blue-400" />
        <MetricCard label="Critical" value={metrics.critical} icon={ShieldAlert} color="text-red-400" />
        <MetricCard label="High" value={metrics.high} icon={AlertTriangle} color="text-orange-400" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <section className="rounded-xl border border-slate-800 bg-[#0D1322] p-5">
          <div className="text-xs font-semibold uppercase tracking-widest text-slate-500">
            Latest completed scan
          </div>
          {metrics.newest ? (
            <div className="mt-5 flex items-center gap-4">
              <div className="flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-full border-4 border-cyan-400/40 text-center">
                <span className="font-mono text-2xl font-bold text-cyan-300">
                  {Math.round(metrics.newest.summary.security_score)}
                </span>
                <span className="text-[9px] uppercase tracking-wider text-slate-500">score</span>
              </div>
              <div className="min-w-0">
                <Link to={`/scans/${metrics.newest.scan_id}`} className="block truncate text-sm font-semibold text-slate-200 hover:text-cyan-300">
                  {metrics.newest.project_name}
                </Link>
                <p className="mt-1 text-xs text-slate-500">
                  {metrics.newest.summary.total_findings} findings · {metrics.newest.files_scanned} files
                </p>
                <p className="mt-1 text-xs text-slate-600">
                  {new Date(metrics.newest.created_at).toLocaleString()}
                </p>
              </div>
            </div>
          ) : (
            <div className="mt-4 text-sm text-slate-500">Complete a scan to see its score.</div>
          )}
          <div className="mt-5 flex items-center gap-2 text-xs text-slate-500">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            {metrics.completed.length} completed scan{metrics.completed.length === 1 ? "" : "s"}
          </div>
        </section>

        <section className="rounded-xl border border-slate-800 bg-[#0D1322] p-5 xl:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">Findings by severity</h2>
            <Link to="/findings" className="text-xs text-cyan-400 hover:text-cyan-300">View findings</Link>
          </div>
          {severityData.length === 0 ? (
            <div className="flex h-40 items-center justify-center text-sm text-slate-600">No findings in scan history.</div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={severityData} barSize={30}>
                <XAxis dataKey="severity" tick={{ fill: "#94A3B8", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                <Tooltip
                  contentStyle={{ background: "#0D1322", border: "1px solid #1E293B", borderRadius: 8, color: "#E2E8F0" }}
                  cursor={{ fill: "#1E293B" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry) => (
                    <Cell key={entry.severity} fill={severityColors[entry.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </section>
      </div>

      <section className="overflow-hidden rounded-xl border border-slate-800 bg-[#0D1322]">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">Recent scans</h2>
          <Link to="/history" className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
            Full history <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        </div>
        {recent.length === 0 ? (
          <EmptyState
            icon={ScanLine}
            title="No scans yet"
            description="Scan a Python file, a ZIP project, or the bundled samples."
            action={<Link to="/scan/new" className="rounded-lg border border-cyan-400/30 px-4 py-2 text-sm text-cyan-300 hover:bg-cyan-400/10">Create first scan</Link>}
          />
        ) : (
          <div className="divide-y divide-slate-800">
            {recent.map((scan) => (
              <Link key={scan.scan_id} to={`/scans/${scan.scan_id}`} className="flex items-center justify-between gap-4 px-5 py-4 transition hover:bg-slate-800/30">
                <div className="flex min-w-0 items-center gap-3">
                  <StatusBadge status={scan.status} />
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-200">{scan.project_name}</p>
                    <p className="mt-1 text-xs text-slate-500">{new Date(scan.created_at).toLocaleString()} · {scan.target_type}</p>
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  {scan.summary.critical_count > 0 && <SeverityBadge severity="critical" size="sm" />}
                  <span className="text-xs text-slate-500">{scan.summary.total_findings} findings</span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
