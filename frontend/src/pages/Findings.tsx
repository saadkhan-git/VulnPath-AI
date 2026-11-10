import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Search } from "lucide-react";
import { listFindings } from "../api/client";
import { ErrorState } from "../components/ErrorState";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { SeverityBadge } from "../components/SeverityBadge";
import type { Finding, SeverityLevel } from "../types";

const severities: Array<"all" | SeverityLevel> = ["all", "critical", "high", "medium", "low", "info"];

export const Findings: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState<"all" | SeverityLevel>("all");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setFindings(await listFindings());
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load findings.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();
    return findings
      .filter((finding) => severity === "all" || finding.severity === severity)
      .filter((finding) =>
        !query ||
        [finding.title, finding.cwe_id, finding.file_path, finding.function_name ?? ""]
          .some((value) => value.toLowerCase().includes(query))
      )
      .sort((a, b) => a.file_path.localeCompare(b.file_path) || a.line_number - b.line_number);
  }, [findings, search, severity]);

  if (loading) return <LoadingSpinner message="Loading findings from local scans…" />;
  if (error && findings.length === 0) return <ErrorState message={error} retry={() => void load()} />;

  return (
    <div className="space-y-5">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Triage</p>
        <h1 className="mt-2 text-2xl font-bold text-white">Findings</h1>
        <p className="mt-1 text-sm text-slate-400">Findings from the most recent 200 completed scans.</p>
      </div>
      {error && <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}
      <div className="flex flex-col gap-3 sm:flex-row">
        <label className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search title, CWE, file, or function"
            className="w-full rounded-lg border border-slate-800 bg-[#0D1322] py-2.5 pl-10 pr-3 text-sm text-slate-200 outline-none focus:border-cyan-400/40"
          />
        </label>
        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value as "all" | SeverityLevel)}
          className="rounded-lg border border-slate-800 bg-[#0D1322] px-3 py-2.5 text-sm capitalize text-slate-300 outline-none"
        >
          {severities.map((value) => <option key={value} value={value}>{value === "all" ? "All severities" : value}</option>)}
        </select>
      </div>
      <p className="text-xs text-slate-500">{visible.length} finding{visible.length === 1 ? "" : "s"}</p>
      {visible.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0D1322] p-8 text-center text-sm text-slate-500">
          {findings.length === 0 ? "No findings are available yet. Run a scan to populate this view." : "No findings match these filters."}
        </div>
      ) : (
        <div className="space-y-3">
          {visible.map((finding) => (
            <Link
              key={finding.finding_id}
              to={`/scans/${finding.scan_id}#${finding.finding_id}`}
              className="block rounded-xl border border-slate-800 bg-[#0D1322] p-4 transition hover:border-slate-700 hover:bg-[#101827]"
            >
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} size="sm" />
                <span className="font-mono text-xs text-cyan-300">{finding.cwe_id}</span>
                <span className="ml-auto text-xs text-slate-600">{finding.remediation_priority}</span>
              </div>
              <h2 className="mt-3 text-sm font-semibold text-slate-100">{finding.title}</h2>
              <p className="mt-1 truncate font-mono text-xs text-slate-500">
                {finding.file_path}:{finding.line_number}
                {finding.function_name ? ` · ${finding.function_name}()` : ""}
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Confidence {Math.round(finding.confidence * 100)}% · {finding.analysis_sources.join(", ") || "AST"}
              </p>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
};
