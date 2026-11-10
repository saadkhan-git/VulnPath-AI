import React, { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Ban, Download, RefreshCw } from "lucide-react";
import { cancelScan, downloadReport, getScan } from "../api/client";
import { CodeViewer } from "../components/CodeViewer";
import { ErrorState } from "../components/ErrorState";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import type { Finding, ReportFormat, ScanRead, ScanStatus } from "../types";

const activeStatuses: ScanStatus[] = ["pending", "extracting", "parsing", "analyzing", "fusing"];
const reportFormats: Array<{ value: ReportFormat; label: string }> = [
  { value: "sarif", label: "SARIF" },
  { value: "json", label: "JSON" },
  { value: "markdown", label: "Markdown" },
];

const FindingPanel: React.FC<{ finding: Finding }> = ({ finding }) => {
  const contextLines = finding.code_context?.split("\n") ?? [];
  const parsedLines = contextLines.map((line) => {
    const match = line.match(/^[> ]\s*(\d+)\s+\|\s?(.*)$/);
    return match ? { number: Number(match[1]), text: match[2] } : null;
  }).filter((line): line is { number: number; text: string } => line !== null);
  const code = parsedLines.length
    ? parsedLines.map((line) => line.text).join("\n")
    : finding.code_context ?? "";
  const startLine = parsedLines[0]?.number ?? finding.line_number;

  return (
    <article id={finding.finding_id} className="scroll-mt-24 rounded-xl border border-slate-800 bg-[#0D1322] p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} size="sm" />
        <span className="font-mono text-xs text-cyan-300">{finding.cwe_id}</span>
        <span className="ml-auto text-xs font-semibold text-slate-500">{finding.remediation_priority}</span>
      </div>
      <h2 className="mt-3 text-base font-semibold text-slate-100">{finding.title}</h2>
      <p className="mt-1 font-mono text-xs text-slate-500">
        {finding.file_path}:{finding.line_number}
        {finding.function_name ? ` · ${finding.function_name}()` : ""}
      </p>
      {finding.source_description && <p className="mt-3 text-sm text-slate-400"><b className="text-slate-300">Source:</b> {finding.source_description}</p>}
      {finding.sink_description && <p className="mt-1 text-sm text-slate-400"><b className="text-slate-300">Sink:</b> {finding.sink_description}</p>}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
        <span>Confidence {Math.round(finding.confidence * 100)}%</span>
        <span>Reachability: {finding.reachability}</span>
        <span>Exposure: {finding.exposure}</span>
        <span>Source: {finding.analysis_sources.join(", ") || "AST"}</span>
      </div>
      {finding.evidence_notes.length > 0 && (
        <ul className="mt-3 list-disc space-y-1 pl-5 text-xs leading-5 text-slate-400">
          {finding.evidence_notes.map((note, index) => <li key={`${index}-${note}`}>{note}</li>)}
        </ul>
      )}
      {code && (
        <div className="mt-4">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-500">Code context</p>
          <CodeViewer code={code} startLine={startLine} highlightLine={finding.line_number} />
        </div>
      )}
      {finding.data_flow_path.length > 0 && (
        <div className="mt-4">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-500">Evidence path</p>
          <ol className="space-y-2 border-l border-slate-700 pl-4">
            {finding.data_flow_path.map((step) => (
              <li key={`${step.step_number}-${step.file_path}-${step.line_number}`} className="relative text-xs">
                <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-cyan-400" />
                <span className="font-semibold uppercase text-cyan-300">{step.node_type}</span>
                <span className="ml-2 font-mono text-slate-500">{step.file_path}:{step.line_number}</span>
                <p className="mt-1 break-all font-mono text-slate-400">{step.statement}</p>
                {step.description && <p className="mt-1 text-slate-500">{step.description}</p>}
              </li>
            ))}
          </ol>
        </div>
      )}
    </article>
  );
};

export const ScanDetail: React.FC = () => {
  const { scanId = "" } = useParams();
  const [scan, setScan] = useState<ScanRead | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);

  const load = useCallback(async () => {
    const result = await getScan(scanId);
    setScan(result);
    setError(null);
    return result;
  }, [scanId]);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await getScan(scanId);
        if (!active) return;
        setScan(result);
        setError(null);
        setLoading(false);
        if (activeStatuses.includes(result.status)) {
          timer = window.setTimeout(() => void poll(), 1200);
        }
      } catch (pollError) {
        if (!active) return;
        setError(pollError instanceof Error ? pollError.message : "Could not load this scan.");
        setLoading(false);
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [scanId]);

  const cancel = async () => {
    setActionBusy(true);
    setActionError(null);
    try {
      await cancelScan(scanId);
      await load();
    } catch (cancelError) {
      setActionError(cancelError instanceof Error ? cancelError.message : "Could not cancel this scan.");
    } finally {
      setActionBusy(false);
    }
  };

  const report = async (format: ReportFormat) => {
    setActionBusy(true);
    setActionError(null);
    try {
      await downloadReport(scanId, format);
    } catch (reportError) {
      setActionError(reportError instanceof Error ? reportError.message : "Could not download report.");
    } finally {
      setActionBusy(false);
    }
  };

  if (loading) return <LoadingSpinner message="Loading scan details…" />;
  if (error && !scan) return <ErrorState message={error} retry={() => void load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Request failed"))} />;
  if (!scan) return null;

  const isActive = activeStatuses.includes(scan.status);
  const summary = scan.summary;

  return (
    <div className="space-y-5">
      <Link to="/history" className="inline-flex items-center gap-2 text-xs text-slate-500 hover:text-cyan-300">
        <ArrowLeft className="h-4 w-4" /> Back to scan history
      </Link>
      <section className="rounded-xl border border-slate-800 bg-[#0D1322] p-5 sm:p-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="break-words text-xl font-bold text-white">{scan.project_name}</h1>
              <StatusBadge status={scan.status} />
            </div>
            <p className="mt-2 font-mono text-xs text-slate-600">{scan.scan_id}</p>
            <p className="mt-2 text-xs text-slate-500">
              {scan.target_type} · Started {new Date(scan.created_at).toLocaleString()}
              {scan.completed_at ? ` · Finished ${new Date(scan.completed_at).toLocaleString()}` : ""}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {isActive && (
              <button disabled={actionBusy} onClick={() => void cancel()} className="inline-flex items-center gap-2 rounded-lg border border-amber-500/30 px-3 py-2 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50">
                <Ban className="h-4 w-4" /> Cancel scan
              </button>
            )}
            {scan.status === "completed" && reportFormats.map(({ value, label }) => (
              <button key={value} disabled={actionBusy} onClick={() => void report(value)} className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:border-cyan-400/40 hover:text-cyan-300 disabled:opacity-50">
                <Download className="h-3.5 w-3.5" /> {label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => void load().catch((refreshError: unknown) =>
                setActionError(refreshError instanceof Error ? refreshError.message : "Could not refresh scan.")
              )}
              className="rounded-lg border border-slate-700 p-2 text-slate-400 hover:text-white"
              title="Refresh"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>
        {actionError && <p role="alert" className="mt-4 text-sm text-red-300">{actionError}</p>}
        {isActive && (
          <div className="mt-6">
            <div className="mb-2 flex justify-between text-xs text-slate-400">
              <span>{scan.current_file ? `Analyzing ${scan.current_file}` : "Preparing scan…"}</span>
              <span>{scan.files_scanned}/{scan.total_files} files · {scan.progress_percent}%</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-slate-800">
              <div className="h-full rounded-full bg-cyan-400 transition-all" style={{ width: `${scan.progress_percent}%` }} />
            </div>
          </div>
        )}
        {scan.status === "failed" && (
          <div role="alert" className="mt-5 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
            {scan.error_message || "The scan failed without an error message."}
          </div>
        )}
        {scan.status === "cancelled" && (
          <div className="mt-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
            This scan was cancelled before it completed.
          </div>
        )}
        {scan.status === "completed" && (
          <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {[
              ["Score", `${summary.security_score}/100`, "text-cyan-300"],
              ["Total", summary.total_findings, "text-slate-100"],
              ["Critical", summary.critical_count, "text-red-400"],
              ["High", summary.high_count, "text-orange-400"],
              ["Medium", summary.medium_count, "text-amber-300"],
              ["Files", scan.files_scanned, "text-slate-100"],
            ].map(([label, value, color]) => (
              <div key={label} className="rounded-lg border border-slate-800 bg-[#070A11] p-3">
                <p className="text-[10px] uppercase tracking-widest text-slate-600">{label}</p>
                <p className={`mt-1 font-mono text-lg font-bold ${color}`}>{value}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      {scan.status === "completed" && (
        <section className="space-y-3">
          <div className="flex items-end justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Findings</h2>
              <p className="mt-1 text-xs text-slate-500">{summary.total_findings} reported · ordered by source location</p>
            </div>
            {Object.keys(summary.cwe_distribution).length > 0 && (
              <div className="hidden text-right text-xs text-slate-500 sm:block">
                {Object.entries(summary.cwe_distribution).slice(0, 3).map(([cwe, count]) => `${cwe}: ${count}`).join(" · ")}
              </div>
            )}
          </div>
          {(scan.findings ?? []).length === 0 ? (
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6 text-sm text-emerald-300">
              No findings were reported by the enabled static checks.
            </div>
          ) : (
            <div className="space-y-3">
              {scan.findings?.map((finding) => <FindingPanel key={finding.finding_id} finding={finding} />)}
            </div>
          )}
        </section>
      )}
    </div>
  );
};
