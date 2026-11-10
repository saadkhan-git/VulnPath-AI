import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, Trash2 } from "lucide-react";
import { deleteScan, listScans } from "../api/client";
import { ErrorState } from "../components/ErrorState";
import { LoadingSpinner } from "../components/LoadingSpinner";
import { StatusBadge } from "../components/StatusBadge";
import type { ScanRead } from "../types";

const activeStatuses = ["pending", "extracting", "parsing", "analyzing", "fusing"];

export const ScanHistory: React.FC = () => {
  const [scans, setScans] = useState<ScanRead[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setScans(await listScans(200));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Could not load scan history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const remove = async (scan: ScanRead) => {
    if (!window.confirm(`Delete scan "${scan.project_name}" and its findings?`)) return;
    try {
      await deleteScan(scan.scan_id);
      setScans((current) => current.filter((entry) => entry.scan_id !== scan.scan_id));
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "Could not delete scan.");
    }
  };

  if (loading) return <LoadingSpinner message="Loading scan history…" />;
  if (error && scans.length === 0) return <ErrorState message={error} retry={() => void load()} />;

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Workspace</p>
          <h1 className="mt-2 text-2xl font-bold text-white">Scan history</h1>
          <p className="mt-1 text-sm text-slate-400">{scans.length} most recent scans stored locally</p>
        </div>
        <button type="button" onClick={() => void load()} className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800">
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>
      {error && <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{error}</div>}
      {scans.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-[#0D1322] p-8 text-center">
          <p className="text-sm text-slate-400">There are no scans in your local history.</p>
          <Link to="/scan/new" className="mt-4 inline-block text-sm text-cyan-300 hover:text-cyan-200">Start a scan →</Link>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#0D1322]">
          <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 border-b border-slate-800 px-4 py-3 text-[11px] font-semibold uppercase tracking-widest text-slate-500 sm:grid-cols-[minmax(0,1fr)_110px_120px_48px]">
            <span>Scan</span><span className="hidden sm:block">Status</span><span className="hidden sm:block">Findings</span><span />
          </div>
          <div className="divide-y divide-slate-800">
            {scans.map((scan) => {
              const active = activeStatuses.includes(scan.status);
              return (
              <div key={scan.scan_id} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-4 py-4 sm:grid-cols-[minmax(0,1fr)_110px_120px_48px]">
                <Link to={`/scans/${scan.scan_id}`} className="min-w-0">
                  <p className="truncate text-sm font-medium text-slate-200 hover:text-cyan-300">{scan.project_name}</p>
                  <p className="mt-1 truncate font-mono text-[11px] text-slate-600">{scan.scan_id}</p>
                  <p className="mt-1 text-xs text-slate-500">{new Date(scan.created_at).toLocaleString()} · {scan.target_type}</p>
                </Link>
                <div className="hidden sm:block"><StatusBadge status={scan.status} /></div>
                <span className="hidden text-sm text-slate-400 sm:block">{scan.summary.total_findings}</span>
                <button
                  type="button"
                  aria-label={`Delete ${scan.project_name}`}
                  title={active ? "Cancel and wait for this scan before deleting it" : "Delete scan"}
                  disabled={active}
                  onClick={() => void remove(scan)}
                  className="rounded-md p-2 text-slate-600 transition hover:bg-red-500/10 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-30"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
                <div className="col-span-2 sm:hidden"><StatusBadge status={scan.status} /></div>
              </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
