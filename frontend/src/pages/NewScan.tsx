import React, { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertCircle, Archive, FileCode, FlaskConical, Upload } from "lucide-react";
import { scanSamples, uploadFile, uploadZip } from "../api/client";

type TargetMode = "file" | "zip" | "sample";
type SampleSet = "vulnerable" | "safe" | "all";

export const NewScan: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<TargetMode>("file");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scanName, setScanName] = useState("");
  const [sampleSet, setSampleSet] = useState<SampleSet>("vulnerable");
  const [enableBandit, setEnableBandit] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chooseFile = (file?: File) => {
    if (!file) return;
    const valid = mode === "file"
      ? /\.(py|pyw)$/i.test(file.name)
      : /\.zip$/i.test(file.name);
    if (!valid) {
      setSelectedFile(null);
      setError(mode === "file"
        ? "Choose a Python source file (.py or .pyw)."
        : "Choose a ZIP archive (.zip).");
      return;
    }
    setSelectedFile(file);
    setError(null);
    if (!scanName) setScanName(file.name.replace(/\.(pyw?|zip)$/i, ""));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const name = scanName.trim() || selectedFile?.name || `Sample Scan [${sampleSet}]`;
      if (mode === "file" && !selectedFile) {
        throw new Error("Please choose a Python file.");
      }
      if (mode === "zip" && !selectedFile) {
        throw new Error("Please choose a ZIP archive.");
      }
      const result =
        mode === "file"
          ? await uploadFile(selectedFile!, name, enableBandit)
          : mode === "zip"
            ? await uploadZip(selectedFile!, name, enableBandit)
            : await scanSamples(sampleSet, enableBandit);
      navigate(`/scans/${result.scan_id}`);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Could not start scan.");
    } finally {
      setLoading(false);
    }
  };

  const modes = [
    { id: "file" as const, icon: FileCode, label: "Python file", desc: ".py / .pyw" },
    { id: "zip" as const, icon: Archive, label: "ZIP archive", desc: "Python project" },
    { id: "sample" as const, icon: FlaskConical, label: "Sample code", desc: "Built-in examples" },
  ];

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Analysis</p>
        <h1 className="mt-2 text-2xl font-bold text-white">Start a new scan</h1>
        <p className="mt-1 text-sm text-slate-400">
          Review Python source statically. The scanned program is never executed.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          {modes.map(({ id, icon: Icon, label, desc }) => (
            <button
              key={id}
              type="button"
              onClick={() => {
                setMode(id);
                setSelectedFile(null);
                setError(null);
              }}
              className={`flex items-center gap-3 rounded-xl border p-4 text-left transition sm:flex-col sm:text-center ${
                mode === id
                  ? "border-cyan-400/50 bg-cyan-400/10 text-cyan-300"
                  : "border-slate-800 bg-[#0D1322] text-slate-400 hover:border-slate-700"
              }`}
            >
              <Icon className="h-5 w-5" />
              <span>
                <span className="block text-sm font-semibold">{label}</span>
                <span className="mt-0.5 block text-xs text-slate-500">{desc}</span>
              </span>
            </button>
          ))}
        </div>

        {mode !== "sample" && (
          <label className="block">
            <span className="mb-2 block text-xs font-semibold uppercase tracking-widest text-slate-500">
              Scan name
            </span>
            <input
              value={scanName}
              onChange={(event) => setScanName(event.target.value)}
              maxLength={120}
              placeholder="e.g. payments-service"
              className="w-full rounded-lg border border-slate-700 bg-[#0D1322] px-4 py-3 text-sm text-slate-200 placeholder-slate-600 outline-none transition focus:border-cyan-400/50"
            />
          </label>
        )}

        {(mode === "file" || mode === "zip") && (
          <div>
            <span className="mb-2 block text-xs font-semibold uppercase tracking-widest text-slate-500">
              {mode === "file" ? "Python source file" : "ZIP archive"}
            </span>
            <div
              role="button"
              tabIndex={0}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") fileInputRef.current?.click();
              }}
              onClick={(event) => {
                if (event.target !== fileInputRef.current) fileInputRef.current?.click();
              }}
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragging(false);
                chooseFile(event.dataTransfer.files[0]);
              }}
              className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-10 text-center transition ${
                dragging
                  ? "border-cyan-400 bg-cyan-400/5"
                  : selectedFile
                    ? "border-emerald-500/50 bg-emerald-500/5"
                    : "border-slate-700 bg-[#0D1322] hover:border-slate-600"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept={mode === "file" ? ".py,.pyw" : ".zip"}
                className="hidden"
                onChange={(event) => chooseFile(event.target.files?.[0])}
              />
              <Upload className={`h-8 w-8 ${selectedFile ? "text-emerald-400" : "text-slate-500"}`} />
              <span className="text-sm text-slate-300">
                {selectedFile ? selectedFile.name : "Drop a file here or click to browse"}
              </span>
              {selectedFile && (
                <span className="text-xs text-slate-500">{(selectedFile.size / 1024).toFixed(1)} KB</span>
              )}
            </div>
          </div>
        )}

        {mode === "sample" && (
          <fieldset>
            <legend className="mb-2 text-xs font-semibold uppercase tracking-widest text-slate-500">
              Sample set
            </legend>
            <div className="grid grid-cols-3 gap-2">
              {(["vulnerable", "safe", "all"] as SampleSet[]).map((set) => (
                <button
                  key={set}
                  type="button"
                  onClick={() => setSampleSet(set)}
                  className={`rounded-lg border px-3 py-2.5 text-sm capitalize ${
                    sampleSet === set
                      ? "border-cyan-400/50 bg-cyan-400/10 text-cyan-300"
                      : "border-slate-800 bg-[#0D1322] text-slate-400 hover:border-slate-700"
                  }`}
                >
                  {set === "all" ? "Both sets" : set}
                </button>
              ))}
            </div>
          </fieldset>
        )}

        <label className="flex items-start gap-3 rounded-xl border border-slate-800 bg-[#0D1322] p-4">
          <input
            type="checkbox"
            checked={enableBandit}
            onChange={(event) => setEnableBandit(event.target.checked)}
            className="mt-0.5 accent-cyan-400"
          />
          <span>
            <span className="block text-sm font-medium text-slate-200">Enable Bandit integration</span>
            <span className="mt-1 block text-xs text-slate-500">
              Adds Bandit checks when the optional dependency is installed in this environment.
            </span>
          </span>
        </label>

        {error && (
          <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-cyan-400 py-3 text-sm font-bold text-[#070A11] transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "Queueing scan…" : "Start static analysis"}
        </button>
        <p className="text-center text-xs text-slate-600">
          Files remain local; no cloud service or code execution is involved.
        </p>
      </form>
    </div>
  );
};
