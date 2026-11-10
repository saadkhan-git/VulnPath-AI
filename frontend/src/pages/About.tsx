import React from "react";
import type { HealthResponse } from "../types";

interface Props {
  health: HealthResponse | null;
}

export const About: React.FC<Props> = ({ health }) => (
  <div className="mx-auto max-w-4xl space-y-6">
    <div>
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">Product</p>
      <h1 className="mt-2 text-2xl font-bold text-white">About VulnPath AI</h1>
      <p className="mt-2 text-sm text-slate-400">A local-first Python static analysis workbench.</p>
    </div>
    <section className="rounded-xl border border-slate-800 bg-[#0D1322] p-5">
      <h2 className="text-sm font-semibold text-white">Implemented analysis</h2>
      <ul className="mt-3 grid gap-2 text-sm text-slate-400 sm:grid-cols-2">
        {[
          "Python AST-based detectors for SQL injection and command injection",
          "Path traversal, unsafe deserialization, and hardcoded-secret checks",
          "Weak cryptography checks and project-specific YAML rules",
          "Optional Bandit integration when installed",
          "SQLite scan history and static source evidence",
          "SARIF 2.1.0, JSON, and Markdown report exports",
        ].map((item) => <li key={item} className="rounded-lg border border-slate-800 bg-[#070A11] p-3">{item}</li>)}
      </ul>
    </section>
    <section className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-5">
      <h2 className="text-sm font-semibold text-amber-200">Current scope</h2>
      <p className="mt-2 text-sm leading-6 text-slate-400">
        This release analyzes Python source only. Learned CodeBERT embeddings, a program dependency
        graph pipeline, trained PAEF fusion, automatic remediation, and non-Python language support
        are not implemented. Results are static-analysis leads and should be reviewed before acting.
      </p>
    </section>
    <section className="rounded-xl border border-slate-800 bg-[#0D1322] p-5">
      <h2 className="text-sm font-semibold text-white">Local runtime</h2>
      <dl className="mt-3 grid gap-4 text-sm sm:grid-cols-2">
        <div><dt className="text-xs text-slate-500">Backend status</dt><dd className="mt-1 text-slate-200">{health?.status ?? "Unavailable"}</dd></div>
        <div><dt className="text-xs text-slate-500">Python</dt><dd className="mt-1 text-slate-200">{health?.runtime.python_version ?? "—"}</dd></div>
        <div><dt className="text-xs text-slate-500">Supported extensions</dt><dd className="mt-1 text-slate-200">{health?.capabilities.supported_extensions.join(", ") ?? "—"}</dd></div>
        <div><dt className="text-xs text-slate-500">Archive limit</dt><dd className="mt-1 text-slate-200">{health ? `${health.capabilities.max_archive_size_mb} MB` : "—"}</dd></div>
      </dl>
    </section>
  </div>
);
