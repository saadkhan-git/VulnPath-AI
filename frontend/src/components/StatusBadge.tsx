// StatusBadge — scan status indicator
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";
import type { ScanStatus } from "../types";

const palette: Record<ScanStatus, { cls: string; dot: string; label: string }> = {
  pending: {
    cls: "bg-slate-500/20 text-slate-400 border border-slate-500/40",
    dot: "bg-slate-400",
    label: "Pending",
  },
  extracting: {
    cls: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
    dot: "bg-blue-400 animate-pulse",
    label: "Extracting",
  },
  parsing: {
    cls: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
    dot: "bg-blue-400 animate-pulse",
    label: "Parsing",
  },
  analyzing: {
    cls: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
    dot: "bg-blue-400 animate-pulse",
    label: "Analyzing",
  },
  fusing: {
    cls: "bg-purple-500/20 text-purple-400 border border-purple-500/40",
    dot: "bg-purple-400 animate-pulse",
    label: "Fusing",
  },
  completed: {
    cls: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40",
    dot: "bg-emerald-400",
    label: "Completed",
  },
  failed: {
    cls: "bg-red-500/20 text-red-400 border border-red-500/40",
    dot: "bg-red-400",
    label: "Failed",
  },
  cancelled: {
    cls: "bg-amber-500/20 text-amber-400 border border-amber-500/40",
    dot: "bg-amber-400",
    label: "Cancelled",
  },
};

interface Props {
  status: ScanStatus;
}

export const StatusBadge: React.FC<Props> = ({ status }) => {
  const { cls, dot, label } = palette[status];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${cls}`}
    >
      <span className={`h-2 w-2 rounded-full ${dot}`} />
      {label}
    </span>
  );
};
