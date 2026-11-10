// SeverityBadge — colored badge for critical/high/medium/low/info
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";
import type { SeverityLevel } from "../types";

const palette: Record<SeverityLevel, string> = {
  critical: "bg-red-500/20 text-red-400 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-400 border border-orange-500/40",
  medium: "bg-amber-500/20 text-amber-400 border border-amber-500/40",
  low: "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40",
  info: "bg-slate-500/20 text-slate-400 border border-slate-500/40",
};

interface Props {
  severity: SeverityLevel;
  size?: "sm" | "md";
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = "md" }) => {
  const px = size === "sm" ? "px-2 py-0.5 text-xs" : "px-3 py-1 text-sm";
  return (
    <span
      className={`inline-flex items-center rounded-full font-semibold uppercase tracking-wide ${px} ${palette[severity]}`}
    >
      {severity}
    </span>
  );
};
