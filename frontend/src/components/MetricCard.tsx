// MetricCard — dark panel metric card
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";
import type { LucideIcon } from "lucide-react";

interface Props {
  label: string;
  value: number | string;
  icon: LucideIcon;
  color?: string; // tailwind text color class
  sub?: string;
}

export const MetricCard: React.FC<Props> = ({
  label,
  value,
  icon: Icon,
  color = "text-cyan-400",
  sub,
}) => (
  <div className="rounded-xl border border-slate-800 bg-[#0D1322] p-5 flex flex-col gap-3">
    <div className="flex items-center justify-between">
      <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">
        {label}
      </span>
      <Icon className={`h-5 w-5 ${color} opacity-80`} />
    </div>
    <div className={`text-3xl font-bold font-mono ${color}`}>{value}</div>
    {sub && <div className="text-xs text-slate-500">{sub}</div>}
  </div>
);
