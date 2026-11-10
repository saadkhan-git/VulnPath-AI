// EmptyState — consistent empty list state
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";
import type { LucideIcon } from "lucide-react";

interface Props {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<Props> = ({
  icon: Icon,
  title,
  description,
  action,
}) => (
  <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
    <div className="rounded-full border border-slate-700 bg-slate-800/50 p-5">
      <Icon className="h-8 w-8 text-slate-500" />
    </div>
    <div>
      <p className="text-base font-semibold text-slate-300">{title}</p>
      {description && (
        <p className="mt-1 text-sm text-slate-500">{description}</p>
      )}
    </div>
    {action && <div className="mt-2">{action}</div>}
  </div>
);
