// LoadingSpinner — consistent loading state
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";
import { Shield } from "lucide-react";

interface Props {
  message?: string;
}

export const LoadingSpinner: React.FC<Props> = ({
  message = "Loading…",
}) => (
  <div className="flex flex-col items-center justify-center gap-4 py-20">
    <Shield className="h-10 w-10 text-cyan-400 animate-pulse" />
    <p className="text-slate-400 text-sm">{message}</p>
  </div>
);
