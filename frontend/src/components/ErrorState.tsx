// ErrorState — consistent error display
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";
import { AlertTriangle } from "lucide-react";

interface Props {
  title?: string;
  message: string;
  retry?: () => void;
}

export const ErrorState: React.FC<Props> = ({
  title = "Something went wrong",
  message,
  retry,
}) => (
  <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
    <div className="rounded-full border border-red-500/30 bg-red-500/10 p-5">
      <AlertTriangle className="h-8 w-8 text-red-400" />
    </div>
    <div>
      <p className="text-base font-semibold text-red-300">{title}</p>
      <p className="mt-1 text-sm text-slate-400 max-w-md">{message}</p>
    </div>
    {retry && (
      <button
        onClick={retry}
        className="mt-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-sm text-slate-300 hover:bg-slate-700 transition"
      >
        Try again
      </button>
    )}
  </div>
);
