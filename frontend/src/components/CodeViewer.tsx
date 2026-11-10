// CodeViewer — syntax-highlighted source code with line numbers and highlighted vulnerable line
// Copyright © Mohammad Saad Khan. All rights reserved.

import React from "react";

interface Props {
  code: string;
  highlightLine?: number; // 1-based
  startLine?: number; // 1-based offset for display
  language?: string;
  maxLines?: number;
}

export const CodeViewer: React.FC<Props> = ({
  code,
  highlightLine,
  startLine = 1,
  maxLines,
}) => {
  const lines = code.split("\n");
  const displayLines = maxLines ? lines.slice(0, maxLines) : lines;

  return (
    <div className="rounded-lg border border-slate-700 bg-[#070A11] overflow-auto text-xs font-mono">
      <table className="w-full border-collapse">
        <tbody>
          {displayLines.map((line, i) => {
            const lineNum = startLine + i;
            const isHighlighted = lineNum === highlightLine;
            return (
              <tr
                key={lineNum}
                className={
                  isHighlighted
                    ? "bg-red-500/15 border-l-2 border-red-500"
                    : "hover:bg-slate-800/40"
                }
              >
                <td className="select-none w-12 text-right pr-4 pl-3 py-0.5 text-slate-600 border-r border-slate-800">
                  {lineNum}
                </td>
                <td className="pl-4 pr-6 py-0.5 whitespace-pre">
                  <span
                    className={
                      isHighlighted ? "text-red-300" : "text-slate-300"
                    }
                  >
                    {line || " "}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
