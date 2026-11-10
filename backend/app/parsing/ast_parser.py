"""Robust Python Abstract Syntax Tree (AST) parsing with error resilience."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from backend.app.ingestion.scanner_target import TargetFile


@dataclass
class ParsedFile:
    """Encapsulates parsed source code and its AST structure."""
    relative_path: str
    source_code: str
    lines: List[str]
    ast_tree: Optional[ast.AST] = None
    syntax_error: Optional[str] = None
    total_lines: int = 0


class PythonAstParser:
    """Parses Python source code into AST with graceful syntax error recovery."""

    @staticmethod
    def parse_source(source_code: str, relative_path: str = "source.py") -> ParsedFile:
        """Parses a string of Python code into a ParsedFile instance."""
        lines = source_code.splitlines()
        total_lines = len(lines)

        try:
            tree = ast.parse(source_code, filename=relative_path)
            return ParsedFile(
                relative_path=relative_path,
                source_code=source_code,
                lines=lines,
                ast_tree=tree,
                syntax_error=None,
                total_lines=total_lines,
            )
        except SyntaxError as e:
            err_msg = f"SyntaxError at line {e.lineno}, col {e.offset}: {e.msg}"
            return ParsedFile(
                relative_path=relative_path,
                source_code=source_code,
                lines=lines,
                ast_tree=None,
                syntax_error=err_msg,
                total_lines=total_lines,
            )

    @classmethod
    def parse_file(cls, target: TargetFile) -> ParsedFile:
        """Reads and parses a TargetFile from disk with multi-encoding fallback."""
        source_bytes = target.absolute_path.read_bytes()
        source_code: str

        for encoding in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                source_code = source_bytes.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            source_code = source_bytes.decode("utf-8", errors="replace")

        return cls.parse_source(source_code, relative_path=target.relative_path)

    @staticmethod
    def extract_code_context(parsed_file: ParsedFile, line_number: int, context_lines: int = 3) -> str:
        """
        Extracts surrounding lines with clear line number prefixes and a marker on the target line.
        """
        if not parsed_file.lines or line_number < 1:
            return ""

        total = len(parsed_file.lines)
        start_idx = max(0, line_number - 1 - context_lines)
        end_idx = min(total, line_number + context_lines)

        snippet_lines = []
        for idx in range(start_idx, end_idx):
            curr_lineno = idx + 1
            marker = ">" if curr_lineno == line_number else " "
            code_line = parsed_file.lines[idx]
            snippet_lines.append(f"{marker} {curr_lineno:4d} | {code_line}")

        return "\n".join(snippet_lines)
