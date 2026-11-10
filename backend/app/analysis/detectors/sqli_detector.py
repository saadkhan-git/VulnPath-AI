"""SQL Injection (CWE-89) AST detector with variable tracking and taint tracing."""

import ast
from typing import Dict, List, Optional, Set, Tuple

from backend.app.analysis.base import BaseDetector
from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile
from backend.app.schemas.finding import CodePathNode, FindingCreate

SQL_EXECUTE_METHODS: Set[str] = {
    "execute",
    "executemany",
    "raw",
    "executescript",
}

SQL_KEYWORDS: Set[str] = {
    "select", "insert", "update", "delete", "drop", "alter", "create", "from", "where"
}


class SqlInjectionDetector(BaseDetector):
    """
    Detects improper neutralization of special elements in SQL commands (CWE-89).
    Flags f-strings, format() calls, % formatting, and string concatenations reaching SQL execution sinks.
    """

    name = "SqlInjectionDetector"
    cwe_id = "CWE-89"
    title = "Potential SQL Injection"
    severity = SeverityLevel.HIGH
    default_confidence = 0.92

    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        if not parsed_file.ast_tree:
            return []

        findings: List[FindingCreate] = []

        # Scope tracker: map (func_name, var_name) -> (ast.AST node, statement_text, lineno, reason)
        unsafe_variables: Dict[Tuple[Optional[str], str], Tuple[ast.AST, str, int, str]] = {}

        # 1. First pass: Collect variables constructed with dynamic string interpolation/concatenation
        for func_node in ast.walk(parsed_file.ast_tree):
            if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = func_node.name
                for stmt in func_node.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        var_name = stmt.targets[0].id
                        is_unsafe, reason = self._is_unsafe_sql_string_expression(stmt.value, parsed_file)
                        if is_unsafe:
                            raw_stmt = parsed_file.lines[stmt.lineno - 1].strip() if stmt.lineno <= len(parsed_file.lines) else var_name
                            unsafe_variables[(func_name, var_name)] = (stmt.value, raw_stmt, stmt.lineno, reason)

        # 2. Second pass: Inspect calls to execute(...) methods
        for node in ast.walk(parsed_file.ast_tree):
            if isinstance(node, ast.Call):
                method_name = self._get_call_method_name(node)
                if method_name in SQL_EXECUTE_METHODS and node.args:
                    query_arg = node.args[0]
                    enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)

                    # Case A: Query is an unsafe variable defined in the same function scope
                    if isinstance(query_arg, ast.Name):
                        var_key = (enclosing_func, query_arg.id)
                        if var_key in unsafe_variables:
                            src_node, src_stmt, src_line, reason = unsafe_variables[var_key]
                            sink_stmt = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else "execute"

                            data_flow_path = [
                                CodePathNode(
                                    step_number=1,
                                    file_path=parsed_file.relative_path,
                                    line_number=src_line,
                                    function_name=enclosing_func,
                                    statement=src_stmt,
                                    node_type="source",
                                    description=f"SQL query dynamically formatted: {reason}",
                                ),
                                CodePathNode(
                                    step_number=2,
                                    file_path=parsed_file.relative_path,
                                    line_number=node.lineno,
                                    function_name=enclosing_func,
                                    statement=sink_stmt,
                                    node_type="sink",
                                    description=f"Query executed without parameterized binding via {method_name}()",
                                ),
                            ]

                            findings.append(
                                FindingCreate(
                                    scan_id=scan_id,
                                    title=self.title,
                                    cwe_id=self.cwe_id,
                                    file_path=parsed_file.relative_path,
                                    line_number=node.lineno,
                                    function_name=enclosing_func,
                                    severity=self.severity,
                                    confidence=self.default_confidence,
                                    reachability="reachable",
                                    exposure="internal",
                                    remediation_priority="P1",
                                    source_description=f"Formatted query string variable '{query_arg.id}'",
                                    sink_description=f"Database execution call {method_name}()",
                                    evidence_notes=[
                                        f"SQL query constructed using dynamic interpolation on line {src_line}",
                                        f"Query executed directly on line {node.lineno} without parameterized query binding",
                                    ],
                                    analysis_sources=["AST"],
                                    code_context=self.extract_context(parsed_file, node.lineno),
                                    data_flow_path=data_flow_path,
                                )
                            )
                            continue

                    # Case B: Query argument is directly inline dynamic expression (f-string, format, %, concatenation)
                    is_inline_unsafe, inline_reason = self._is_unsafe_sql_string_expression(query_arg, parsed_file)
                    if is_inline_unsafe:
                        sink_stmt = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else "execute"
                        data_flow_path = [
                            CodePathNode(
                                step_number=1,
                                file_path=parsed_file.relative_path,
                                line_number=node.lineno,
                                function_name=enclosing_func,
                                statement=sink_stmt,
                                node_type="sink",
                                description=f"Direct inline dynamic SQL string execution: {inline_reason}",
                            )
                        ]

                        findings.append(
                            FindingCreate(
                                scan_id=scan_id,
                                title=self.title,
                                cwe_id=self.cwe_id,
                                file_path=parsed_file.relative_path,
                                line_number=node.lineno,
                                function_name=enclosing_func,
                                severity=self.severity,
                                confidence=self.default_confidence,
                                reachability="reachable",
                                exposure="internal",
                                remediation_priority="P1",
                                source_description="Inline dynamically formatted SQL expression",
                                sink_description=f"Database execution call {method_name}()",
                                evidence_notes=[
                                    f"Direct execution of dynamically formatted SQL string: {inline_reason}",
                                ],
                                analysis_sources=["AST"],
                                code_context=self.extract_context(parsed_file, node.lineno),
                                data_flow_path=data_flow_path,
                            )
                        )

        return findings

    def _is_unsafe_sql_string_expression(self, node: ast.AST, parsed_file: ParsedFile) -> Tuple[bool, str]:
        """
        Determines if an expression represents a dynamic SQL construction.
        Returns (is_unsafe, reason).
        """
        # 1. f-string: ast.JoinedStr
        if isinstance(node, ast.JoinedStr):
            # Check if it has interpolated formatted values
            has_formatted_value = any(isinstance(v, ast.FormattedValue) for v in node.values)
            if has_formatted_value and self._string_contains_sql_keyword(node):
                return True, "f-string interpolation with SQL keywords"

        # 2. String % formatting: ast.BinOp(op=ast.Mod)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if self._string_contains_sql_keyword(node.left):
                return True, "% format string substitution with SQL keywords"

        # 3. String concatenation: ast.BinOp(op=ast.Add)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if (self._string_contains_sql_keyword(node.left) or self._string_contains_sql_keyword(node.right)):
                # If neither left nor right is a constant, or at least one is dynamic
                if not (self.is_constant_value(node.left) and self.is_constant_value(node.right)):
                    return True, "String concatenation (+) into SQL query string"

        # 4. .format(...) method call
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if self._string_contains_sql_keyword(node.func.value):
                return True, ".format() string method substitution with SQL keywords"

        return False, ""

    def _string_contains_sql_keyword(self, node: ast.AST) -> bool:
        """Checks if a string literal or joined string contains common SQL command keywords."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text_lower = node.value.lower()
            return any(kw in text_lower for kw in SQL_KEYWORDS)
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    if any(kw in part.value.lower() for kw in SQL_KEYWORDS):
                        return True
        return False

    @staticmethod
    def _get_call_method_name(call_node: ast.Call) -> str:
        """Extracts the attribute or function name from a Call node."""
        if isinstance(call_node.func, ast.Attribute):
            return call_node.func.attr
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        return ""
