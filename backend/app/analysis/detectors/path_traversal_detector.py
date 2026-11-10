"""Path Traversal (CWE-22) AST detector."""

import ast
from typing import Dict, List, Optional, Set, Tuple

from backend.app.analysis.base import BaseDetector
from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile
from backend.app.schemas.finding import CodePathNode, FindingCreate

FILE_OPEN_FUNCS: Set[str] = {"open"}
PATH_JOIN_FUNCS: Set[str] = {"join"}


class PathTraversalDetector(BaseDetector):
    """
    Detects improper limitation of a pathname to a restricted directory (CWE-22).
    Flags unvalidated path joining and opening with user input lacking boundary containment checks.
    """

    name = "PathTraversalDetector"
    cwe_id = "CWE-22"
    title = "Potential Path Traversal"
    severity = SeverityLevel.MEDIUM
    default_confidence = 0.88

    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        if not parsed_file.ast_tree:
            return []

        findings: List[FindingCreate] = []

        # Track which functions contain safety verification patterns:
        # e.g., calling .relative_to(...), os.path.commonpath, or os.path.commonprefix
        safe_functions = self._identify_functions_with_path_containment_checks(parsed_file.ast_tree)

        # Track variable joins: (func_name, var_name) -> (ast.AST, str, int)
        joined_paths: Dict[Tuple[Optional[str], str], Tuple[ast.AST, str, int]] = {}

        for func_node in ast.walk(parsed_file.ast_tree):
            if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = func_node.name
                for stmt in func_node.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        var_name = stmt.targets[0].id
                        if self._is_path_join_call(stmt.value):
                            raw_stmt = parsed_file.lines[stmt.lineno - 1].strip() if stmt.lineno <= len(parsed_file.lines) else var_name
                            joined_paths[(func_name, var_name)] = (stmt.value, raw_stmt, stmt.lineno)

        # Inspect open() calls
        for node in ast.walk(parsed_file.ast_tree):
            if isinstance(node, ast.Call):
                func_id, mod_id = self._get_call_identity(node)
                enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)

                # Skip if enclosing function implements path containment verification (.relative_to, etc.)
                if enclosing_func and enclosing_func in safe_functions:
                    continue

                if func_id in FILE_OPEN_FUNCS and (mod_id is None or mod_id in ("io", "builtins")):
                    if node.args:
                        path_arg = node.args[0]

                        # If open argument is a constant string, it's safe (e.g. open("data.json"))
                        if self.is_constant_value(path_arg):
                            continue

                        # Case 1: Argument was assigned via os.path.join earlier without validation
                        if isinstance(path_arg, ast.Name):
                            var_key = (enclosing_func, path_arg.id)
                            if var_key in joined_paths:
                                src_node, src_stmt, src_line = joined_paths[var_key]
                                sink_stmt = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else "open()"

                                data_flow_path = [
                                    CodePathNode(
                                        step_number=1,
                                        file_path=parsed_file.relative_path,
                                        line_number=src_line,
                                        function_name=enclosing_func,
                                        statement=src_stmt,
                                        node_type="source",
                                        description="Path constructed via join() without traversal neutralization",
                                    ),
                                    CodePathNode(
                                        step_number=2,
                                        file_path=parsed_file.relative_path,
                                        line_number=node.lineno,
                                        function_name=enclosing_func,
                                        statement=sink_stmt,
                                        node_type="sink",
                                        description="Unvalidated path opened directly",
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
                                        remediation_priority="P2",
                                        source_description=f"Path variable '{path_arg.id}' joined from unvalidated inputs",
                                        sink_description="File open() call",
                                        evidence_notes=[
                                            f"Path constructed via join on line {src_line}",
                                            f"File opened directly on line {node.lineno} without relative_to boundary check",
                                        ],
                                        analysis_sources=["AST"],
                                        code_context=self.extract_context(parsed_file, node.lineno),
                                        data_flow_path=data_flow_path,
                                    )
                                )
                                continue

                        # Case 2: Inline join inside open(os.path.join(...))
                        if self._is_path_join_call(path_arg):
                            sink_stmt = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else "open()"
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
                                    remediation_priority="P2",
                                    source_description="Inline path join expression",
                                    sink_description="File open() call",
                                    evidence_notes=[
                                        "File opened with inline joined path without directory containment check",
                                    ],
                                    analysis_sources=["AST"],
                                    code_context=self.extract_context(parsed_file, node.lineno),
                                    data_flow_path=[
                                        CodePathNode(
                                            step_number=1,
                                            file_path=parsed_file.relative_path,
                                            line_number=node.lineno,
                                            function_name=enclosing_func,
                                            statement=sink_stmt,
                                            node_type="sink",
                                            description="Inline joined path passed to open() without path confinement",
                                        )
                                    ],
                                )
                            )

        return findings

    @staticmethod
    def _identify_functions_with_path_containment_checks(tree: ast.AST) -> Set[str]:
        """Detects functions that call .relative_to(...) or commonpath to enforce path boundaries."""
        safe_funcs: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        # Check for .relative_to(...)
                        if isinstance(sub.func, ast.Attribute) and sub.func.attr == "relative_to":
                            safe_funcs.add(node.name)
                        # Check for os.path.commonpath / commonprefix
                        elif isinstance(sub.func, ast.Attribute) and sub.func.attr in ("commonpath", "commonprefix"):
                            safe_funcs.add(node.name)
        return safe_funcs

    @staticmethod
    def _is_path_join_call(node: ast.AST) -> bool:
        """Determines if a node is an os.path.join(...) call."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                # Matches os.path.join or path.join
                return True
        return False

    @staticmethod
    def _get_call_identity(call_node: ast.Call) -> Tuple[str, Optional[str]]:
        if isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr
            if isinstance(call_node.func.value, ast.Name):
                return func_name, call_node.func.value.id
            return func_name, None
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id, None
        return "", None
