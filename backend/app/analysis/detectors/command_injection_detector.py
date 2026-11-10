"""OS Command Injection (CWE-78) AST detector."""

import ast
from typing import Dict, List, Optional, Set, Tuple

from backend.app.analysis.base import BaseDetector
from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile
from backend.app.schemas.finding import CodePathNode, FindingCreate

SUBPROCESS_FUNCS: Set[str] = {
    "run", "Popen", "call", "check_call", "check_output"
}

OS_COMMAND_FUNCS: Set[str] = {
    "system", "popen"
}


class CommandInjectionDetector(BaseDetector):
    """
    Detects improper neutralization of special elements in OS Commands (CWE-78).
    Flags os.system, os.popen, and subprocess calls with shell=True and dynamic input.
    """

    name = "CommandInjectionDetector"
    cwe_id = "CWE-78"
    title = "Potential OS Command Injection"
    severity = SeverityLevel.CRITICAL
    default_confidence = 0.95

    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        if not parsed_file.ast_tree:
            return []

        findings: List[FindingCreate] = []

        # Scope tracker: map (func_name, var_name) -> (ast.AST, str, int, str)
        dynamic_cmd_vars: Dict[Tuple[Optional[str], str], Tuple[ast.AST, str, int, str]] = {}

        for func_node in ast.walk(parsed_file.ast_tree):
            if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = func_node.name
                for stmt in func_node.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        var_name = stmt.targets[0].id
                        is_dyn, reason = self._is_dynamic_expression(stmt.value)
                        if is_dyn:
                            raw_stmt = parsed_file.lines[stmt.lineno - 1].strip() if stmt.lineno <= len(parsed_file.lines) else var_name
                            dynamic_cmd_vars[(func_name, var_name)] = (stmt.value, raw_stmt, stmt.lineno, reason)

        for node in ast.walk(parsed_file.ast_tree):
            if isinstance(node, ast.Call):
                func_id, mod_id = self._get_call_identity(node)
                enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)

                # Check 1: os.system(...) or os.popen(...)
                if mod_id == "os" and func_id in OS_COMMAND_FUNCS:
                    if node.args:
                        arg0 = node.args[0]
                        # If argument is not a constant
                        if not self.is_constant_value(arg0):
                            findings.append(
                                self._create_finding(
                                    scan_id=scan_id,
                                    parsed_file=parsed_file,
                                    call_node=node,
                                    enclosing_func=enclosing_func,
                                    sink_desc=f"os.{func_id}() execution",
                                    reason=f"Direct shell command execution via os.{func_id}() with dynamic input",
                                    dynamic_cmd_vars=dynamic_cmd_vars,
                                    arg_node=arg0,
                                )
                            )
                            continue

                # Check 2: subprocess.run/Popen/call(...) with shell=True
                if (mod_id == "subprocess" and func_id in SUBPROCESS_FUNCS) or (func_id in SUBPROCESS_FUNCS):
                    shell_kw = self._get_keyword_arg(node, "shell")
                    if shell_kw and self._is_truthy_node(shell_kw):
                        if node.args:
                            cmd_arg = node.args[0]
                            # If shell=True and cmd_arg is not a verified safe static list
                            if not self._is_safe_constant_list(cmd_arg):
                                findings.append(
                                    self._create_finding(
                                        scan_id=scan_id,
                                        parsed_file=parsed_file,
                                        call_node=node,
                                        enclosing_func=enclosing_func,
                                        sink_desc=f"subprocess.{func_id}(..., shell=True)",
                                        reason=f"Subprocess invoked with shell=True and dynamic command",
                                        dynamic_cmd_vars=dynamic_cmd_vars,
                                        arg_node=cmd_arg,
                                    )
                                )

        return findings

    def _create_finding(
        self,
        scan_id: str,
        parsed_file: ParsedFile,
        call_node: ast.Call,
        enclosing_func: Optional[str],
        sink_desc: str,
        reason: str,
        dynamic_cmd_vars: Dict[Tuple[Optional[str], str], Tuple[ast.AST, str, int, str]],
        arg_node: ast.AST,
    ) -> FindingCreate:
        sink_stmt = parsed_file.lines[call_node.lineno - 1].strip() if call_node.lineno <= len(parsed_file.lines) else "command_execution"
        data_flow_path: List[CodePathNode] = []

        # If argument was a variable defined earlier
        if isinstance(arg_node, ast.Name):
            var_key = (enclosing_func, arg_node.id)
            if var_key in dynamic_cmd_vars:
                src_node, src_stmt, src_line, var_reason = dynamic_cmd_vars[var_key]
                data_flow_path.append(
                    CodePathNode(
                        step_number=1,
                        file_path=parsed_file.relative_path,
                        line_number=src_line,
                        function_name=enclosing_func,
                        statement=src_stmt,
                        node_type="source",
                        description=f"Command string formatted dynamically: {var_reason}",
                    )
                )

        data_flow_path.append(
            CodePathNode(
                step_number=len(data_flow_path) + 1,
                file_path=parsed_file.relative_path,
                line_number=call_node.lineno,
                function_name=enclosing_func,
                statement=sink_stmt,
                node_type="sink",
                description=f"Execution sink reached: {sink_desc}",
            )
        )

        return FindingCreate(
            scan_id=scan_id,
            title=self.title,
            cwe_id=self.cwe_id,
            file_path=parsed_file.relative_path,
            line_number=call_node.lineno,
            function_name=enclosing_func,
            severity=self.severity,
            confidence=self.default_confidence,
            reachability="reachable",
            exposure="internal",
            remediation_priority="P1",
            source_description="Dynamic command string with potential shell metacharacters",
            sink_description=sink_desc,
            evidence_notes=[
                reason,
                "Arbitrary command execution possible if input contains shell metacharacters (;, &, |)",
            ],
            analysis_sources=["AST"],
            code_context=self.extract_context(parsed_file, call_node.lineno),
            data_flow_path=data_flow_path,
        )

    def _is_dynamic_expression(self, node: ast.AST) -> Tuple[bool, str]:
        """Checks if an expression is non-constant (f-string, formatting, concatenation)."""
        if isinstance(node, ast.JoinedStr):
            return True, "f-string command interpolation"
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True, "concatenation or % format operator"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True, ".format() command interpolation"
        return False, ""

    @staticmethod
    def _is_safe_constant_list(node: ast.AST) -> bool:
        """Checks if node is a list/tuple composed purely of constant literals."""
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(isinstance(elt, ast.Constant) for elt in node.elts)
        return False

    @staticmethod
    def _get_call_identity(call_node: ast.Call) -> Tuple[str, Optional[str]]:
        """Returns (function_name, module_name) if available."""
        if isinstance(call_node.func, ast.Attribute):
            func_name = call_node.func.attr
            if isinstance(call_node.func.value, ast.Name):
                return func_name, call_node.func.value.id
            return func_name, None
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id, None
        return "", None

    @staticmethod
    def _get_keyword_arg(call_node: ast.Call, keyword_name: str) -> Optional[ast.AST]:
        """Retrieves a specific keyword argument value from a Call node."""
        for kw in call_node.keywords:
            if kw.arg == keyword_name:
                return kw.value
        return None

    @staticmethod
    def _is_truthy_node(node: ast.AST) -> bool:
        """Evaluates whether an AST node represents a boolean truthy value."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return False
