"""Insecure Deserialization (CWE-502) AST detector."""

import ast
from typing import List, Optional, Set, Tuple

from backend.app.analysis.base import BaseDetector
from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile
from backend.app.schemas.finding import CodePathNode, FindingCreate

PICKLE_MODULES: Set[str] = {"pickle", "_pickle", "cPickle"}
DESERIALIZE_FUNCS: Set[str] = {"loads", "load"}


class InsecureDeserializationDetector(BaseDetector):
    """
    Detects deserialization of untrusted data (CWE-502).
    Flags pickle.loads(), marshal.loads(), and unsafe yaml.load() calls.
    """

    name = "InsecureDeserializationDetector"
    cwe_id = "CWE-502"
    title = "Insecure Deserialization of Untrusted Data"
    severity = SeverityLevel.CRITICAL
    default_confidence = 0.95

    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        if not parsed_file.ast_tree:
            return []

        findings: List[FindingCreate] = []

        for node in ast.walk(parsed_file.ast_tree):
            if isinstance(node, ast.Call):
                func_id, mod_id = self._get_call_identity(node)
                enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)

                # Check 1: pickle.loads / pickle.load
                if mod_id in PICKLE_MODULES and func_id in DESERIALIZE_FUNCS:
                    stmt_text = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else f"{mod_id}.{func_id}"
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
                            source_description="Deserialized serialized data payload",
                            sink_description=f"{mod_id}.{func_id}() deserialization sink",
                            evidence_notes=[
                                f"Direct invocation of {mod_id}.{func_id}() allows arbitrary object instantiation and RCE.",
                            ],
                            analysis_sources=["AST"],
                            code_context=self.extract_context(parsed_file, node.lineno),
                            data_flow_path=[
                                CodePathNode(
                                    step_number=1,
                                    file_path=parsed_file.relative_path,
                                    line_number=node.lineno,
                                    function_name=enclosing_func,
                                    statement=stmt_text,
                                    node_type="sink",
                                    description=f"Dangerous deserializer {mod_id}.{func_id}() invoked",
                                )
                            ],
                        )
                    )

                # Check 2: yaml.load without SafeLoader
                elif mod_id == "yaml" and func_id == "load":
                    loader_kw = self._get_keyword_arg(node, "Loader")
                    is_safe_loader = False
                    if loader_kw and isinstance(loader_kw, ast.Attribute):
                        if loader_kw.attr in ("SafeLoader", "CSafeLoader"):
                            is_safe_loader = True

                    if not is_safe_loader:
                        stmt_text = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else "yaml.load"
                        findings.append(
                            FindingCreate(
                                scan_id=scan_id,
                                title="Unsafe YAML Deserialization",
                                cwe_id=self.cwe_id,
                                file_path=parsed_file.relative_path,
                                line_number=node.lineno,
                                function_name=enclosing_func,
                                severity=SeverityLevel.HIGH,
                                confidence=0.92,
                                reachability="reachable",
                                exposure="internal",
                                remediation_priority="P1",
                                source_description="YAML stream data",
                                sink_description="yaml.load() without SafeLoader",
                                evidence_notes=[
                                    "yaml.load() invoked without SafeLoader or CSafeLoader. Use yaml.safe_load() instead.",
                                ],
                                analysis_sources=["AST"],
                                code_context=self.extract_context(parsed_file, node.lineno),
                                data_flow_path=[
                                    CodePathNode(
                                        step_number=1,
                                        file_path=parsed_file.relative_path,
                                        line_number=node.lineno,
                                        function_name=enclosing_func,
                                        statement=stmt_text,
                                        node_type="sink",
                                        description="yaml.load() executed with default unsafe loader",
                                    )
                                ],
                            )
                        )

        return findings

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

    @staticmethod
    def _get_keyword_arg(call_node: ast.Call, keyword_name: str) -> Optional[ast.AST]:
        for kw in call_node.keywords:
            if kw.arg == keyword_name:
                return kw.value
        return None
