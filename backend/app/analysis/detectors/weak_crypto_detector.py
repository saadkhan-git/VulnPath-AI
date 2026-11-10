"""Broken or Risky Cryptographic Algorithms (CWE-327) AST detector."""

import ast
from typing import List, Optional, Set, Tuple

from backend.app.analysis.base import BaseDetector
from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile
from backend.app.schemas.finding import CodePathNode, FindingCreate

WEAK_HASH_ALGORITHMS: Set[str] = {"md5", "sha1"}
WEAK_CIPHERS: Set[str] = {"DES", "ARC4", "Blowfish"}


class WeakCryptographyDetector(BaseDetector):
    """
    Detects use of broken or risky cryptographic algorithms (CWE-327).
    Flags MD5, SHA-1, DES, and ARC4 usage unless usedforsecurity=False is set.
    """

    name = "WeakCryptographyDetector"
    cwe_id = "CWE-327"
    title = "Use of a Broken or Risky Cryptographic Algorithm"
    severity = SeverityLevel.LOW
    default_confidence = 0.95

    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        if not parsed_file.ast_tree:
            return []

        findings: List[FindingCreate] = []

        for node in ast.walk(parsed_file.ast_tree):
            if isinstance(node, ast.Call):
                func_id, mod_id = self._get_call_identity(node)
                enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)

                # Check hashlib.md5 or hashlib.sha1
                if mod_id == "hashlib" and func_id in WEAK_HASH_ALGORITHMS:
                    # Check if usedforsecurity=False is passed
                    used_for_security = self._get_keyword_arg(node, "usedforsecurity")
                    if used_for_security and isinstance(used_for_security, ast.Constant) and used_for_security.value is False:
                        continue  # Explicitly marked as not for security purposes

                    stmt_text = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else f"hashlib.{func_id}"
                    findings.append(
                        FindingCreate(
                            scan_id=scan_id,
                            title=f"Weak Cryptographic Hash ({func_id.upper()})",
                            cwe_id=self.cwe_id,
                            file_path=parsed_file.relative_path,
                            line_number=node.lineno,
                            function_name=enclosing_func,
                            severity=self.severity,
                            confidence=self.default_confidence,
                            reachability="reachable",
                            exposure="internal",
                            remediation_priority="P4",
                            source_description=f"hashlib.{func_id}() invocation",
                            sink_description="Cryptographic hashing",
                            evidence_notes=[
                                f"{func_id.upper()} is cryptographically broken and vulnerable to collision attacks. Use SHA-256 or SHA-3.",
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
                                    description=f"Broken hashing function hashlib.{func_id}() called",
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
