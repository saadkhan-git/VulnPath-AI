"""Hardcoded Secrets and Credentials (CWE-798) AST detector."""

import ast
import re
from typing import List, Set

from backend.app.analysis.base import BaseDetector
from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile
from backend.app.schemas.finding import CodePathNode, FindingCreate

SECRET_VAR_KEYWORDS: Set[str] = {
    "password", "passwd", "secret", "api_key", "apikey", "auth_token",
    "jwt_secret", "access_key", "secret_key", "private_key"
}

AWS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
GENERIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{24,}$")

SAFE_PLACEHOLDERS: Set[str] = {
    "", "test", "dummy", "example", "placeholder", "change_me", "none", "password", "secret", "admin"
}


class HardcodedSecretDetector(BaseDetector):
    """
    Detects use of hard-coded credentials and private cryptographic keys (CWE-798).
    Flags literal secrets assigned to sensitive variable names or matching key patterns.
    """

    name = "HardcodedSecretDetector"
    cwe_id = "CWE-798"
    title = "Hardcoded Sensitive Credential"
    severity = SeverityLevel.HIGH
    default_confidence = 0.90

    def run(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        if not parsed_file.ast_tree:
            return []

        findings: List[FindingCreate] = []

        for node in ast.walk(parsed_file.ast_tree):
            # Case 1: Variable assignments: api_key = "..."
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(kw in var_name for kw in SECRET_VAR_KEYWORDS):
                            # Inspect assigned value
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                val_str = node.value.value
                                if val_str.lower() not in SAFE_PLACEHOLDERS and len(val_str) >= 8:
                                    enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)
                                    stmt_text = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else var_name

                                    # Obfuscate secret in finding record
                                    masked_val = val_str[:4] + "*" * (len(val_str) - 8) + val_str[-4:] if len(val_str) >= 8 else "***"

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
                                            source_description=f"Hardcoded credential in variable '{target.id}'",
                                            sink_description="Committed source code",
                                            evidence_notes=[
                                                f"Variable '{target.id}' assigned literal string matching secret naming pattern",
                                                f"Masked value: {masked_val}",
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
                                                    node_type="source",
                                                    description=f"Sensitive literal credential assigned to {target.id}",
                                                )
                                            ],
                                        )
                                    )

            # Case 2: Direct AWS access key patterns anywhere in literals
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if AWS_KEY_PATTERN.search(node.value):
                    enclosing_func = self.get_enclosing_function_name(parsed_file.ast_tree, node.lineno)
                    stmt_text = parsed_file.lines[node.lineno - 1].strip() if node.lineno <= len(parsed_file.lines) else "secret"
                    findings.append(
                        FindingCreate(
                            scan_id=scan_id,
                            title="Hardcoded AWS Access Key",
                            cwe_id=self.cwe_id,
                            file_path=parsed_file.relative_path,
                            line_number=node.lineno,
                            function_name=enclosing_func,
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.98,
                            reachability="reachable",
                            exposure="internal",
                            remediation_priority="P1",
                            source_description="AWS Access Key pattern (AKIA...)",
                            sink_description="Committed source code",
                            evidence_notes=[
                                "String literal matches valid AWS Access Key format (AKIA followed by 16 alphanumeric characters)",
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
                                    node_type="source",
                                    description="AWS Access Key literal detected",
                                )
                            ],
                        )
                    )

        return findings
