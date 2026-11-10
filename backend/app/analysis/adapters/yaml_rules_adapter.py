"""Custom clean-room YAML security rules engine."""

import ast
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import yaml

from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import ParsedFile, PythonAstParser
from backend.app.schemas.finding import CodePathNode, FindingCreate


@dataclass
class CustomSecurityRule:
    """Represents a validated YAML-defined security rule."""
    rule_id: str
    cwe_id: str
    title: str
    severity: SeverityLevel
    confidence: float
    regex_pattern: Optional[re.Pattern] = None
    function_calls: Optional[List[str]] = None
    description: str = ""
    remediation_hint: str = ""


class YamlRulesEngine:
    """
    Executes custom YAML pattern rules against Python AST and source lines.
    Provides flexible, extensible static analysis without external native dependencies.
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path("rules")
        self.rules: List[CustomSecurityRule] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Discovers and parses all .yaml and .yml files from rules_dir."""
        self.rules.clear()
        if not self.rules_dir.is_dir():
            return

        for rule_file in self.rules_dir.glob("*.y*ml"):
            try:
                content = rule_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                if isinstance(data, dict) and "rules" in data:
                    for r_dict in data["rules"]:
                        parsed_rule = self._parse_rule_dict(r_dict)
                        if parsed_rule:
                            self.rules.append(parsed_rule)
            except Exception:
                continue

    @staticmethod
    def _parse_rule_dict(d: Dict[str, Any]) -> Optional[CustomSecurityRule]:
        try:
            rule_id = d.get("id", "CUSTOM-RULE")
            cwe_id = d.get("cwe", "CWE-200")
            title = d.get("title", rule_id)
            sev_str = d.get("severity", "medium").lower()
            severity = (
                SeverityLevel.CRITICAL if sev_str == "critical"
                else SeverityLevel.HIGH if sev_str == "high"
                else SeverityLevel.LOW if sev_str == "low"
                else SeverityLevel.MEDIUM
            )
            confidence = float(d.get("confidence", 0.85))
            regex_str = d.get("patterns", {}).get("regex")
            regex_pat = re.compile(regex_str) if regex_str else None
            func_calls = d.get("patterns", {}).get("function_calls")

            return CustomSecurityRule(
                rule_id=rule_id,
                cwe_id=cwe_id,
                title=title,
                severity=severity,
                confidence=confidence,
                regex_pattern=regex_pat,
                function_calls=func_calls,
                description=d.get("description", ""),
                remediation_hint=d.get("remediation", ""),
            )
        except Exception:
            return None

    def scan_parsed_file(self, parsed_file: ParsedFile, scan_id: str) -> List[FindingCreate]:
        """Runs all registered YAML security rules against parsed_file."""
        findings: List[FindingCreate] = []

        for rule in self.rules:
            # 1. Regex line-by-line checks
            if rule.regex_pattern:
                for idx, line in enumerate(parsed_file.lines):
                    if rule.regex_pattern.search(line):
                        lineno = idx + 1
                        findings.append(
                            FindingCreate(
                                scan_id=scan_id,
                                title=f"Rule [{rule.rule_id}]: {rule.title}",
                                cwe_id=rule.cwe_id,
                                file_path=parsed_file.relative_path,
                                line_number=lineno,
                                severity=rule.severity,
                                confidence=rule.confidence,
                                reachability="unknown",
                                exposure="internal",
                                remediation_priority="P2",
                                source_description=f"Pattern match for rule {rule.rule_id}",
                                sink_description=rule.description,
                                evidence_notes=[
                                    rule.description,
                                    f"Remediation: {rule.remediation_hint}",
                                ],
                                analysis_sources=["YAML-Rule"],
                                code_context=PythonAstParser.extract_code_context(parsed_file, lineno),
                                data_flow_path=[
                                    CodePathNode(
                                        step_number=1,
                                        file_path=parsed_file.relative_path,
                                        line_number=lineno,
                                        statement=line.strip(),
                                        node_type="sink",
                                        description=rule.description,
                                    )
                                ],
                            )
                        )

            # 2. AST Function call checks
            if rule.function_calls and parsed_file.ast_tree:
                for node in ast.walk(parsed_file.ast_tree):
                    if isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id

                        if func_name in rule.function_calls:
                            lineno = node.lineno
                            line_text = parsed_file.lines[lineno - 1].strip() if lineno <= len(parsed_file.lines) else func_name
                            findings.append(
                                FindingCreate(
                                    scan_id=scan_id,
                                    title=f"Rule [{rule.rule_id}]: {rule.title}",
                                    cwe_id=rule.cwe_id,
                                    file_path=parsed_file.relative_path,
                                    line_number=lineno,
                                    severity=rule.severity,
                                    confidence=rule.confidence,
                                    reachability="reachable",
                                    exposure="internal",
                                    remediation_priority="P2",
                                    source_description=f"Insecure call {func_name}()",
                                    sink_description=rule.description,
                                    evidence_notes=[
                                        f"Prohibited security-sensitive call {func_name}() detected",
                                        f"Remediation: {rule.remediation_hint}",
                                    ],
                                    analysis_sources=["YAML-Rule"],
                                    code_context=PythonAstParser.extract_code_context(parsed_file, lineno),
                                    data_flow_path=[
                                        CodePathNode(
                                            step_number=1,
                                            file_path=parsed_file.relative_path,
                                            line_number=lineno,
                                            statement=line_text,
                                            node_type="sink",
                                            description=rule.description,
                                        )
                                    ],
                                )
                            )

        return findings


yaml_rules_engine = YamlRulesEngine()
