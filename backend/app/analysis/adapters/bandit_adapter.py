"""Bandit static security analyzer integration and finding normalizer."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

from backend.app.core.constants import SeverityLevel
from backend.app.parsing.ast_parser import PythonAstParser
from backend.app.schemas.finding import CodePathNode, FindingCreate

# Mapping Bandit Test IDs to MITRE CWEs
BANDIT_TO_CWE: Dict[str, str] = {
    # SQL Injection
    "B608": "CWE-89",
    # OS Command Injection
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B606": "CWE-78",
    "B607": "CWE-78",
    # Hardcoded Secrets
    "B105": "CWE-798",
    "B106": "CWE-798",
    "B107": "CWE-798",
    # Cryptographic issues
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B324": "CWE-327",
    # Insecure Deserialization
    "B301": "CWE-502",
    "B403": "CWE-502",
    # Path Traversal & File access
    "B108": "CWE-22",
    # Code Execution
    "B102": "CWE-94",
    "B307": "CWE-94",
}

SEVERITY_MAP: Dict[str, SeverityLevel] = {
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
}


class BanditAdapter:
    """Safely executes Bandit static analysis on source targets and normalizes findings."""

    def __init__(self, bandit_executable: Optional[str] = None):
        self.bandit_executable = bandit_executable or sys.executable

    def is_available(self) -> bool:
        """Check if Bandit is installed in current Python environment."""
        try:
            import bandit  # noqa: F401
            return True
        except ImportError:
            return False

    def scan_path(self, target_path: Path, scan_id: str, base_dir: Optional[Path] = None) -> List[FindingCreate]:
        """
        Runs Bandit in JSON output mode and converts results to FindingCreate instances.
        """
        if not self.is_available() or not target_path.exists():
            return []

        resolved_target = target_path.resolve()
        resolved_base = base_dir.resolve() if base_dir else resolved_target.parent

        # Execute Bandit via Python module to ensure correct virtualenv environment
        cmd = [
            self.bandit_executable,
            "-m",
            "bandit",
            "-r" if resolved_target.is_dir() else "",
            str(resolved_target),
            "-f",
            "json",
            "-q",
        ]
        cmd = [c for c in cmd if c]  # Remove empty strings

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            # Bandit returns exit code 1 if issues found, 0 if clean
            output_str = proc.stdout.strip()
            if not output_str:
                return []

            data = json.loads(output_str)
            return self._normalize_bandit_results(data.get("results", []), scan_id, resolved_base)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            return []

    def _normalize_bandit_results(
        self,
        bandit_results: List[Dict],
        scan_id: str,
        base_dir: Path,
    ) -> List[FindingCreate]:
        normalized: List[FindingCreate] = []

        for item in bandit_results:
            test_id = item.get("test_id", "")
            cwe_id = BANDIT_TO_CWE.get(test_id, "CWE-200")
            raw_severity = item.get("issue_severity", "MEDIUM").upper()
            severity = SEVERITY_MAP.get(raw_severity, SeverityLevel.MEDIUM)

            confidence_str = item.get("issue_confidence", "MEDIUM").upper()
            confidence = 0.90 if confidence_str == "HIGH" else 0.75 if confidence_str == "MEDIUM" else 0.60

            filename = item.get("filename", "")
            try:
                rel_file = Path(filename).resolve().relative_to(base_dir).as_posix()
            except ValueError:
                rel_file = Path(filename).name

            line_number = item.get("line_number", 1)
            line_range = item.get("line_range", [line_number])
            end_line = line_range[-1] if line_range else line_number

            code_text = item.get("code", "").strip()

            path_node = CodePathNode(
                step_number=1,
                file_path=rel_file,
                line_number=line_number,
                statement=code_text.splitlines()[0] if code_text else "bandit_finding",
                node_type="sink",
                description=item.get("issue_text", "Bandit flagged static security pattern"),
            )

            finding = FindingCreate(
                scan_id=scan_id,
                title=f"Bandit [{test_id}]: {item.get('test_name', 'Security Issue')}",
                cwe_id=cwe_id,
                file_path=rel_file,
                line_number=line_number,
                end_line_number=end_line,
                severity=severity,
                confidence=confidence,
                reachability="unknown",
                exposure="internal",
                remediation_priority="P2" if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "P3",
                source_description=f"Bandit heuristic match ({test_id})",
                sink_description=item.get("issue_text", ""),
                evidence_notes=[
                    f"Identified by Bandit rule {test_id} ({item.get('test_name', '')})",
                    item.get("issue_text", ""),
                    f"More info: {item.get('more_info', '')}",
                ],
                analysis_sources=["Bandit"],
                code_context=code_text,
                data_flow_path=[path_node],
            )
            normalized.append(finding)

        return normalized


bandit_adapter = BanditAdapter()
