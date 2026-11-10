"""Report generation service for SARIF 2.1.0, JSON, and Markdown formats."""

from datetime import datetime
import json
from typing import Any, Dict

from backend.app.core.constants import PRODUCT_NAME, PRODUCT_VERSION, SeverityLevel
from backend.app.schemas.scan import ScanRead


class ExportService:
    """Generates standardized security scan reports."""

    @staticmethod
    def to_json(scan: ScanRead) -> str:
        """Returns JSON representation of scan details and findings."""
        return scan.model_dump_json(indent=2)

    @classmethod
    def to_sarif(cls, scan: ScanRead) -> Dict[str, Any]:
        """
        Exports findings adhering strictly to OASIS SARIF v2.1.0 standard schema.
        Includes rules catalog, threadFlows for data-flow paths, and location regions.
        """
        rules_map: Dict[str, Dict[str, Any]] = {}
        results = []

        if scan.findings:
            for f in scan.findings:
                # Register rule definition if not already added
                if f.cwe_id not in rules_map:
                    rules_map[f.cwe_id] = {
                        "id": f.cwe_id,
                        "name": f.title,
                        "shortDescription": {"text": f.title},
                        "defaultConfiguration": {
                            "level": "error" if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "warning"
                        },
                    }

                # Map severity to SARIF level
                level = "error" if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "warning" if f.severity == SeverityLevel.MEDIUM else "note"

                # ThreadFlow steps for data-flow path
                thread_flow_locations = []
                for node in f.data_flow_path:
                    thread_flow_locations.append(
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": node.file_path},
                                    "region": {"startLine": node.line_number},
                                },
                                "message": {"text": f"[{node.node_type.upper()}] {node.description or node.statement}"},
                            }
                        }
                    )

                result_entry: Dict[str, Any] = {
                    "ruleId": f.cwe_id,
                    "level": level,
                    "message": {"text": f"{f.title}: {f.source_description or ''} -> {f.sink_description or ''}".strip()},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file_path},
                                "region": {
                                    "startLine": f.line_number,
                                    "endLine": f.end_line_number or f.line_number,
                                },
                            }
                        }
                    ],
                }

                if thread_flow_locations:
                    result_entry["codeFlows"] = [
                        {
                            "threadFlows": [
                                {
                                    "locations": thread_flow_locations
                                }
                            ]
                        }
                    ]

                results.append(result_entry)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": PRODUCT_NAME,
                            "semanticVersion": PRODUCT_VERSION,
                            "informationUri": "https://github.com/saadkhan-git",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    @staticmethod
    def to_markdown(scan: ScanRead) -> str:
        """Renders an executive Markdown security audit report."""
        summary = scan.summary
        md_lines = [
            f"# {PRODUCT_NAME} Security Audit Report",
            f"**Project:** {scan.project_name}  ",
            f"**Scan ID:** `{scan.scan_id}`  ",
            f"**Scan Date:** {scan.created_at}  ",
            f"**Target Type:** `{scan.target_type}`  ",
            f"**Security Score:** **{summary.security_score}/100**  ",
            "",
            "## 1. Executive Summary",
            "",
            "| Severity | Count |",
            "| :--- | :--- |",
            f"| **Critical** | {summary.critical_count} |",
            f"| **High** | {summary.high_count} |",
            f"| **Medium** | {summary.medium_count} |",
            f"| **Low** | {summary.low_count} |",
            f"| **Info** | {summary.info_count} |",
            f"| **Total Findings** | **{summary.total_findings}** |",
            "",
            "## 2. Weakness Distribution (CWE)",
            "",
        ]

        if summary.cwe_distribution:
            for cwe, count in summary.cwe_distribution.items():
                md_lines.append(f"- **{cwe}**: {count} occurrence(s)")
        else:
            md_lines.append("*No vulnerabilities detected.*")

        md_lines.extend(["", "## 3. Detailed Findings", ""])

        if not scan.findings:
            md_lines.append("*No security findings reported for this target.*")
        else:
            for idx, f in enumerate(scan.findings, 1):
                md_lines.extend([
                    f"### {idx}. [{f.severity.upper()}] {f.title} ({f.cwe_id})",
                    f"- **File:** `{f.file_path}:{f.line_number}`",
                    f"- **Confidence:** {int(f.confidence * 100)}%",
                    f"- **Priority:** {f.remediation_priority}",
                    f"- **Source:** {f.source_description or 'N/A'}",
                    f"- **Sink:** {f.sink_description or 'N/A'}",
                    "",
                    "#### Evidence & Reasoning",
                ])
                for note in f.evidence_notes:
                    md_lines.append(f"- {note}")

                if f.code_context:
                    md_lines.extend([
                        "",
                        "```python",
                        f.code_context,
                        "```",
                    ])

                if f.data_flow_path:
                    md_lines.extend(["", "#### Data Flow Path"])
                    for step in f.data_flow_path:
                        md_lines.append(
                            f"{step.step_number}. `[{step.node_type.upper()}]` `{step.file_path}:{step.line_number}` — `{step.statement}` ({step.description or ''})"
                        )
                md_lines.append("")

        md_lines.extend([
            "---",
            f"*Generated locally by {PRODUCT_NAME} v{PRODUCT_VERSION}. Mohammad Saad Khan.*",
        ])
        return "\n".join(md_lines)


export_service = ExportService()
