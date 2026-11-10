"""Core analysis engine coordinating parsing, detectors, and finding deduplication."""

from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from backend.app.analysis.adapters.bandit_adapter import BanditAdapter, bandit_adapter
from backend.app.analysis.adapters.yaml_rules_adapter import YamlRulesEngine, yaml_rules_engine
from backend.app.analysis.base import BaseDetector
from backend.app.analysis.detectors.command_injection_detector import CommandInjectionDetector
from backend.app.analysis.detectors.deserialization_detector import InsecureDeserializationDetector
from backend.app.analysis.detectors.hardcoded_secret_detector import HardcodedSecretDetector
from backend.app.analysis.detectors.path_traversal_detector import PathTraversalDetector
from backend.app.analysis.detectors.sqli_detector import SqlInjectionDetector
from backend.app.analysis.detectors.weak_crypto_detector import WeakCryptographyDetector
from backend.app.core.constants import SeverityLevel
from backend.app.ingestion.scanner_target import TargetFile
from backend.app.parsing.ast_parser import ParsedFile, PythonAstParser
from backend.app.schemas.finding import FindingCreate
from backend.app.schemas.scan import ScanSummary


class CoreAnalysisEngine:
    """
    Coordinates AST parsing and executes registered vulnerability detectors across source targets.
    Enforces deduplication, evidence aggregation, and security posture scoring.
    """

    def __init__(
        self,
        detectors: Optional[List[BaseDetector]] = None,
        bandit: Optional[BanditAdapter] = None,
        rules_engine: Optional[YamlRulesEngine] = None,
    ):
        self.detectors: List[BaseDetector] = detectors or [
            SqlInjectionDetector(),
            CommandInjectionDetector(),
            PathTraversalDetector(),
            HardcodedSecretDetector(),
            InsecureDeserializationDetector(),
            WeakCryptographyDetector(),
        ]
        self.bandit = bandit or bandit_adapter
        self.rules_engine = rules_engine or yaml_rules_engine

    def analyze_source_code(
        self,
        source_code: str,
        relative_path: str = "source.py",
        scan_id: str = "inline_scan",
        enable_yaml_rules: bool = True,
    ) -> List[FindingCreate]:
        """Convenience method to scan a string of code directly."""
        parsed_file = PythonAstParser.parse_source(source_code, relative_path=relative_path)
        raw_findings: List[FindingCreate] = []

        if parsed_file.ast_tree:
            for detector in self.detectors:
                raw_findings.extend(detector.run(parsed_file, scan_id=scan_id))

            if enable_yaml_rules and self.rules_engine:
                raw_findings.extend(self.rules_engine.scan_parsed_file(parsed_file, scan_id=scan_id))

        return self.deduplicate_findings(raw_findings)

    def analyze_targets(
        self,
        target_files: List[TargetFile],
        scan_id: str,
        enable_bandit: bool = False,
        enable_yaml_rules: bool = True,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        check_cancelled: Optional[Callable[[], bool]] = None,
        base_dir: Optional[Path] = None,
    ) -> Tuple[List[FindingCreate], ScanSummary]:
        """
        Sequentially analyzes discovered target files, checking for cancellation between files.
        Optionally executes Bandit static scanning across targets.
        """
        all_findings: List[FindingCreate] = []
        total_files = len(target_files)

        for idx, target in enumerate(target_files):
            # Check for cancellation between files
            if check_cancelled and check_cancelled():
                break

            if progress_callback:
                progress_callback(idx + 1, total_files, target.relative_path)

            parsed_file = PythonAstParser.parse_file(target)
            if parsed_file.ast_tree:
                # 1. AST native detectors
                for detector in self.detectors:
                    findings = detector.run(parsed_file, scan_id=scan_id)
                    all_findings.extend(findings)

                # 2. YAML custom rules
                if enable_yaml_rules and self.rules_engine:
                    yaml_findings = self.rules_engine.scan_parsed_file(parsed_file, scan_id=scan_id)
                    all_findings.extend(yaml_findings)

        # 3. Optional Bandit integration
        if enable_bandit and self.bandit.is_available() and target_files:
            # Run bandit across the base directory or individual files
            scan_root = base_dir if base_dir else target_files[0].absolute_path.parent
            bandit_findings = self.bandit.scan_path(scan_root, scan_id=scan_id, base_dir=scan_root)
            all_findings.extend(bandit_findings)

        deduplicated = self.deduplicate_findings(all_findings)
        summary = self.calculate_summary(deduplicated)
        return deduplicated, summary

    @staticmethod
    def deduplicate_findings(findings: List[FindingCreate]) -> List[FindingCreate]:
        """
        Deduplicates findings by (file_path, line_number, cwe_id).
        Preserves highest confidence and merges evidence notes and sources.
        """
        dedup_map: Dict[Tuple[str, int, str], FindingCreate] = {}

        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.cwe_id)
            if key not in dedup_map:
                dedup_map[key] = finding
            else:
                existing = dedup_map[key]
                # Merge evidence notes
                for note in finding.evidence_notes:
                    if note not in existing.evidence_notes:
                        existing.evidence_notes.append(note)
                # Merge analysis sources
                for source in finding.analysis_sources:
                    if source not in existing.analysis_sources:
                        existing.analysis_sources.append(source)
                # Preserve highest confidence
                if finding.confidence > existing.confidence:
                    existing.confidence = finding.confidence
                # Prefer fuller data flow path if available
                if len(finding.data_flow_path) > len(existing.data_flow_path):
                    existing.data_flow_path = finding.data_flow_path

        return list(dedup_map.values())

    @staticmethod
    def calculate_summary(findings: List[FindingCreate]) -> ScanSummary:
        """
        Aggregates severity counts, computes the deterministic security score,
        and generates the CWE distribution.
        """
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        cwe_counter = Counter()

        for f in findings:
            cwe_counter[f.cwe_id] += 1
            if f.severity == SeverityLevel.CRITICAL:
                critical += 1
            elif f.severity == SeverityLevel.HIGH:
                high += 1
            elif f.severity == SeverityLevel.MEDIUM:
                medium += 1
            elif f.severity == SeverityLevel.LOW:
                low += 1
            elif f.severity == SeverityLevel.INFO:
                info += 1

        total = len(findings)

        # Deterministic severity-weighted score: 100 - (25*crit + 12*high + 5*med + 1*low)
        penalty = (critical * 25.0) + (high * 12.0) + (medium * 5.0) + (low * 1.0)
        score = max(0.0, round(100.0 - penalty, 1))

        return ScanSummary(
            total_findings=total,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            security_score=score,
            cwe_distribution=dict(cwe_counter),
        )


core_engine = CoreAnalysisEngine()
