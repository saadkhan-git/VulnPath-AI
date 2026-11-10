"""Tests for Phase 2: Bandit and Custom YAML Rules integrations."""

from pathlib import Path
import pytest

from backend.app.analysis.adapters.bandit_adapter import BanditAdapter, bandit_adapter
from backend.app.analysis.adapters.yaml_rules_adapter import YamlRulesEngine
from backend.app.analysis.engine import CoreAnalysisEngine
from backend.app.core.constants import SeverityLevel
from backend.app.ingestion.scanner_target import TargetFile


def test_bandit_adapter_availability():
    """Verify Bandit adapter detects that Bandit is installed."""
    assert bandit_adapter.is_available() is True


def test_bandit_scan_vulnerable_sample():
    """Verify Bandit scanning runs on SQLi sample and normalizes to CWE-89."""
    sample_file = Path("samples/vulnerable/sql_injection.py")
    findings = bandit_adapter.scan_path(sample_file, scan_id="bandit_test")

    # Bandit should detect either B608 (SQL injection) or mark it
    assert len(findings) >= 1
    # Check normalized properties
    finding = findings[0]
    assert finding.cwe_id in ("CWE-89", "CWE-200")
    assert "Bandit" in finding.analysis_sources
    assert finding.scan_id == "bandit_test"


def test_yaml_rules_engine_loads_rules():
    """Verify YAML rules engine loads custom rules pack."""
    engine = YamlRulesEngine(rules_dir=Path("rules"))
    assert len(engine.rules) >= 3

    rule_ids = {r.rule_id for r in engine.rules}
    assert "VP-SEC-001" in rule_ids  # Insecure tempfile
    assert "VP-SEC-002" in rule_ids  # SSRF
    assert "VP-SEC-003" in rule_ids  # XXE


def test_yaml_rules_detection_ssrf_and_tempfile():
    """Verify custom YAML rules detect SSRF and insecure tempfile."""
    code = """
import requests
import tempfile

def fetch_data(target_url):
    # Triggers VP-SEC-002 (SSRF)
    resp = requests.get(target_url)
    
    # Triggers VP-SEC-001 (Insecure temp file)
    path = tempfile.mktemp()
    return resp.text, path
"""
    engine = CoreAnalysisEngine()
    findings = engine.analyze_source_code(code, "test_yaml.py", enable_yaml_rules=True)

    cwe_set = {f.cwe_id for f in findings}
    assert "CWE-918" in cwe_set  # SSRF
    assert "CWE-377" in cwe_set  # Insecure temp file


def test_fused_analysis_integration(tmp_path: Path):
    """Test full pipeline running AST, YAML, and Bandit on target files."""
    test_file = tmp_path / "vulnerable_app.py"
    test_file.write_text(
        """
import sqlite3
import tempfile

def query_and_store(user_id):
    c = sqlite3.connect(":memory:").cursor()
    c.execute(f"SELECT * FROM items WHERE id = '{user_id}'")
    tmp = tempfile.mktemp()
    return tmp
"""
    )

    targets = [TargetFile("vulnerable_app.py", test_file, test_file.stat().st_size)]
    engine = CoreAnalysisEngine()

    findings, summary = engine.analyze_targets(
        targets,
        scan_id="fused_test",
        enable_bandit=True,
        enable_yaml_rules=True,
    )

    assert summary.total_findings >= 2
    cwe_distribution = summary.cwe_distribution
    assert "CWE-89" in cwe_distribution   # AST / Bandit
    assert "CWE-377" in cwe_distribution  # YAML rule
