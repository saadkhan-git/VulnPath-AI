"""Comprehensive unit and regression tests for VulnPath AI Core Engine (Phase 1)."""

import io
from pathlib import Path
import zipfile
import pytest

from backend.app.analysis.engine import CoreAnalysisEngine, core_engine
from backend.app.core.constants import SeverityLevel
from backend.app.core.security import SecurityViolationError
from backend.app.ingestion.extractor import SafeArchiveExtractor
from backend.app.ingestion.scanner_target import ScanTargetHandler, TargetFile
from backend.app.parsing.ast_parser import PythonAstParser


# --- 1. Extraction and Ingestion Tests ---

def test_safe_zip_extraction(tmp_path: Path):
    """Test extracting a benign zip archive succeeds."""
    zip_path = tmp_path / "valid.zip"
    dest_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("app/main.py", "print('hello world')")
        zf.writestr("utils/helper.py", "def add(a, b): return a + b")

    extractor = SafeArchiveExtractor()
    extracted = extractor.extract_zip(zip_path, dest_dir)

    assert len(extracted) == 2
    assert (dest_dir / "app" / "main.py").exists()
    assert (dest_dir / "utils" / "helper.py").exists()


def test_zip_slip_rejection(tmp_path: Path):
    """Test Zip Slip attempt with upward path traversal is rejected."""
    zip_path = tmp_path / "malicious_slip.zip"
    dest_dir = tmp_path / "extracted_slip"

    with zipfile.ZipFile(zip_path, "w") as zf:
        # Malicious traversal path
        zf.writestr("../../evil_escape.py", "import os; os.system('echo pwned')")

    extractor = SafeArchiveExtractor()
    with pytest.raises(SecurityViolationError, match="Zip Slip"):
        extractor.extract_zip(zip_path, dest_dir)


def test_zip_file_count_quota(tmp_path: Path):
    """Test archive exceeding maximum permitted file count is rejected."""
    zip_path = tmp_path / "bomb.zip"
    dest_dir = tmp_path / "extracted_bomb"

    with zipfile.ZipFile(zip_path, "w") as zf:
        for i in range(15):
            zf.writestr(f"file_{i}.py", f"x = {i}")

    # Set threshold to 10
    extractor = SafeArchiveExtractor(max_file_count=10)
    with pytest.raises(SecurityViolationError, match="exceeding maximum"):
        extractor.extract_zip(zip_path, dest_dir)


def test_target_handler_directory_discovery(tmp_path: Path):
    """Test directory walker discovers Python files and ignores .git and .venv."""
    # Create test tree
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text("a = 1")
    (tmp_path / "app" / "models.py").write_text("b = 2")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.py").write_text("c = 3")  # Must be ignored
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("d = 4")    # Must be ignored
    (tmp_path / "notes.txt").write_text("some notes")      # Non-python must be ignored

    handler = ScanTargetHandler()
    discovered = handler.discover_directory_files(tmp_path)

    rel_paths = {t.relative_path for t in discovered}
    assert "app/views.py" in rel_paths
    assert "app/models.py" in rel_paths
    assert ".git/config.py" not in rel_paths
    assert ".venv/lib.py" not in rel_paths
    assert "notes.txt" not in rel_paths


# --- 2. AST Parsing and Resilience Tests ---

def test_ast_parser_valid_code():
    """Test parsing syntactically valid Python code."""
    code = "def greet(name):\n    return f'Hello, {name}'\n"
    parsed = PythonAstParser.parse_source(code, "test_greet.py")

    assert parsed.ast_tree is not None
    assert parsed.syntax_error is None
    assert parsed.total_lines == 2


def test_ast_parser_syntax_error_resilience():
    """Test scanner does not crash when encountering broken syntax."""
    broken_code = "def broken_func(\n   print('missing parenthesis'\n"
    parsed = PythonAstParser.parse_source(broken_code, "broken.py")

    assert parsed.ast_tree is None
    assert parsed.syntax_error is not None
    assert "SyntaxError" in parsed.syntax_error


def test_code_context_extraction():
    """Test extracting surrounding lines of code with target marker."""
    code = "line 1\nline 2\nline 3\nvulnerable line 4\nline 5\nline 6"
    parsed = PythonAstParser.parse_source(code, "context.py")
    context = PythonAstParser.extract_code_context(parsed, line_number=4, context_lines=2)

    assert ">    4 | vulnerable line 4" in context
    assert "     2 | line 2" in context
    assert "     6 | line 6" in context


# --- 3. Vulnerability Detectors vs Samples Regression Tests ---

def test_sql_injection_detector():
    """Verify SQLi detector flags vulnerable sample and rejects safe sample."""
    engine = CoreAnalysisEngine()

    # 1. Vulnerable sample
    vuln_path = Path("samples/vulnerable/sql_injection.py")
    vuln_code = vuln_path.read_text(encoding="utf-8")
    vuln_findings = engine.analyze_source_code(vuln_code, relative_path=vuln_path.as_posix())

    assert len(vuln_findings) == 1
    assert vuln_findings[0].cwe_id == "CWE-89"
    assert vuln_findings[0].severity == SeverityLevel.HIGH
    assert len(vuln_findings[0].data_flow_path) >= 1

    # 2. Safe sample (parameterized placeholder)
    safe_path = Path("samples/safe/sql_injection_safe.py")
    safe_code = safe_path.read_text(encoding="utf-8")
    safe_findings = engine.analyze_source_code(safe_code, relative_path=safe_path.as_posix())

    # Must produce 0 false positives!
    assert len(safe_findings) == 0


def test_command_injection_detector():
    """Verify Command Injection detector flags vulnerable sample and rejects safe sample."""
    engine = CoreAnalysisEngine()

    # 1. Vulnerable sample (shell=True with dynamic string)
    vuln_path = Path("samples/vulnerable/command_injection.py")
    vuln_code = vuln_path.read_text(encoding="utf-8")
    vuln_findings = engine.analyze_source_code(vuln_code, relative_path=vuln_path.as_posix())

    assert len(vuln_findings) == 1
    assert vuln_findings[0].cwe_id == "CWE-78"
    assert vuln_findings[0].severity == SeverityLevel.CRITICAL

    # 2. Safe sample (shell=False with argument vector list)
    safe_path = Path("samples/safe/command_injection_safe.py")
    safe_code = safe_path.read_text(encoding="utf-8")
    safe_findings = engine.analyze_source_code(safe_code, relative_path=safe_path.as_posix())

    # Must produce 0 false positives!
    assert len(safe_findings) == 0


def test_path_traversal_detector():
    """Verify Path Traversal detector flags vulnerable sample and rejects safe sample."""
    engine = CoreAnalysisEngine()

    # 1. Vulnerable sample
    vuln_path = Path("samples/vulnerable/path_traversal.py")
    vuln_code = vuln_path.read_text(encoding="utf-8")
    vuln_findings = engine.analyze_source_code(vuln_code, relative_path=vuln_path.as_posix())

    assert len(vuln_findings) == 1
    assert vuln_findings[0].cwe_id == "CWE-22"
    assert vuln_findings[0].severity == SeverityLevel.MEDIUM

    # 2. Safe sample (relative_to boundary verification)
    safe_path = Path("samples/safe/path_traversal_safe.py")
    safe_code = safe_path.read_text(encoding="utf-8")
    safe_findings = engine.analyze_source_code(safe_code, relative_path=safe_path.as_posix())

    # Must produce 0 false positives!
    assert len(safe_findings) == 0


def test_hardcoded_secrets_detector():
    """Verify Hardcoded Secrets detector flags credentials and rejects env-based credentials."""
    engine = CoreAnalysisEngine()

    # 1. Vulnerable sample (AWS key and JWT literal secrets)
    vuln_path = Path("samples/vulnerable/hardcoded_secret.py")
    vuln_code = vuln_path.read_text(encoding="utf-8")
    vuln_findings = engine.analyze_source_code(vuln_code, relative_path=vuln_path.as_posix())

    assert len(vuln_findings) >= 2
    cwe_ids = {f.cwe_id for f in vuln_findings}
    assert "CWE-798" in cwe_ids

    # 2. Safe sample (os.environ retrieval)
    safe_path = Path("samples/safe/hardcoded_secret_safe.py")
    safe_code = safe_path.read_text(encoding="utf-8")
    safe_findings = engine.analyze_source_code(safe_code, relative_path=safe_path.as_posix())

    # Must produce 0 false positives!
    assert len(safe_findings) == 0


def test_deserialization_and_weak_crypto_detectors():
    """Verify Insecure Deserialization (CWE-502) and Broken Crypto (CWE-327) detectors."""
    engine = CoreAnalysisEngine()

    code = """
import pickle
import hashlib

def process(data):
    # Deserialization vulnerability
    obj = pickle.loads(data)
    
    # Broken hash vulnerability
    h = hashlib.md5(data)
    
    # Safe non-security hash
    safe_h = hashlib.md5(data, usedforsecurity=False)
    return obj
"""
    findings = engine.analyze_source_code(code, "crypto_pickle.py")

    cwe_map = {f.cwe_id: f for f in findings}
    assert "CWE-502" in cwe_map
    assert "CWE-327" in cwe_map
    assert cwe_map["CWE-502"].severity == SeverityLevel.CRITICAL
    assert cwe_map["CWE-327"].severity == SeverityLevel.LOW


# --- 4. Core Engine Coordination & Summary Tests ---

def test_engine_deduplication_and_scoring():
    """Verify deduplication and deterministic security scoring."""
    engine = CoreAnalysisEngine()

    code = """
import sqlite3

def run_query(uid):
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    # High severity SQL injection
    c.execute(f"SELECT * FROM users WHERE id = '{uid}'")
"""
    findings = engine.analyze_source_code(code, "test_scoring.py")
    summary = engine.calculate_summary(findings)

    assert summary.total_findings == 1
    assert summary.high_count == 1
    # 100 - (12 * 1) = 88.0
    assert summary.security_score == 88.0
    assert summary.cwe_distribution.get("CWE-89") == 1


def test_engine_target_scan_cancellation(tmp_path: Path):
    """Verify cooperative cancellation stops analysis between files."""
    file1 = tmp_path / "file1.py"
    file2 = tmp_path / "file2.py"
    file1.write_text("import pickle\npickle.loads(b'')")
    file2.write_text("import pickle\npickle.loads(b'')")

    targets = [
        TargetFile("file1.py", file1, 30),
        TargetFile("file2.py", file2, 30),
    ]

    engine = CoreAnalysisEngine()
    cancelled = True

    findings, summary = engine.analyze_targets(
        targets,
        scan_id="cancel_test",
        check_cancelled=lambda: cancelled,
    )

    # Cancelled before file 1 processing
    assert len(findings) == 0
