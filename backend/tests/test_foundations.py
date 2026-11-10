"""Foundational tests for VulnPath AI Phase 0."""

import pytest
from httpx import AsyncClient

from backend.app.core.constants import (
    AUTHOR_GITHUB,
    AUTHOR_NAME,
    CLEAN_ROOM_COMPLIANT,
    PRODUCT_NAME,
    PRODUCT_TAGLINE,
    PRODUCT_VERSION,
    SeverityLevel,
)
from backend.app.core.security import (
    SecurityViolationError,
    is_safe_relative_path,
    validate_path_within_root,
)
from backend.app.database.db import DatabaseManager
from backend.app.schemas.finding import CodePathNode, FindingCreate, FindingRead
from backend.app.schemas.scan import ScanRead, ScanSummary


def test_product_identity_and_clean_room():
    """Verify strictly required product branding and clean-room provenance."""
    assert PRODUCT_NAME == "VulnPath AI"
    assert PRODUCT_TAGLINE == "Trace the path. Fix the flaw."
    assert AUTHOR_NAME == "Mohammad Saad Khan"
    assert AUTHOR_GITHUB == "https://github.com/saadkhan-git"
    assert PRODUCT_VERSION == "0.1.0"
    assert CLEAN_ROOM_COMPLIANT is True


def test_security_relative_path_validation():
    """Test path traversal mitigations against Zip Slip and directory escapes."""
    # Safe relative paths
    assert is_safe_relative_path("app/main.py") is True
    assert is_safe_relative_path("src/core/parser.py") is True
    assert is_safe_relative_path("tests/subfolder/file.py") is True

    # Malicious traversal paths
    assert is_safe_relative_path("../etc/passwd") is False
    assert is_safe_relative_path("app/../../escape.py") is False
    assert is_safe_relative_path("/root/secrets.txt") is False
    assert is_safe_relative_path("C:\\Windows\\system32\\calc.exe") is False
    assert is_safe_relative_path("") is False


def test_path_within_root_containment(tmp_path):
    """Test boundary validation that paths strictly reside in the allowed root."""
    safe_file = tmp_path / "child.py"
    safe_file.write_text("print('safe')")
    validated = validate_path_within_root(safe_file, tmp_path)
    assert validated == safe_file.resolve()

    # Escape attempt
    outside_file = tmp_path.parent / "outside.py"
    with pytest.raises(SecurityViolationError):
        validate_path_within_root(outside_file, tmp_path)


def test_schemas_validation():
    """Verify Pydantic v2 schemas for findings and scans."""
    node = CodePathNode(
        step_number=1,
        file_path="app/views.py",
        line_number=42,
        statement="user_input = request.args.get('id')",
        node_type="source",
        description="Untrusted user input",
    )
    assert node.step_number == 1
    assert node.node_type == "source"

    finding = FindingCreate(
        scan_id="scn_test_123",
        title="SQL Injection in user search",
        cwe_id="CWE-89",
        file_path="app/views.py",
        line_number=45,
        severity=SeverityLevel.HIGH,
        confidence=0.95,
        data_flow_path=[node],
    )
    assert finding.cwe_id == "CWE-89"
    assert finding.severity == SeverityLevel.HIGH
    assert len(finding.data_flow_path) == 1

    summary = ScanSummary(
        total_findings=1,
        high_count=1,
        security_score=88.0,
        cwe_distribution={"CWE-89": 1},
    )
    assert summary.security_score == 88.0


@pytest.mark.asyncio
async def test_database_initialization(temp_db: DatabaseManager):
    """Ensure SQLite database schema creates properly and executes queries."""
    async with temp_db.get_connection() as db:
        # Check projects table exists
        cursor = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='projects';")
        row = await cursor.fetchone()
        assert row is not None
        assert row["name"] == "projects"

        # Insert a test scan record
        await db.execute(
            """
            INSERT INTO scans (scan_id, project_name, target_type, status, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("scn_001", "Demo Project", "single_file", "completed", "2026-11-10T19:00:00Z"),
        )
        await db.commit()

        # Query it back
        query_cursor = await db.execute("SELECT scan_id, project_name, status FROM scans WHERE scan_id = ?", ("scn_001",))
        scan_row = await query_cursor.fetchone()
        assert scan_row is not None
        assert scan_row["scan_id"] == "scn_001"
        assert scan_row["project_name"] == "Demo Project"
        assert scan_row["status"] == "completed"


@pytest.mark.asyncio
async def test_health_api_endpoint(client: AsyncClient):
    """Test /api/health for system status, headers, and metadata."""
    response = await client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["product"]["name"] == "VulnPath AI"
    assert data["product"]["creator"] == "Mohammad Saad Khan"
    assert data["product"]["tagline"] == "Trace the path. Fix the flaw."
    assert data["governance"]["clean_room_verified"] is True
    assert ".py" in data["capabilities"]["supported_extensions"]

    # Verify custom security headers
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Server") == "VulnPath-AI-Local"


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test root endpoint provides product metadata and docs URLs."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["product"] == "VulnPath AI"
    assert data["documentation"] == "/docs"
