"""Phase 3 API & Storage endpoint integration tests."""

import asyncio
import json
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_scans_empty(client: AsyncClient):
    """Listing scans on a fresh database returns empty list."""
    response = await client.get("/api/scans/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


@pytest.mark.asyncio
async def test_list_findings_empty(client: AsyncClient):
    """Workspace findings endpoint returns an empty list for a fresh database."""
    response = await client.get("/api/scans/findings/")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_get_nonexistent_scan(client: AsyncClient):
    """Requesting a non-existent scan returns 404."""
    response = await client.get("/api/scans/nonexistent_scan_id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_scan_single_file_upload(client: AsyncClient):
    """Upload a single Python file and verify scan_id is returned."""
    code = b"""
import sqlite3
def search(user_input):
    c = sqlite3.connect(':memory:').cursor()
    c.execute(f"SELECT * FROM t WHERE name='{user_input}'")
"""
    response = await client.post(
        "/api/scans/upload/file",
        data={"project_name": "API Test Scan", "enable_bandit": "false"},
        files={"file": ("test_vuln.py", code, "text/x-python")},
    )
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "pending"
    scan_id = data["scan_id"]

    # Poll for completion
    for _ in range(20):
        await asyncio.sleep(0.1)
        poll = await client.get(f"/api/scans/{scan_id}")
        if poll.json().get("status") in ("completed", "failed"):
            break

    final = await client.get(f"/api/scans/{scan_id}")
    assert final.status_code == 200
    scan_data = final.json()
    assert scan_data["status"] == "completed"
    assert scan_data["summary"]["total_findings"] >= 1
    assert scan_data["summary"]["high_count"] >= 1
    assert scan_data["findings"][0]["finding_id"].startswith(f"{scan_id}-")

    # Finding IDs are scan-scoped, so different scans can persist overlapping rules.
    second = await client.post(
        "/api/scans/upload/file",
        data={"project_name": "Second API Test Scan", "enable_bandit": "false"},
        files={"file": ("second_vuln.py", code, "text/x-python")},
    )
    second_id = second.json()["scan_id"]
    for _ in range(20):
        await asyncio.sleep(0.1)
        poll = await client.get(f"/api/scans/{second_id}")
        if poll.json().get("status") in ("completed", "failed"):
            break
    assert (await client.get(f"/api/scans/{second_id}")).json()["status"] == "completed"
    findings = await client.get("/api/scans/findings/")
    assert findings.status_code == 200
    assert {item["scan_id"] for item in findings.json()} == {scan_id, second_id}


@pytest.mark.asyncio
async def test_scan_zip_upload(client: AsyncClient, tmp_path):
    """Upload a ZIP archive with vulnerable Python files and verify scan completes."""
    import io
    import zipfile

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("app.py", """
import pickle

def deserialize(data):
    return pickle.loads(data)
""")
    zip_buffer.seek(0)

    response = await client.post(
        "/api/scans/upload/zip",
        data={"project_name": "ZIP Test Scan", "enable_bandit": "false"},
        files={"file": ("project.zip", zip_buffer.getvalue(), "application/zip")},
    )
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["files_queued"] >= 1


@pytest.mark.asyncio
async def test_scan_samples_endpoint(client: AsyncClient):
    """Trigger a sample scan and verify it starts successfully."""
    response = await client.post("/api/scans/samples/vulnerable")
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["files_queued"] >= 1


@pytest.mark.asyncio
async def test_cancel_running_scan(client: AsyncClient):
    """Verify cancellation endpoint flags a pending scan."""
    code = b"x = 1"
    response = await client.post(
        "/api/scans/upload/file",
        data={"project_name": "Cancel Test"},
        files={"file": ("tiny.py", code, "text/x-python")},
    )
    scan_id = response.json()["scan_id"]

    cancel = await client.post(f"/api/scans/{scan_id}/cancel")
    # Status can be 200 (cancelled) or 409 (already completed)
    assert cancel.status_code in (200, 409)


@pytest.mark.asyncio
async def test_delete_scan(client: AsyncClient):
    """Scan can be deleted after completion."""
    code = b"x = 1"
    resp = await client.post(
        "/api/scans/upload/file",
        data={"project_name": "Delete Test"},
        files={"file": ("del.py", code, "text/x-python")},
    )
    scan_id = resp.json()["scan_id"]

    for _ in range(20):
        await asyncio.sleep(0.1)
        s = await client.get(f"/api/scans/{scan_id}")
        if s.json().get("status") in ("completed", "failed", "cancelled"):
            break

    del_resp = await client.delete(f"/api/scans/{scan_id}")
    assert del_resp.status_code == 200

    not_found = await client.get(f"/api/scans/{scan_id}")
    assert not_found.status_code == 404


@pytest.mark.asyncio
async def test_report_download_sarif(client: AsyncClient):
    """Verify SARIF 2.1.0 report can be downloaded after scan completion."""
    code = b"""
import hashlib
def hash_it(val):
    return hashlib.md5(val).hexdigest()
"""
    resp = await client.post(
        "/api/scans/upload/file",
        data={"project_name": "SARIF Report Test"},
        files={"file": ("hash.py", code, "text/x-python")},
    )
    scan_id = resp.json()["scan_id"]

    for _ in range(30):
        await asyncio.sleep(0.1)
        s = await client.get(f"/api/scans/{scan_id}")
        if s.json().get("status") == "completed":
            break

    sarif_resp = await client.get(f"/api/scans/{scan_id}/report?format=sarif")
    assert sarif_resp.status_code == 200
    sarif = sarif_resp.json()
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
