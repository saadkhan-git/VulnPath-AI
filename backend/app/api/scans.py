"""FastAPI scan orchestration endpoints — Phase 3 API & Storage."""

import io
import tempfile
from pathlib import Path
from typing import List, Literal, Optional
import uuid

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse, Response

from backend.app.core.config import settings
from backend.app.core.constants import ScanStatus
from backend.app.database.repository import scan_repo
from backend.app.ingestion.extractor import SafeArchiveExtractor
from backend.app.ingestion.scanner_target import ScanTargetHandler, TargetFile
from backend.app.parsing.ast_parser import PythonAstParser
from backend.app.schemas.finding import FindingRead
from backend.app.schemas.scan import ScanConfig, ScanRead
from backend.app.services.export_service import export_service
from backend.app.services.scan_service import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("/", summary="List scan history", response_model=List[ScanRead])
async def list_scans(limit: int = Query(default=50, ge=1, le=200)):
    """Returns a list of recent scans ordered by date descending."""
    return await scan_repo.list_scans(limit=limit)


@router.get("/findings/", summary="List recent findings", response_model=List[FindingRead])
async def list_findings(limit: int = Query(default=1000, ge=1, le=1000)):
    """Returns recent findings from completed scans for workspace-wide triage."""
    return await scan_repo.list_findings(limit=limit)


@router.get("/{scan_id}", summary="Get scan details", response_model=ScanRead)
async def get_scan(scan_id: str):
    """Returns full scan status, progress, summary, and findings."""
    result = await scan_repo.get_scan_by_id(scan_id, include_findings=True)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
    return result


@router.delete("/{scan_id}", summary="Delete a scan from history")
async def delete_scan(scan_id: str):
    """Removes a completed scan and its findings from local history."""
    result = await scan_repo.get_scan_by_id(scan_id, include_findings=False)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
    if result.status in (
        ScanStatus.PENDING,
        ScanStatus.ANALYZING,
        ScanStatus.EXTRACTING,
        ScanStatus.PARSING,
        ScanStatus.FUSING,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An active scan cannot be deleted. Cancel it and wait for it to finish first.",
        )
    deleted = await scan_repo.delete_scan(scan_id)
    return {"detail": f"Scan '{scan_id}' deleted successfully."}


@router.post("/{scan_id}/cancel", summary="Request scan cancellation")
async def cancel_scan(scan_id: str):
    """Flags the running scan for cooperative cancellation between files."""
    result = await scan_repo.get_scan_by_id(scan_id, include_findings=False)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")
    if result.status not in (ScanStatus.PENDING, ScanStatus.ANALYZING, ScanStatus.EXTRACTING, ScanStatus.PARSING):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is not in a cancellable state.")
    scan_service.request_cancellation(scan_id)
    return {"detail": f"Cancellation requested for scan '{scan_id}'."}


@router.post("/upload/file", summary="Start a scan from a single Python file", status_code=status.HTTP_202_ACCEPTED)
async def scan_single_file(
    file: UploadFile = File(...),
    project_name: str = Form(default="File Upload Scan"),
    enable_bandit: bool = Form(default=False),
):
    """
    Accepts a single Python source file and queues an analysis scan job.
    Returns scan_id immediately; poll GET /api/scans/{scan_id} for progress.
    """
    if not file.filename or not file.filename.endswith((".py", ".pyw")):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only Python source files (.py, .pyw) are supported.",
        )

    content = await file.read()
    if len(content) > settings.max_single_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum permitted size of {settings.max_single_file_size_bytes // 1024} KB.",
        )

    # Decode safely with encoding fallback
    try:
        source_code = content.decode("utf-8")
    except UnicodeDecodeError:
        source_code = content.decode("latin-1")

    # Write to safe temp file
    work_dir = Path(tempfile.mkdtemp(prefix="vulnpath_file_"))
    safe_name = Path(file.filename).name  # Strip any directory component
    target_path = work_dir / safe_name
    target_path.write_text(source_code, encoding="utf-8")

    targets = [TargetFile(relative_path=safe_name, absolute_path=target_path, size_bytes=len(content))]

    scan_id = await scan_service.start_scan_job(
        project_name=project_name,
        target_type="single_file",
        target_files=targets,
        scan_config=ScanConfig(project_name=project_name, enable_bandit=enable_bandit),
        temp_dir_to_clean=work_dir,
    )
    return {"scan_id": scan_id, "status": ScanStatus.PENDING.value}


@router.post("/upload/zip", summary="Start a scan from a ZIP archive", status_code=status.HTTP_202_ACCEPTED)
async def scan_zip_archive(
    file: UploadFile = File(...),
    project_name: str = Form(default="Archive Scan"),
    enable_bandit: bool = Form(default=False),
):
    """
    Accepts a ZIP archive, extracts it safely, and queues an analysis scan job.
    Returns scan_id immediately; poll GET /api/scans/{scan_id} for progress.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only .zip archives are accepted.",
        )

    content = await file.read()
    if len(content) > settings.max_archive_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Archive exceeds maximum permitted size of {settings.max_archive_size_bytes // (1024 * 1024)} MB.",
        )

    work_dir = Path(tempfile.mkdtemp(prefix="vulnpath_zip_"))
    zip_path = work_dir / "upload.zip"
    zip_path.write_bytes(content)

    try:
        extractor = SafeArchiveExtractor()
        extract_dest = work_dir / "source"
        extractor.extract_zip(zip_path, extract_dest)
        zip_path.unlink()  # Remove raw zip after extraction

        handler = ScanTargetHandler()
        targets = handler.discover_directory_files(extract_dest)
    except Exception as ex:
        import shutil
        shutil.rmtree(work_dir, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Archive processing failed: {str(ex)}",
        )

    if not targets:
        import shutil
        shutil.rmtree(work_dir, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No supported Python source files (.py) found in the archive.",
        )

    scan_id = await scan_service.start_scan_job(
        project_name=project_name,
        target_type="archive_zip",
        target_files=targets,
        scan_config=ScanConfig(project_name=project_name, enable_bandit=enable_bandit),
        temp_dir_to_clean=work_dir,
        base_dir=extract_dest,
    )
    return {"scan_id": scan_id, "status": ScanStatus.PENDING.value, "files_queued": len(targets)}


@router.post("/samples/{sample_set}", summary="Scan bundled sample code", status_code=status.HTTP_202_ACCEPTED)
async def scan_samples(sample_set: str, enable_bandit: bool = False):
    """
    Queues a scan against the bundled vulnerable, safe, or all sample code.
    Valid values: 'vulnerable', 'safe', 'all'.
    """
    samples_root = Path("samples")
    if sample_set == "vulnerable":
        scan_root = samples_root / "vulnerable"
    elif sample_set == "safe":
        scan_root = samples_root / "safe"
    elif sample_set == "all":
        scan_root = samples_root
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="sample_set must be 'vulnerable', 'safe', or 'all'.",
        )

    if not scan_root.is_dir():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Samples directory not found.")

    handler = ScanTargetHandler()
    targets = handler.discover_directory_files(scan_root)

    if not targets:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No Python samples found.")

    project_name = f"Sample Scan [{sample_set}]"
    scan_id = await scan_service.start_scan_job(
        project_name=project_name,
        target_type="local_directory",
        target_files=targets,
        scan_config=ScanConfig(project_name=project_name, enable_bandit=enable_bandit),
        base_dir=scan_root,
    )
    return {"scan_id": scan_id, "status": ScanStatus.PENDING.value, "files_queued": len(targets)}


@router.get("/{scan_id}/report", summary="Download scan report")
async def download_report(scan_id: str, format: Literal["json", "sarif", "markdown"] = Query(default="json")):
    """
    Downloads the completed scan report in JSON, SARIF 2.1.0, or Markdown format.
    """
    scan = await scan_repo.get_scan_by_id(scan_id, include_findings=True)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan '{scan_id}' not found.")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan status is '{scan.status}'. Reports are only available for completed scans.",
        )

    if format == "sarif":
        sarif_data = export_service.to_sarif(scan)
        import json
        return Response(
            content=json.dumps(sarif_data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="vulnpath_{scan_id}.sarif"'},
        )
    elif format == "markdown":
        md_content = export_service.to_markdown(scan)
        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="vulnpath_{scan_id}.md"'},
        )
    else:
        json_content = export_service.to_json(scan)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="vulnpath_{scan_id}.json"'},
        )
