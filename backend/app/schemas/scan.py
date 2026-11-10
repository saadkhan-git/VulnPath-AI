"""Pydantic v2 schemas for scans and scan lifecycle management."""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.constants import ScanStatus
from backend.app.schemas.finding import FindingRead


class ScanConfig(BaseModel):
    """Configuration options for a scan job."""
    project_name: str = Field(default="Untitled Scan", description="Label for scan run")
    enable_bandit: bool = Field(default=False, description="Run Bandit scanner")
    enable_taint_analysis: bool = Field(default=True, description="Trace source-to-sink AST flows")
    context_lines: int = Field(default=3, ge=0, le=10, description="Lines of surrounding code context")


class ScanSummary(BaseModel):
    """Aggregated metrics and security health for a completed scan."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    security_score: float = Field(
        default=100.0,
        ge=0.0,
        le=100.0,
        description="Calculated security posture score from 0 (Critical) to 100 (Clean)",
    )
    cwe_distribution: Dict[str, int] = Field(default_factory=dict)


class ScanRead(BaseModel):
    """Details and progress of a scan run."""
    scan_id: str
    project_name: str
    target_type: str = Field(..., description="'archive_zip', 'local_directory', or 'single_file'")
    status: ScanStatus = ScanStatus.PENDING
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_file: Optional[str] = None
    files_scanned: int = 0
    total_files: int = 0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    error_message: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None
    findings: Optional[List[FindingRead]] = None
