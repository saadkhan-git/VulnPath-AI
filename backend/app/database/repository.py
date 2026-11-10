"""Database repository layer for managing projects, scans, and findings."""

import json
from typing import Dict, List, Optional
import aiosqlite

from backend.app.core.constants import ScanStatus
import backend.app.database.db as db_module
from backend.app.schemas.finding import CodePathNode, FindingCreate, FindingRead
from backend.app.schemas.scan import ScanRead, ScanSummary


def _get_db_manager():
    """Return the current global db_manager (allows test override)."""
    return db_module.db_manager


class ScanRepository:
    """Handles CRUD persistence for scans and findings."""

    async def create_scan(
        self,
        scan_id: str,
        project_name: str,
        target_type: str,
        created_at: str,
    ) -> None:
        async with _get_db_manager().get_connection() as db:
            await db.execute(
                """
                INSERT INTO scans (
                    scan_id, project_name, target_type, status,
                    progress_percent, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, project_name, target_type, ScanStatus.PENDING.value, 0, created_at),
            )
            await db.commit()

    async def update_scan_progress(
        self,
        scan_id: str,
        status: ScanStatus,
        progress_percent: int,
        current_file: Optional[str] = None,
        files_scanned: int = 0,
        total_files: int = 0,
    ) -> None:
        async with _get_db_manager().get_connection() as db:
            await db.execute(
                """
                UPDATE scans
                SET status = ?, progress_percent = ?, current_file = ?,
                    files_scanned = ?, total_files = ?
                WHERE scan_id = ?
                """,
                (status.value, progress_percent, current_file, files_scanned, total_files, scan_id),
            )
            await db.commit()

    async def complete_scan(
        self,
        scan_id: str,
        summary: ScanSummary,
        completed_at: str,
        files_scanned: int,
        total_files: int,
    ) -> None:
        async with _get_db_manager().get_connection() as db:
            await db.execute(
                """
                UPDATE scans
                SET status = ?, progress_percent = 100, current_file = NULL,
                    files_scanned = ?, total_files = ?,
                    total_findings = ?, critical_count = ?, high_count = ?,
                    medium_count = ?, low_count = ?, info_count = ?,
                    security_score = ?, cwe_distribution_json = ?,
                    completed_at = ?
                WHERE scan_id = ?
                """,
                (
                    ScanStatus.COMPLETED.value,
                    files_scanned,
                    total_files,
                    summary.total_findings,
                    summary.critical_count,
                    summary.high_count,
                    summary.medium_count,
                    summary.low_count,
                    summary.info_count,
                    summary.security_score,
                    json.dumps(summary.cwe_distribution),
                    completed_at,
                    scan_id,
                ),
            )
            await db.commit()

    async def fail_scan(self, scan_id: str, error_message: str) -> None:
        async with _get_db_manager().get_connection() as db:
            await db.execute(
                """
                UPDATE scans
                SET status = ?, error_message = ?
                WHERE scan_id = ?
                """,
                (ScanStatus.FAILED.value, error_message, scan_id),
            )
            await db.commit()

    async def cancel_scan(self, scan_id: str) -> None:
        async with _get_db_manager().get_connection() as db:
            await db.execute(
                """
                UPDATE scans
                SET status = ?
                WHERE scan_id = ?
                """,
                (ScanStatus.CANCELLED.value, scan_id),
            )
            await db.commit()

    async def save_findings(self, findings: List[FindingCreate], created_at: str) -> None:
        if not findings:
            return

        async with _get_db_manager().get_connection() as db:
            for idx, f in enumerate(findings):
                finding_id = f"{f.scan_id}-VPA-{idx + 1:04d}"
                await db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, scan_id, title, cwe_id, file_path,
                        line_number, end_line_number, function_name,
                        severity, confidence, reachability, exposure,
                        remediation_priority, source_description, sink_description,
                        evidence_notes_json, analysis_sources_json,
                        code_context, data_flow_path_json, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        f.scan_id,
                        f.title,
                        f.cwe_id,
                        f.file_path,
                        f.line_number,
                        f.end_line_number,
                        f.function_name,
                        f.severity.value,
                        f.confidence,
                        f.reachability,
                        f.exposure,
                        f.remediation_priority,
                        f.source_description,
                        f.sink_description,
                        json.dumps(f.evidence_notes),
                        json.dumps(f.analysis_sources),
                        f.code_context,
                        json.dumps([n.model_dump() for n in f.data_flow_path]),
                        "needs_review",
                        created_at,
                    ),
                )
            await db.commit()

    async def get_scan_by_id(self, scan_id: str, include_findings: bool = True) -> Optional[ScanRead]:
        async with _get_db_manager().get_connection() as db:
            cursor = await db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = await cursor.fetchone()
            if not row:
                return None

            findings: Optional[List[FindingRead]] = None
            if include_findings:
                f_cursor = await db.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number ASC",
                    (scan_id,),
                )
                f_rows = await f_cursor.fetchall()
                findings = []
                for f in f_rows:
                    path_data = json.loads(f["data_flow_path_json"] or "[]")
                    findings.append(
                        FindingRead(
                            finding_id=f["finding_id"],
                            scan_id=f["scan_id"],
                            title=f["title"],
                            cwe_id=f["cwe_id"],
                            file_path=f["file_path"],
                            line_number=f["line_number"],
                            end_line_number=f["end_line_number"],
                            function_name=f["function_name"],
                            severity=f["severity"],
                            confidence=f["confidence"],
                            reachability=f["reachability"],
                            exposure=f["exposure"],
                            remediation_priority=f["remediation_priority"],
                            source_description=f["source_description"],
                            sink_description=f["sink_description"],
                            evidence_notes=json.loads(f["evidence_notes_json"] or "[]"),
                            analysis_sources=json.loads(f["analysis_sources_json"] or "[]"),
                            code_context=f["code_context"],
                            data_flow_path=[CodePathNode(**p) for p in path_data],
                            status=f["status"],
                            created_at=f["created_at"],
                        )
                    )

            cwe_dist = json.loads(row["cwe_distribution_json"] or "{}")
            summary = ScanSummary(
                total_findings=row["total_findings"],
                critical_count=row["critical_count"],
                high_count=row["high_count"],
                medium_count=row["medium_count"],
                low_count=row["low_count"],
                info_count=row["info_count"],
                security_score=row["security_score"],
                cwe_distribution=cwe_dist,
            )

            return ScanRead(
                scan_id=row["scan_id"],
                project_name=row["project_name"],
                target_type=row["target_type"],
                status=row["status"],
                progress_percent=row["progress_percent"],
                current_file=row["current_file"],
                files_scanned=row["files_scanned"],
                total_files=row["total_files"],
                summary=summary,
                error_message=row["error_message"],
                created_at=row["created_at"],
                completed_at=row["completed_at"],
                findings=findings,
            )

    async def list_scans(self, limit: int = 50) -> List[ScanRead]:
        async with _get_db_manager().get_connection() as db:
            cursor = await db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                cwe_dist = json.loads(row["cwe_distribution_json"] or "{}")
                summary = ScanSummary(
                    total_findings=row["total_findings"],
                    critical_count=row["critical_count"],
                    high_count=row["high_count"],
                    medium_count=row["medium_count"],
                    low_count=row["low_count"],
                    info_count=row["info_count"],
                    security_score=row["security_score"],
                    cwe_distribution=cwe_dist,
                )
                results.append(
                    ScanRead(
                        scan_id=row["scan_id"],
                        project_name=row["project_name"],
                        target_type=row["target_type"],
                        status=row["status"],
                        progress_percent=row["progress_percent"],
                        current_file=row["current_file"],
                        files_scanned=row["files_scanned"],
                        total_files=row["total_files"],
                        summary=summary,
                        error_message=row["error_message"],
                        created_at=row["created_at"],
                        completed_at=row["completed_at"],
                    )
                )
            return results

    async def list_findings(self, limit: int = 1000) -> List[FindingRead]:
        """Returns recent findings across all scans for workspace-wide triage."""
        async with _get_db_manager().get_connection() as db:
            cursor = await db.execute(
                """
                SELECT findings.*
                FROM findings
                JOIN scans ON scans.scan_id = findings.scan_id
                WHERE scans.status = ?
                ORDER BY findings.created_at DESC, findings.file_path, findings.line_number
                LIMIT ?
                """,
                (ScanStatus.COMPLETED.value, limit),
            )
            rows = await cursor.fetchall()
            return [
                FindingRead(
                    finding_id=row["finding_id"],
                    scan_id=row["scan_id"],
                    title=row["title"],
                    cwe_id=row["cwe_id"],
                    file_path=row["file_path"],
                    line_number=row["line_number"],
                    end_line_number=row["end_line_number"],
                    function_name=row["function_name"],
                    severity=row["severity"],
                    confidence=row["confidence"],
                    reachability=row["reachability"],
                    exposure=row["exposure"],
                    remediation_priority=row["remediation_priority"],
                    source_description=row["source_description"],
                    sink_description=row["sink_description"],
                    evidence_notes=json.loads(row["evidence_notes_json"] or "[]"),
                    analysis_sources=json.loads(row["analysis_sources_json"] or "[]"),
                    code_context=row["code_context"],
                    data_flow_path=[
                        CodePathNode(**node)
                        for node in json.loads(row["data_flow_path_json"] or "[]")
                    ],
                    status=row["status"],
                    created_at=row["created_at"],
                )
                for row in rows
            ]

    async def delete_scan(self, scan_id: str) -> bool:
        async with _get_db_manager().get_connection() as db:
            cursor = await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            await db.commit()
            return cursor.rowcount > 0


scan_repo = ScanRepository()
