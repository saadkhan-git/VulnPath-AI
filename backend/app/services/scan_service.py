"""Asynchronous scan execution service and lifecycle management."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import shutil
import tempfile
from typing import Dict, List, Optional, Set
import uuid

from backend.app.analysis.engine import core_engine
from backend.app.core.constants import ScanStatus
from backend.app.database.repository import scan_repo
from backend.app.ingestion.scanner_target import ScanTargetHandler, TargetFile
from backend.app.schemas.scan import ScanConfig, ScanRead


class ScanService:
    """Manages asynchronous scan jobs, background tasks, and cleanup."""

    def __init__(self):
        self._target_handler = ScanTargetHandler()
        self._active_cancels: Set[str] = set()

    def request_cancellation(self, scan_id: str) -> bool:
        """Flags a scan for cooperative cancellation between files."""
        self._active_cancels.add(scan_id)
        return True

    async def start_scan_job(
        self,
        project_name: str,
        target_type: str,
        target_files: List[TargetFile],
        scan_config: Optional[ScanConfig] = None,
        temp_dir_to_clean: Optional[Path] = None,
        base_dir: Optional[Path] = None,
    ) -> str:
        """Creates scan record and launches background execution."""
        scan_id = f"scn_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()
        cfg = scan_config or ScanConfig()

        await scan_repo.create_scan(
            scan_id=scan_id,
            project_name=project_name,
            target_type=target_type,
            created_at=now_str,
        )

        # Launch background runner task
        asyncio.create_task(
            self._execute_scan_async(
                scan_id=scan_id,
                target_files=target_files,
                config=cfg,
                temp_dir_to_clean=temp_dir_to_clean,
                base_dir=base_dir,
            )
        )
        return scan_id

    async def _execute_scan_async(
        self,
        scan_id: str,
        target_files: List[TargetFile],
        config: ScanConfig,
        temp_dir_to_clean: Optional[Path] = None,
        base_dir: Optional[Path] = None,
    ) -> None:
        total_files = len(target_files)
        loop = asyncio.get_running_loop()

        def progress_cb(scanned: int, total: int, current_file: str):
            pct = int((scanned / total) * 100) if total > 0 else 0
            progress_update = asyncio.run_coroutine_threadsafe(
                scan_repo.update_scan_progress(
                    scan_id=scan_id,
                    status=ScanStatus.ANALYZING,
                    progress_percent=pct,
                    current_file=current_file,
                    files_scanned=scanned,
                    total_files=total,
                ),
                loop,
            )
            progress_update.result()

        def is_cancelled() -> bool:
            return scan_id in self._active_cancels

        try:
            findings, summary = await asyncio.to_thread(
                core_engine.analyze_targets,
                target_files=target_files,
                scan_id=scan_id,
                enable_bandit=config.enable_bandit,
                enable_yaml_rules=True,
                progress_callback=progress_cb,
                check_cancelled=is_cancelled,
                base_dir=base_dir,
            )

            now_str = datetime.now(timezone.utc).isoformat()

            if is_cancelled():
                await scan_repo.cancel_scan(scan_id)
            else:
                await scan_repo.save_findings(findings, created_at=now_str)
                await scan_repo.complete_scan(
                    scan_id=scan_id,
                    summary=summary,
                    completed_at=now_str,
                    files_scanned=total_files,
                    total_files=total_files,
                )

        except Exception as ex:
            await scan_repo.fail_scan(scan_id=scan_id, error_message=str(ex))
        finally:
            self._active_cancels.discard(scan_id)
            # Safe cleanup of temporary extracted directory
            if temp_dir_to_clean and temp_dir_to_clean.is_dir():
                try:
                    shutil.rmtree(temp_dir_to_clean, ignore_errors=True)
                except Exception:
                    pass


scan_service = ScanService()
