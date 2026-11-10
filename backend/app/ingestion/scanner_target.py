"""Target discovery and file filtering for scan operations."""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import List, Optional, Set

from backend.app.core.config import settings
from backend.app.core.constants import SUPPORTED_PYTHON_EXTENSIONS
from backend.app.core.security import SecurityViolationError, is_path_in_allowed_roots
from backend.app.ingestion.extractor import SafeArchiveExtractor

IGNORED_DIRECTORIES: Set[str] = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".vulnpath",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".egg-info",
}


@dataclass
class TargetFile:
    """Represents a validated source file to be scanned."""
    relative_path: str
    absolute_path: Path
    size_bytes: int


class ScanTargetHandler:
    """Discovers, validates, and filters source files for security analysis."""

    def __init__(self, allowed_roots: Optional[List[str]] = None):
        self.allowed_roots = allowed_roots or settings.allowed_scan_roots
        self.extractor = SafeArchiveExtractor()

    def discover_directory_files(self, base_dir: Path) -> List[TargetFile]:
        """
        Recursively discovers supported source files in base_dir,
        skipping ignored directories and files exceeding size quotas.
        """
        resolved_base = base_dir.resolve()
        if not resolved_base.is_dir():
            raise NotADirectoryError(f"Directory not found: {resolved_base}")

        # Check allowed root boundary if configured
        if self.allowed_roots and not is_path_in_allowed_roots(resolved_base, self.allowed_roots):
            raise SecurityViolationError(
                f"Directory '{resolved_base}' is outside permitted scan roots."
            )

        discovered: List[TargetFile] = []

        for root, dirs, files in os.walk(resolved_base, topdown=True):
            # Prune ignored directories in-place
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES and not d.endswith(".egg-info")]

            current_dir = Path(root)
            for file_name in files:
                file_path = current_dir / file_name
                ext = file_path.suffix.lower()

                if ext in SUPPORTED_PYTHON_EXTENSIONS:
                    try:
                        stat = file_path.stat()
                        if stat.st_size > settings.max_single_file_size_bytes:
                            continue  # Skip files exceeding maximum single-file threshold

                        rel_path = file_path.relative_to(resolved_base).as_posix()
                        discovered.append(
                            TargetFile(
                                relative_path=rel_path,
                                absolute_path=file_path,
                                size_bytes=stat.st_size,
                            )
                        )

                        if len(discovered) > settings.max_file_count:
                            raise SecurityViolationError(
                                f"Scanned file count exceeded maximum limit of {settings.max_file_count}"
                            )
                    except (PermissionError, FileNotFoundError):
                        continue

        return discovered

    def discover_single_file(self, file_path: Path) -> List[TargetFile]:
        """Validates and packages an individual source file for scanning."""
        resolved = file_path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"File not found: {resolved}")

        if resolved.suffix.lower() not in SUPPORTED_PYTHON_EXTENSIONS:
            raise ValueError(
                f"File extension '{resolved.suffix}' is not a supported Python source file."
            )

        stat = resolved.stat()
        if stat.st_size > settings.max_single_file_size_bytes:
            raise SecurityViolationError(
                f"File size ({stat.st_size} bytes) exceeds limit of {settings.max_single_file_size_bytes} bytes."
            )

        return [
            TargetFile(
                relative_path=resolved.name,
                absolute_path=resolved,
                size_bytes=stat.st_size,
            )
        ]

    def process_zip_target(self, zip_path: Path, work_dir: Path) -> List[TargetFile]:
        """Extracts ZIP archive safely into work_dir and returns discovered source files."""
        self.extractor.extract_zip(zip_path, work_dir)
        return self.discover_directory_files(work_dir)
