"""Secure archive extraction with strict resource and path boundary enforcement."""

import os
from pathlib import Path
import tempfile
import zipfile
from typing import List

from backend.app.core.config import settings
from backend.app.core.security import SecurityViolationError, is_safe_relative_path


class SafeArchiveExtractor:
    """
    Safely extracts ZIP archives mitigating Zip Slip (CWE-22),
    archive bombs (CWE-400), and symlink escape attacks.
    """

    def __init__(
        self,
        max_archive_size: int = settings.max_archive_size_bytes,
        max_extracted_size: int = settings.max_total_extracted_bytes,
        max_file_count: int = settings.max_file_count,
        max_single_file_size: int = settings.max_single_file_size_bytes,
    ):
        self.max_archive_size = max_archive_size
        self.max_extracted_size = max_extracted_size
        self.max_file_count = max_file_count
        self.max_single_file_size = max_single_file_size

    def extract_zip(self, zip_path: Path, destination_dir: Path) -> List[Path]:
        """
        Validates and extracts all safe files from zip_path to destination_dir.
        Returns a list of extracted file paths.
        """
        if not zip_path.is_file():
            raise FileNotFoundError(f"Archive not found: {zip_path}")

        archive_size = zip_path.stat().st_size
        if archive_size > self.max_archive_size:
            raise SecurityViolationError(
                f"Archive size ({archive_size} bytes) exceeds maximum permitted ({self.max_archive_size} bytes)"
            )

        if not zipfile.is_zipfile(zip_path):
            raise ValueError(f"File is not a valid ZIP archive: {zip_path}")

        destination_dir.mkdir(parents=True, exist_ok=True)
        resolved_dest = destination_dir.resolve()
        extracted_files: List[Path] = []
        total_extracted_bytes = 0
        total_files = 0

        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()

            if len(infolist) > self.max_file_count:
                raise SecurityViolationError(
                    f"Archive contains {len(infolist)} entries, exceeding maximum allowed of {self.max_file_count}"
                )

            for member in infolist:
                # 1. Skip directories
                if member.is_dir():
                    continue

                # 2. Check path safety (Mitigates Zip Slip)
                normalized_name = member.filename.replace("\\", "/")
                if not is_safe_relative_path(normalized_name):
                    raise SecurityViolationError(
                        f"Zip Slip attempt detected: entry '{member.filename}' escapes target extraction root."
                    )

                # 3. Check for symlinks in zip metadata
                # Upper 16 bits of external_attr contain POSIX permissions; 0o120000 indicates symlink
                if (member.external_attr >> 16) & 0o120000 == 0o120000:
                    raise SecurityViolationError(
                        f"Symbolic link detected in archive entry '{member.filename}'. Symlinks are prohibited."
                    )

                # 4. Enforce single file size limit
                if member.file_size > self.max_single_file_size:
                    raise SecurityViolationError(
                        f"Archive entry '{member.filename}' ({member.file_size} bytes) exceeds single file limit of {self.max_single_file_size} bytes."
                    )

                # 5. Track uncompressed total size (Zip Bomb mitigation)
                total_extracted_bytes += member.file_size
                if total_extracted_bytes > self.max_extracted_size:
                    raise SecurityViolationError(
                        f"Archive expansion exceeded limit of {self.max_extracted_size} bytes."
                    )

                # 6. Safe extraction target resolution
                target_file_path = (resolved_dest / normalized_name).resolve()
                try:
                    target_file_path.relative_to(resolved_dest)
                except ValueError:
                    raise SecurityViolationError(
                        f"Target path {target_file_path} escapes root destination {resolved_dest}"
                    )

                # Ensure parent directory exists
                target_file_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract file safely
                with zf.open(member) as source, open(target_file_path, "wb") as target:
                    bytes_written = 0
                    while chunk := source.read(65536):
                        bytes_written += len(chunk)
                        if bytes_written > self.max_single_file_size:
                            raise SecurityViolationError(
                                f"Extracted bytes exceeded declared file size for '{member.filename}'"
                            )
                        target.write(chunk)

                extracted_files.append(target_file_path)
                total_files += 1

        return extracted_files
