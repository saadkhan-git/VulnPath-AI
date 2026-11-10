"""Application configuration settings for VulnPath AI."""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

from backend.app.core.constants import (
    DEFAULT_MAX_ARCHIVE_SIZE_BYTES,
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_SINGLE_FILE_SIZE_BYTES,
    DEFAULT_MAX_TOTAL_EXTRACTED_BYTES,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
)


class Settings(BaseSettings):
    """VulnPath AI runtime settings loaded from environment or defaults."""
    
    model_config = SettingsConfigDict(
        env_prefix="VULNPATH_",
        case_sensitive=False,
        env_file=".env",
        extra="ignore",
    )

    # Server Network Binding (Loopback Only)
    host: str = Field(default="127.0.0.1", description="Local loopback host")
    port: int = Field(default=8765, description="Local web and API port")
    cors_origins: List[str] = Field(
        default=[
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ],
        description="Permitted loopback origins for dashboard",
    )

    # Storage and Persistence
    data_dir: Path = Field(
        default=Path(".vulnpath"),
        description="Local directory for scan history and cache",
    )
    db_name: str = Field(default="vulnpath.db", description="SQLite database filename")

    # Resource and Extraction Quotas
    max_archive_size_bytes: int = DEFAULT_MAX_ARCHIVE_SIZE_BYTES
    max_single_file_size_bytes: int = DEFAULT_MAX_SINGLE_FILE_SIZE_BYTES
    max_total_extracted_bytes: int = DEFAULT_MAX_TOTAL_EXTRACTED_BYTES
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    scan_timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS

    # Allowed scanning project roots (Restricting local folder scans)
    allowed_scan_roots: List[str] = Field(
        default_factory=list,
        description="Explicit directories permitted for local path scanning",
    )

    @property
    def db_path(self) -> Path:
        """Absolute or relative path to the SQLite database file."""
        return self.data_dir / self.db_name

    def ensure_data_dir(self) -> Path:
        """Create the data directory if it does not already exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir


settings = Settings()
