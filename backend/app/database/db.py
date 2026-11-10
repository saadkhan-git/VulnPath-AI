"""Asynchronous SQLite persistence manager for VulnPath AI."""

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional
import aiosqlite

from backend.app.core.config import settings

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    local_path TEXT,
    created_at TEXT NOT NULL,
    last_scanned_at TEXT,
    total_scans INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    progress_percent INTEGER DEFAULT 0,
    current_file TEXT,
    files_scanned INTEGER DEFAULT 0,
    total_files INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    security_score REAL DEFAULT 100.0,
    cwe_distribution_json TEXT DEFAULT '{}',
    error_message TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    end_line_number INTEGER,
    function_name TEXT,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    reachability TEXT NOT NULL,
    exposure TEXT NOT NULL,
    remediation_priority TEXT NOT NULL,
    source_description TEXT,
    sink_description TEXT,
    evidence_notes_json TEXT DEFAULT '[]',
    analysis_sources_json TEXT DEFAULT '[]',
    code_context TEXT,
    data_flow_path_json TEXT DEFAULT '[]',
    status TEXT DEFAULT 'needs_review',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
"""


class DatabaseManager:
    """Manages SQLite connections and schema initialization."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.db_path

    async def init_db(self) -> None:
        """Create parent directory and establish schema tables if not existing."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(str(self.db_path)) as db:
            await db.execute("PRAGMA journal_mode = WAL;")
            await db.execute("PRAGMA foreign_keys = ON;")
            await db.executescript(CREATE_TABLES_SQL)
            await db.commit()

    @asynccontextmanager
    async def get_connection(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Context manager returning an active connection with foreign keys enabled."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(str(self.db_path)) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys = ON;")
            yield db


db_manager = DatabaseManager()
