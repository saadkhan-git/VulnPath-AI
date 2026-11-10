"""Pydantic v2 schemas for project workspaces."""

from typing import List, Optional
from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    """Payload to register a new project workspace."""
    name: str = Field(..., description="Project workspace name")
    description: Optional[str] = Field(None, description="Project notes or scope")
    local_path: Optional[str] = Field(None, description="Local absolute filesystem path")


class ProjectRead(BaseModel):
    """Project workspace record."""
    project_id: str
    name: str
    description: Optional[str] = None
    local_path: Optional[str] = None
    created_at: str
    last_scanned_at: Optional[str] = None
    total_scans: int = 0
