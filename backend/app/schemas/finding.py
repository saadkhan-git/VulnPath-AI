"""Pydantic v2 domain schemas for vulnerability findings."""

from typing import List, Optional
from pydantic import BaseModel, Field
from backend.app.core.constants import ConfidenceLevel, SeverityLevel


class CodePathNode(BaseModel):
    """Represents a discrete step in a source-to-sink data-flow path."""
    step_number: int = Field(..., description="Order in the trace sequence (1=Source, N=Sink)")
    file_path: str = Field(..., description="Relative file path")
    line_number: int = Field(..., description="Line number of code statement")
    function_name: Optional[str] = Field(None, description="Enclosing function name")
    statement: str = Field(..., description="Exact code statement text")
    node_type: str = Field(..., description="Role: 'source', 'propagator', 'sanitizer', or 'sink'")
    description: Optional[str] = Field(None, description="Explanation of data transformation")


class FindingBase(BaseModel):
    """Core attributes of a static analysis vulnerability finding."""
    title: str = Field(..., description="Human-readable summary of the weakness")
    cwe_id: str = Field(..., description="Common Weakness Enumeration ID, e.g. CWE-89")
    file_path: str = Field(..., description="Relative path to affected source file")
    line_number: int = Field(..., description="Primary line number of the vulnerability")
    end_line_number: Optional[int] = Field(None, description="End line number if multiline statement")
    function_name: Optional[str] = Field(None, description="Function or method enclosing finding")
    
    # Risk Intelligence Metrics
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Potential impact")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Detection confidence score")
    reachability: str = Field(default="unknown", description="'reachable', 'unreachable', or 'unknown'")
    exposure: str = Field(default="unknown", description="'externally_exposed', 'internal', or 'unknown'")
    remediation_priority: str = Field(default="P3", description="'P1' (Urgent) down to 'P5' (Low)")

    # Evidence & Traceability
    source_description: Optional[str] = Field(None, description="Untrusted entry point or variable")
    sink_description: Optional[str] = Field(None, description="Sensitive operation or execution sink")
    evidence_notes: List[str] = Field(default_factory=list, description="Reasoning and heuristic evidence")
    analysis_sources: List[str] = Field(default_factory=list, description="Engines: 'AST', 'Bandit', 'PAEF'")
    code_context: Optional[str] = Field(None, description="Surrounding code snippet with context")
    data_flow_path: List[CodePathNode] = Field(default_factory=list, description="Source-to-sink trace")


class FindingCreate(FindingBase):
    """Schema for creating a new finding during scan execution."""
    scan_id: str = Field(..., description="Associated scan identifier")


class FindingRead(FindingBase):
    """Schema returned by API endpoints for finding display."""
    finding_id: str = Field(..., description="Unique finding identifier scoped to its scan")
    scan_id: str = Field(..., description="Scan identifier")
    status: str = Field(default="needs_review", description="'needs_review', 'confirmed', 'false_positive', 'fixed'")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
