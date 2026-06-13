from datetime import datetime
from pydantic import BaseModel
from app.models.scan import FindingType, ScanStatus, Severity

class ScanUploadResponse(BaseModel):
    session_id: int
    filename: str
    files: list[str]
    message: str

class ScanStatusResponse(BaseModel):
    session_id: int
    status: ScanStatus
    message: str
    error_message: str | None = None

class FindingResponse(BaseModel):
    id: int
    finding_type: FindingType
    title: str
    file_path: str | None
    line_number: int | None
    severity: Severity
    cwe_id: str | None
    category: str | None
    description: str | None
    cvss_score: float | None
    cve_id: str | None
    package_name: str | None
    package_version: str | None
    code_snippet: str | None
    ai_explanation: str | None
    exploitation_scenario: str | None
    fix_snippet: str | None

    model_config = {"from_attributes": True}

class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0

class ScanResultsResponse(BaseModel):
    session_id: int
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None
    severity_summary: SeveritySummary
    findings: list[FindingResponse]
    ai_available: bool
    report_available: bool
    scan_warnings: list[str] = []
