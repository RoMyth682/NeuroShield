import json
import logging
import shutil
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import get_current_user
from app.config import settings
from app.database import SessionLocal, get_db
from app.models.scan import ScanFinding, ScanSession, ScanStatus, Severity
from app.models.user import User
from app.schemas.scan import (
    FindingResponse,
    ScanResultsResponse,
    ScanStatusResponse,
    ScanUploadResponse,
    SeveritySummary,
)
from app.services.ai_explainer import AIExplainer
from app.services.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/api/scan", tags=["scan"])
orchestrator = ScanOrchestrator()
logger = logging.getLogger(__name__)


def _validate_upload(file: UploadFile, content: bytes) -> None:
    # Accept any file types (including single-source files) and zip archives.
    # Validation is limited to size to allow scanning of any language or file.
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File exceeds maximum size of {settings.max_upload_size_mb} MB",
        )


def _run_scan_background(session_id: int) -> None:
    db = SessionLocal()
    try:
        session = db.get(ScanSession, session_id)
        if session:
            orchestrator.run_analysis(db, session)
    except Exception:
        logger.exception("Scan failed for session %s", session_id)
    finally:
        db.close()


@router.post("/upload", response_model=ScanUploadResponse)
async def upload_code(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    content = await file.read()
    _validate_upload(file, content)

    session = ScanSession(
        user_id=current_user.id,
        status=ScanStatus.PENDING,
        original_filename=file.filename or "unknown",
        upload_path="",
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    session_dir = settings.upload_path / f"session_{session.id}"
    session_dir.mkdir(parents=True, exist_ok=True)
    upload_path = session_dir / (file.filename or "upload.zip")
    upload_path.write_bytes(content)

    session.upload_path = str(upload_path)
    db.commit()

    extract_preview_dir = session_dir / "preview"
    extract_preview_dir.mkdir(exist_ok=True)
    try:
        files = orchestrator.extract_upload(upload_path, extract_preview_dir)
        if not files:
            files = orchestrator.list_source_files(extract_preview_dir)
    except Exception:
        files = [file.filename or "uploaded file"]
    finally:
        shutil.rmtree(extract_preview_dir, ignore_errors=True)

    background_tasks.add_task(_run_scan_background, session.id)

    return ScanUploadResponse(
        session_id=session.id,
        filename=file.filename or "unknown",
        files=files[:settings.preview_file_limit],
        message="Upload successful. Analysis started.",
    )


@router.get("/{session_id}/status", response_model=ScanStatusResponse)
def get_scan_status(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _get_user_session(db, session_id, current_user)
    messages = {
        ScanStatus.PENDING: "Waiting to start analysis",
        ScanStatus.EXTRACTING: "Extracting uploaded files",
        ScanStatus.SAST_RUNNING: "Running static analysis (Bandit/Semgrep)",
        ScanStatus.CVE_RUNNING: "Scanning dependencies for known CVEs",
        ScanStatus.AI_RUNNING: "Generating AI explanations",
        ScanStatus.COMPLETED: "Analysis complete",
        ScanStatus.FAILED: "Analysis failed",
    }
    return ScanStatusResponse(
        session_id=session.id,
        status=session.status,
        message=messages.get(session.status, "Processing"),
        error_message=session.error_message,
    )


@router.get("/{session_id}/results", response_model=ScanResultsResponse)
def get_scan_results(
    session_id: int,
    severity: Severity | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _get_user_session(db, session_id, current_user)
    findings = session.findings
    if severity:
        findings = [f for f in findings if f.severity == severity]

    summary = SeveritySummary(total=len(session.findings))
    for f in session.findings:
        setattr(summary, f.severity.value, getattr(summary, f.severity.value) + 1)

    ai = AIExplainer()
    warnings: list[str] = []
    if session.scan_warnings:
        try:
            warnings = json.loads(session.scan_warnings)
        except json.JSONDecodeError:
            warnings = [session.scan_warnings]

    return ScanResultsResponse(
        session_id=session.id,
        status=session.status,
        created_at=session.created_at,
        completed_at=session.completed_at,
        severity_summary=summary,
        findings=[FindingResponse.model_validate(f) for f in findings],
        ai_available=ai.is_available,
        report_available=bool(session.report_path and Path(session.report_path).exists()),
        scan_warnings=warnings,
    )


@router.get("/{session_id}/report")
def download_report(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _get_user_session(db, session_id, current_user)
    if session.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Report not ready yet")

    # Regenerate the report dynamically to include any on-demand AI explanations generated since the initial scan
    try:
        report_path = settings.reports_path / f"report_{session.id}.pdf"
        orchestrator.reporter.generate(session, session.findings, report_path)
        session.report_path = str(report_path)
        db.commit()
    except Exception as exc:
        logger.exception("Failed to regenerate report dynamically")
        # Fall back to existing report if regeneration fails
        if not session.report_path or not Path(session.report_path).exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found")

    return FileResponse(
        session.report_path,
        media_type="application/pdf",
        filename=f"neuroshield_report_{session_id}.pdf",
    )


@router.post("/finding/{finding_id}/explain", response_model=FindingResponse)
def explain_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = db.get(ScanFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    # Check if user has access to this scan session
    session = db.get(ScanSession, finding.session_id)
    if not session or (session.user_id != current_user.id and current_user.role.value != "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this finding")

    # If already has explanation and it is not a fallback explanation, return it
    if finding.ai_explanation and not finding.ai_explanation.startswith("⚠️ AI Explanation"):
        return finding

    # Generate explanation
    ai = AIExplainer()
    if not ai.is_available:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="AI Explainer is not configured or available")

    try:
        explanation = ai.explain_finding(
            title=finding.title,
            finding_type=finding.finding_type.value,
            severity=finding.severity.value,
            cwe_id=finding.cwe_id,
            category=finding.category,
            file_path=finding.file_path,
            line_number=finding.line_number,
            description=finding.description,
            code_snippet=finding.code_snippet,
        )
        finding.ai_explanation = explanation.explanation
        finding.exploitation_scenario = explanation.exploitation_scenario
        finding.fix_snippet = explanation.fix_snippet
        db.commit()
        db.refresh(finding)

        # Regenerate report so that it is cached on disk too
        report_path = settings.reports_path / f"report_{session.id}.pdf"
        orchestrator.reporter.generate(session, session.findings, report_path)
        session.report_path = str(report_path)
        db.commit()

        return finding
    except Exception as e:
        logger.exception("Failed to generate AI explanation on-demand for finding %s", finding_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate explanation: {str(e)}",
        )


class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []

@router.post("/finding/{finding_id}/chat")
def chat_finding(
    finding_id: int,
    req: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = db.get(ScanFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    session = db.get(ScanSession, finding.session_id)
    if not session or (session.user_id != current_user.id and current_user.role.value != "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this finding")

    ai = AIExplainer()
    try:
        response_text = ai.chat_vulnerability(
            finding=finding,
            new_message=req.message,
            history=req.history
        )
        return {"message": response_text}
    except Exception as e:
        logger.exception("AI Chat failed for finding %s", finding_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to communicate with AI: {str(e)}"
        )


def _get_user_session(db: Session, session_id: int, user: User) -> ScanSession:
    session = db.get(ScanSession, session_id)
    if not session or (session.user_id != user.id and user.role.value != "admin"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan session not found")
    return session
