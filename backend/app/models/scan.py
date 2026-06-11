import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    EXTRACTING = "extracting"
    SAST_RUNNING = "sast_running"
    CVE_RUNNING = "cve_running"
    AI_RUNNING = "ai_running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingType(str, enum.Enum):
    SAST = "sast"
    CVE = "cve"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    original_filename: Mapped[str] = mapped_column(String(512))
    upload_path: Mapped[str] = mapped_column(String(1024))
    report_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_warnings: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user = relationship("User", back_populates="scan_sessions")
    findings = relationship("ScanFinding", back_populates="session", cascade="all, delete-orphan")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"), nullable=False)
    finding_type: Mapped[FindingType] = mapped_column(Enum(FindingType))
    title: Mapped[str] = mapped_column(String(512))
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploitation_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    session = relationship("ScanSession", back_populates="findings")
