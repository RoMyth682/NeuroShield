import json
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.models.scan import FindingType, ScanFinding, ScanSession, ScanStatus, Severity
from app.services.ai_explainer import AIExplainer
from app.services.cve_scanner import CVEScanner
from app.services.report_generator import ReportGenerator
from app.services.sast_scanner import SASTScanner

ALLOWED_EXTENSIONS = {".zip"}  # keep zip explicitly allowed; individual file types are accepted

# Filenames without suffix that are commonly used as source/configuration
SPECIAL_FILENAMES = {"Dockerfile", "Makefile", "pom.xml", "build.gradle", "requirements.txt", "package.json", "Gemfile", "Procfile"}


class ScanOrchestrator:
    def __init__(self) -> None:
        self.sast = SASTScanner()
        self.cve = CVEScanner()
        self.ai = AIExplainer()
        self.reporter = ReportGenerator()

    def extract_upload(self, upload_path: Path, dest: Path) -> list[str]:
        dest.mkdir(parents=True, exist_ok=True)
        files: list[str] = []

        if upload_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(upload_path, "r") as zf:
                for member in zf.namelist():
                    if member.endswith("/") or ".." in member:
                        continue
                    zf.extract(member, dest)
                    files.append(member)
        else:
            target = dest / upload_path.name
            shutil.copy2(upload_path, target)
            files.append(upload_path.name)

        return files

    def list_source_files(self, root: Path) -> list[str]:
        files: list[str] = []
        for p in root.rglob("**/*"):
            if not p.is_file():
                continue
            suffix = p.suffix.lower()
            name = p.name
            if suffix in SASTScanner.SUPPORTED_EXTENSIONS or name in SPECIAL_FILENAMES:
                try:
                    files.append(str(p.relative_to(root)))
                except Exception:
                    files.append(str(p))
        return files

    def run_analysis(self, db: Session, session: ScanSession) -> ScanSession:
        upload_path = Path(session.upload_path)
        if upload_path.suffix.lower() == ".zip":
            work_dir = upload_path.parent / "extracted"
            if work_dir.exists():
                shutil.rmtree(work_dir)
            work_dir.mkdir(parents=True)
            self.extract_upload(upload_path, work_dir)
            scan_root = work_dir
        else:
            scan_root = upload_path.parent

        try:
            session.status = ScanStatus.SAST_RUNNING
            db.commit()
            sast_result = self.sast.scan_directory(scan_root)

            session.status = ScanStatus.CVE_RUNNING
            db.commit()
            cve_result = self.cve.scan_directory(scan_root)

            warnings = sast_result.errors + cve_result.errors
            # check whether any supported source files exist in the upload
            has_supported = any(
                (p.suffix.lower() in SASTScanner.SUPPORTED_EXTENSIONS) or (p.name in SPECIAL_FILENAMES)
                for p in scan_root.rglob("**/*")
                if p.is_file()
            )
            if not sast_result.findings and not has_supported:
                warnings.append(
                    "No supported source files found in upload. Upload source files or a ZIP containing supported source files."
                )
            session.scan_warnings = json.dumps(warnings) if warnings else None

            findings: list[ScanFinding] = []
            for item in sast_result.findings:
                findings.append(
                    ScanFinding(
                        session_id=session.id,
                        finding_type=FindingType.SAST,
                        title=item.title,
                        file_path=item.file_path,
                        line_number=item.line_number,
                        severity=item.severity,
                        cwe_id=item.cwe_id,
                        category=item.category,
                        description=item.description,
                        code_snippet=item.code_snippet,
                    )
                )

            for item in cve_result.findings:
                findings.append(
                    ScanFinding(
                        session_id=session.id,
                        finding_type=FindingType.CVE,
                        title=f"{item.cve_id} in {item.package_name}",
                        severity=item.severity,
                        description=item.description,
                        cvss_score=item.cvss_score,
                        cve_id=item.cve_id,
                        package_name=item.package_name,
                        package_version=item.package_version,
                        category="A06:2021-Vulnerable and Outdated Components",
                    )
                )

            db.add_all(findings)
            db.commit()

            session.status = ScanStatus.AI_RUNNING
            db.commit()

            ai_limit = 20
            findings_to_explain = findings[:ai_limit]

            from concurrent.futures import ThreadPoolExecutor

            # Extract plain dict of parameters for each finding to avoid cross-thread DB operations
            tasks = []
            for idx, finding in enumerate(findings_to_explain):
                tasks.append({
                    "index": idx,
                    "params": {
                        "title": finding.title,
                        "finding_type": finding.finding_type.value,
                        "severity": finding.severity.value,
                        "cwe_id": finding.cwe_id,
                        "category": finding.category,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "description": finding.description,
                        "code_snippet": finding.code_snippet,
                    }
                })

            def explain_one(task):
                try:
                    explanation = self.ai.explain_finding(**task["params"])
                    return task["index"], explanation
                except Exception:
                    return task["index"], None

            max_workers = min(5, len(tasks)) if tasks else 1
            explanations_by_index = {}
            if tasks:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    results = executor.map(explain_one, tasks)
                    for idx, explanation in results:
                        if explanation:
                            explanations_by_index[idx] = explanation

            # Apply explanations to database objects in the main thread
            for idx, finding in enumerate(findings_to_explain):
                explanation = explanations_by_index.get(idx)
                if explanation:
                    finding.ai_explanation = explanation.explanation
                    finding.exploitation_scenario = explanation.exploitation_scenario
                    finding.fix_snippet = explanation.fix_snippet
            db.commit()

            report_path = settings.reports_path / f"report_{session.id}.pdf"
            self.reporter.generate(session, findings, report_path)
            session.report_path = str(report_path)
            session.status = ScanStatus.COMPLETED
            session.completed_at = datetime.utcnow()
            db.commit()

        except Exception as exc:
            session.status = ScanStatus.FAILED
            session.error_message = str(exc)
            db.commit()
            raise

        return session

    def cleanup_session_files(self, session: ScanSession) -> None:
        upload = Path(session.upload_path)
        parent = upload.parent
        if parent.exists():
            shutil.rmtree(parent, ignore_errors=True)
