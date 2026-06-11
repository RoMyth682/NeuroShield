from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models.scan import FindingType, ScanFinding, ScanSession, Severity


class ReportGenerator:
    SEVERITY_COLORS = {
        Severity.CRITICAL: colors.HexColor("#dc2626"),
        Severity.HIGH: colors.HexColor("#ea580c"),
        Severity.MEDIUM: colors.HexColor("#ca8a04"),
        Severity.LOW: colors.HexColor("#16a34a"),
    }

    def generate(self, session: ScanSession, findings: list[ScanFinding], output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(str(output_path), pagesize=A4, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Title"], alignment=TA_CENTER, fontSize=22, spaceAfter=20)
        heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=14, spaceBefore=16, spaceAfter=8)
        body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14)

        story = [
            Paragraph("NeuroShield Security Assessment Report", title_style),
            Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body_style),
            Paragraph(f"Scan ID: {session.id} | File: {session.original_filename}", body_style),
            Spacer(1, 0.25 * inch),
        ]

        summary = self._severity_counts(findings)
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(
            Paragraph(
                f"This report presents the results of an automated security analysis. "
                f"A total of <b>{summary['total']}</b> findings were identified: "
                f"<font color='#dc2626'>{summary['critical']} Critical</font>, "
                f"<font color='#ea580c'>{summary['high']} High</font>, "
                f"<font color='#ca8a04'>{summary['medium']} Medium</font>, "
                f"<font color='#16a34a'>{summary['low']} Low</font>.",
                body_style,
            )
        )
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Vulnerability Summary Table", heading_style))
        table_data = [["#", "Title", "Severity", "Type", "Location"]]
        for idx, f in enumerate(findings, 1):
            loc = f.file_path or f.package_name or "N/A"
            if f.line_number:
                loc += f":{f.line_number}"
            table_data.append([str(idx), f.title[:40], f.severity.value.upper(), f.finding_type.value.upper(), loc[:35]])

        if len(table_data) > 1:
            table = Table(table_data, colWidths=[0.4 * inch, 2.2 * inch, 0.8 * inch, 0.7 * inch, 1.8 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ]
                )
            )
            story.append(table)
        else:
            story.append(Paragraph("No vulnerabilities detected.", body_style))

        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Detailed Findings", heading_style))

        for idx, finding in enumerate(findings, 1):
            color = self.SEVERITY_COLORS.get(finding.severity, colors.black)
            story.append(
                Paragraph(
                    f"<b>{idx}. {finding.title}</b> "
                    f"[<font color='{color.hexval()}'>{finding.severity.value.upper()}</font>]",
                    body_style,
                )
            )
            if finding.finding_type == FindingType.SAST:
                story.append(Paragraph(f"<b>File:</b> {finding.file_path or 'N/A'} (line {finding.line_number or 'N/A'})", body_style))
                if finding.cwe_id:
                    story.append(Paragraph(f"<b>CWE:</b> {finding.cwe_id}", body_style))
            else:
                story.append(
                    Paragraph(
                        f"<b>Package:</b> {finding.package_name}@{finding.package_version} | <b>CVE:</b> {finding.cve_id}",
                        body_style,
                    )
                )
            if finding.ai_explanation:
                story.append(Paragraph(f"<b>Explanation:</b> {finding.ai_explanation}", body_style))
            if finding.exploitation_scenario:
                story.append(Paragraph(f"<b>Exploitation Scenario:</b> {finding.exploitation_scenario}", body_style))
            if finding.fix_snippet:
                story.append(Paragraph(f"<b>Recommended Fix:</b><br/><pre>{finding.fix_snippet}</pre>", body_style))
            story.append(Spacer(1, 0.15 * inch))

        cve_findings = [f for f in findings if f.finding_type == FindingType.CVE]
        if cve_findings:
            story.append(Paragraph("CVE Dependency Findings", heading_style))
            for f in cve_findings:
                story.append(
                    Paragraph(
                        f"• {f.cve_id}: {f.package_name}@{f.package_version} "
                        f"(CVSS: {f.cvss_score or 'N/A'}) — {f.description or ''}",
                        body_style,
                    )
                )

        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Risk Summary", heading_style))
        risk_level = "LOW"
        if summary["critical"] > 0:
            risk_level = "CRITICAL"
        elif summary["high"] > 0:
            risk_level = "HIGH"
        elif summary["medium"] > 0:
            risk_level = "MEDIUM"
        story.append(Paragraph(f"Overall Risk Level: <b>{risk_level}</b>", body_style))

        doc.build(story)
        return output_path

    def _severity_counts(self, findings: list[ScanFinding]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
        for f in findings:
            counts[f.severity.value] += 1
        return counts
