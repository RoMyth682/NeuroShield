import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from app.config import settings
from app.models.scan import Severity
from app.services.risk_scoring import cvss_to_severity


@dataclass
class CVEFinding:
    cve_id: str
    package_name: str
    package_version: str
    severity: Severity
    cvss_score: float | None
    description: str
    ecosystem: str


@dataclass
class CVEResult:
    findings: list[CVEFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    packages_checked: int = 0


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str


class CVEScanner:
    def scan_directory(self, root: Path) -> CVEResult:
        result = CVEResult()
        dependencies = self._parse_dependencies(root)
        result.packages_checked = len(dependencies)

        if not dependencies:
            result.errors.append(
                "No dependency manifest files found — expected if you uploaded a single source file. "
                "For CVE scanning, include a requirements.txt, package.json, or pom.xml with your code."
            )
            return result

        with httpx.Client(timeout=settings.cve_http_timeout) as client:
            for dep in dependencies[:settings.cve_max_packages]:
                try:
                    findings = self._query_osv(client, dep)
                    if not findings:
                        findings = self._query_nvd(client, dep)
                    result.findings.extend(findings)
                except httpx.TimeoutException:
                    result.errors.append(f"CVE API timeout while checking {dep.name}")
                except httpx.HTTPError as exc:
                    result.errors.append(f"CVE API error for {dep.name}: {exc}")

        return result

    def _parse_dependencies(self, root: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        for req in root.rglob("requirements.txt"):
            deps.extend(self._parse_requirements(req))
        for pkg in root.rglob("package.json"):
            if "node_modules" in pkg.parts:
                continue
            deps.extend(self._parse_package_json(pkg))
        for pom in root.rglob("pom.xml"):
            deps.extend(self._parse_pom(pom))
        return deps

    def _parse_requirements(self, path: Path) -> list[Dependency]:
        deps = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([^\s;]+)", line)
            if match:
                deps.append(Dependency(name=match.group(1).lower(), version=match.group(2), ecosystem="PyPI"))
        return deps

    def _parse_package_json(self, path: Path) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies"):
                for name, version in data.get(section, {}).items():
                    clean = re.sub(r"^[\^~>=<]+", "", str(version))
                    if clean:
                        deps.append(Dependency(name=name, version=clean, ecosystem="npm"))
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_pom(self, path: Path) -> list[Dependency]:
        deps = []
        content = path.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(
            r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
            content,
        ):
            deps.append(Dependency(name=match.group(1), version=match.group(2), ecosystem="Maven"))
        return deps

    def _query_osv(self, client: httpx.Client, dep: Dependency) -> list[CVEFinding]:
        payload = {
            "package": {"name": dep.name, "ecosystem": dep.ecosystem},
            "version": dep.version,
        }
        response = client.post(settings.osv_api_url, json=payload)
        if response.status_code != 200:
            return []

        findings = []
        for vuln in response.json().get("vulns", []):
            cvss, score = self._extract_cvss(vuln)
            findings.append(
                CVEFinding(
                    cve_id=vuln.get("id", "UNKNOWN"),
                    package_name=dep.name,
                    package_version=dep.version,
                    severity=cvss_to_severity(score),
                    cvss_score=score,
                    description=vuln.get("summary", vuln.get("details", "Known vulnerability"))[:settings.cve_description_max_length],
                    ecosystem=dep.ecosystem,
                )
            )
        return findings

    def _query_nvd(self, client: httpx.Client, dep: Dependency) -> list[CVEFinding]:
        response = client.get(
            settings.nvd_api_url,
            params={"keywordSearch": f"{dep.name} {dep.version}", "resultsPerPage": 5},
        )
        if response.status_code != 200:
            return []

        findings = []
        for item in response.json().get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break
            descriptions = cve.get("descriptions", [{}])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "Known vulnerability")
            findings.append(
                CVEFinding(
                    cve_id=cve_id,
                    package_name=dep.name,
                    package_version=dep.version,
                    severity=cvss_to_severity(score),
                    cvss_score=score,
                    description=desc[:settings.cve_description_max_length],
                    ecosystem=dep.ecosystem,
                )
            )
        return findings

    def _extract_cvss(self, vuln: dict) -> tuple[Severity, float | None]:
        score = None
        for item in vuln.get("severity", []):
            if item.get("type") == "CVSS_V3":
                try:
                    score = float(item.get("score", 0))
                except (TypeError, ValueError):
                    pass
        return cvss_to_severity(score), score
