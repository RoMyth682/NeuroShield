import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings
from app.models.scan import Severity
from app.services.risk_scoring import bandit_to_severity, semgrep_to_severity

OWASP_CATEGORY_MAP = {
    "B608": "A03:2021-Injection",
    "B602": "A03:2021-Injection",
    "B701": "A08:2021-Software and Data Integrity Failures",
    "B506": "A05:2021-Security Misconfiguration",
    "B105": "A02:2021-Cryptographic Failures",
    "B303": "A02:2021-Cryptographic Failures",
    "B501": "B501",
    "B201": "A01:2021-Broken Access Control",
}


@dataclass
class SASTFinding:
    title: str
    file_path: str
    line_number: int | None
    severity: Severity
    cwe_id: str | None
    category: str | None
    description: str
    code_snippet: str | None = None
    source: str = "bandit"


@dataclass
class SASTResult:
    findings: list[SASTFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class SASTScanner:
    # Broaden supported extensions to cover many common languages and config files.
    SUPPORTED_EXTENSIONS = {
        ".py",
        ".js",
        ".java",
        ".ts",
        ".jsx",
        ".tsx",
        ".php",
        ".go",
        ".rb",
        ".cs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".sh",
        ".bash",
        ".ps1",
        ".gradle",
        ".kt",
        ".kts",
        ".dart",
        ".swift",
        ".rs",
        ".erl",
        ".ex",
    }

    def scan_directory(self, root: Path) -> SASTResult:
        result = SASTResult()
        python_files = [p for p in root.rglob("*") if p.suffix == ".py" and p.is_file()]

        if python_files:
            bandit_result = self._run_bandit(root)
            result.findings.extend(bandit_result.findings)
            result.errors.extend(bandit_result.errors)

        semgrep_result = self._run_semgrep(root)
        result.findings.extend(semgrep_result.findings)
        result.errors.extend(semgrep_result.errors)

        return result

    def _bandit_command(self, root: Path) -> list[str]:
        # Use the same Python as the running server so Bandit works on Windows
        # even when the bandit.exe Scripts folder is not on PATH.
        return [sys.executable, "-m", "bandit", "-r", str(root), "-f", "json", "-q", "--exit-zero"]

    def _run_bandit(self, root: Path) -> SASTResult:
        result = SASTResult()
        proc = None
        try:
            # NO_COLOR + PYTHONIOENCODING suppress the rich/terminal crash on Windows
            import os
            env = {**os.environ, "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8", "TERM": "dumb"}
            proc = subprocess.run(
                self._bandit_command(root),
                capture_output=True,
                text=True,
                timeout=settings.bandit_timeout,
                env=env,
            )
            output = proc.stdout.strip()
            stderr = (proc.stderr or "").strip()

            if not output and stderr:
                if "No module named 'bandit'" in stderr:
                    result.errors.append(
                        "Bandit is not installed. In backend folder run: pip install -r requirements.txt"
                    )
                elif "Traceback" in stderr or "KeyboardInterrupt" in stderr:
                    # Suppress full Python traceback — just note Bandit had an internal error
                    result.errors.append("Bandit encountered an internal error and was skipped. Semgrep results are still shown.")
                else:
                    # Cap to 300 chars to avoid flooding warnings
                    result.errors.append(stderr[:300])
                return result

            if output:
                data = json.loads(output)
                for item in data.get("results", []):
                    test_id = item.get("test_id", "")
                    result.findings.append(
                        SASTFinding(
                            title=item.get("test_name", "Security Issue"),
                            file_path=self._relative_path(root, item.get("filename", "")),
                            line_number=item.get("line_number"),
                            severity=bandit_to_severity(item.get("issue_severity", "MEDIUM")),
                            cwe_id=f"CWE-{item['issue_cwe']['id']}" if item.get("issue_cwe") else test_id,
                            category=OWASP_CATEGORY_MAP.get(test_id, "OWASP Top 10"),
                            description=item.get("issue_text", ""),
                            code_snippet=item.get("code", "").strip() or None,
                            source="bandit",
                        )
                    )
        except FileNotFoundError:
            result.errors.append(
                "Bandit is not installed. In backend folder run: pip install -r requirements.txt"
            )
        except json.JSONDecodeError as exc:
            result.errors.append(f"Failed to parse Bandit output: {exc}")
            if proc and proc.stderr and proc.stderr.strip():
                result.errors.append(proc.stderr.strip()[:300])
        except subprocess.TimeoutExpired:
            result.errors.append("Bandit scan timed out after 25 seconds")
        except KeyError as exc:
            result.errors.append(f"Unexpected Bandit result format: {exc}")
        return result

    def _semgrep_exe(self) -> str:
        """Return the semgrep executable inside the same venv as this Python."""
        scripts_dir = Path(sys.executable).parent
        # Windows: semgrep.exe  /  Unix: semgrep
        for name in ("semgrep.exe", "semgrep"):
            candidate = scripts_dir / name
            if candidate.exists():
                return str(candidate)
        return "semgrep"  # fall back to PATH

    def _run_semgrep(self, root: Path) -> SASTResult:
        result = SASTResult()
        rules_dir = Path(__file__).resolve().parent.parent / "rules"
        expanded_config = rules_dir / "expanded-semgrep.yaml"
        default_config = rules_dir / "owasp-semgrep.yaml"
        if expanded_config.exists():
            config = str(expanded_config)
        elif default_config.exists():
            config = str(default_config)
        else:
            config = settings.semgrep_default_config

        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                output_file = tmp.name

            proc = subprocess.run(
                [
                    self._semgrep_exe(),
                    "--config",
                    config,
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    "--output",
                    output_file,
                    str(root),
                ],
                capture_output=True,
                text=True,
                timeout=settings.semgrep_timeout,
            )
            output_path = Path(output_file)

            if proc.returncode != 0 and (not output_path.exists() or output_path.stat().st_size == 0):
                stderr_msg = proc.stderr.strip()
                if stderr_msg:
                    result.errors.append(f"Semgrep execution error: {stderr_msg[:300]}")
                else:
                    result.errors.append(f"Semgrep exited with code {proc.returncode}")

            if output_path.exists() and output_path.stat().st_size > 0:
                data = json.loads(output_path.read_text(encoding="utf-8"))
                for item in data.get("results", []):
                    extra = item.get("extra", {})
                    metadata = extra.get("metadata", {})
                    result.findings.append(
                        SASTFinding(
                            title=extra.get("message", item.get("check_id", "Semgrep Finding")),
                            file_path=self._relative_path(root, item.get("path", "")),
                            line_number=item.get("start", {}).get("line"),
                            severity=semgrep_to_severity(extra.get("severity", "WARNING")),
                            cwe_id=metadata.get("cwe", [None])[0] if metadata.get("cwe") else None,
                            category=metadata.get("owasp", ["OWASP Top 10"])[0]
                            if metadata.get("owasp")
                            else "OWASP Top 10",
                            description=extra.get("message", ""),
                            code_snippet=extra.get("lines", "").strip() or None,
                            source="semgrep",
                        )
                    )
            output_path.unlink(missing_ok=True)
        except FileNotFoundError:
            result.errors.append("Semgrep not found. In backend folder run: pip install -r requirements.txt")
        except subprocess.TimeoutExpired:
            result.errors.append("Semgrep scan timed out after 25 seconds")
        except (json.JSONDecodeError, OSError) as exc:
            result.errors.append(f"Semgrep scan issue: {exc}")
        return result

    def _relative_path(self, root: Path, file_path: str) -> str:
        try:
            return str(Path(file_path).resolve().relative_to(root.resolve()))
        except ValueError:
            return file_path
