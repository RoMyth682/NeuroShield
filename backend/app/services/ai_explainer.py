import json
from dataclasses import dataclass
from pathlib import Path

from openai import OpenAI

from app.config import settings

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "vulnerability_explanation.txt"
OWASP_FALLBACK_URL = "https://owasp.org/www-project-top-ten/"


@dataclass
class AIExplanation:
    explanation: str
    exploitation_scenario: str
    fix_snippet: str
    from_ai: bool = True


class AIExplainer:
    def __init__(self) -> None:
        self.client = OpenAI(api_key=settings.openai_api_key) if settings.openai_api_key else None
        self.prompt_template = PROMPT_PATH.read_text(encoding="utf-8") if PROMPT_PATH.exists() else ""

    @property
    def is_available(self) -> bool:
        return bool(settings.openai_api_key and self.client)

    def explain_finding(
        self,
        *,
        title: str,
        finding_type: str,
        severity: str,
        cwe_id: str | None,
        category: str | None,
        file_path: str | None,
        line_number: int | None,
        description: str | None,
        code_snippet: str | None,
    ) -> AIExplanation:
        if not self.is_available:
            return self._fallback(title, description)

        prompt = self.prompt_template.format(
            title=title,
            finding_type=finding_type,
            severity=severity,
            cwe_id=cwe_id or "N/A",
            category=category or "OWASP Top 10",
            file_path=file_path or "N/A",
            line_number=line_number or "N/A",
            description=description or title,
            code_snippet=code_snippet or "Not available",
        )

        try:
            response = self.client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=800,
                timeout=8.0,
            )
            content = response.choices[0].message.content or "{}"
            content = content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[-1].rsplit("```", 1)[0]
            data = json.loads(content)
            return AIExplanation(
                explanation=data.get("explanation", ""),
                exploitation_scenario=data.get("exploitation_scenario", ""),
                fix_snippet=data.get("fix_snippet", ""),
                from_ai=True,
            )
        except Exception:
            return self._fallback(title, description)

    def _fallback(self, title: str, description: str | None) -> AIExplanation:
        return AIExplanation(
            explanation=description or f"Security issue detected: {title}",
            exploitation_scenario=(
                "An attacker could exploit this vulnerability to compromise confidentiality, "
                "integrity, or availability of the application."
            ),
            fix_snippet="Review OWASP secure coding guidelines and apply the recommended remediation.",
            from_ai=False,
        )

    def get_fallback_notice(self) -> str:
        return (
            f"AI explanations are temporarily unavailable. "
            f"Refer to OWASP documentation: {OWASP_FALLBACK_URL}"
        )
