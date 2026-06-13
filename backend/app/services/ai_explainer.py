import json
import re
import httpx
from dataclasses import dataclass
from pathlib import Path
from openai import OpenAI
from app.config import settings

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "vulnerability_explanation.txt"
ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"


def _read_env_key(key: str, default: str = "") -> str:
    """Read a single key from .env without reloading the whole app."""
    if not ENV_PATH.exists():
        return default
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line[len(key) + 1:]
    return default


def _clean_json(text: str) -> str:
    """Strip markdown fences and ASCII control characters before JSON parsing."""
    text = text.strip()
    # Remove ```json ... ``` fences
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    # Remove ASCII control chars (0x00-0x1F) except tab/newline/cr
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text.strip()


@dataclass
class AIExplanation:
    explanation: str
    exploitation_scenario: str
    fix_snippet: str
    from_ai: bool = True


class AIExplainer:
    def __init__(self) -> None:
        self.prompt_template = PROMPT_PATH.read_text(encoding="utf-8") if PROMPT_PATH.exists() else ""
        self._setup_client()

    def _resolve_active_provider(self) -> str:
        if settings.active_provider in ("groq", "openai", "gemini"):
            if settings.active_provider == "groq" and settings.groq_api_key:
                return "groq"
            if settings.active_provider == "gemini" and settings.gemini_api_key:
                return "gemini"
            if settings.active_provider == "openai" and settings.openai_api_key:
                return "openai"

        # fallback to priority
        if settings.groq_api_key:
            return "groq"
        if settings.gemini_api_key:
            return "gemini"
        if settings.openai_api_key:
            return "openai"
        return "none"

    def _setup_client(self) -> None:
        self.client = None
        self.gemini_model = settings.gemini_model or "gemini-2.5-flash"
        
        active = self._resolve_active_provider()
        if active == "groq":
            self.client = OpenAI(
                api_key=settings.groq_api_key,
                base_url="https://api.groq.com/openai/v1"
            )
            self.model = settings.groq_model or "llama-3.1-8b-instant"
        elif active == "openai":
            self.client = OpenAI(api_key=settings.openai_api_key)
            self.model = settings.openai_model
        else:
            self.model = "none"

    @property
    def is_available(self) -> bool:
        return bool(settings.openai_api_key or settings.gemini_api_key or settings.groq_api_key)

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
        self._setup_client()
        if self._resolve_active_provider() == "gemini":
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
            return self._explain_with_gemini(prompt)

        if not self.is_available:
            return self._fallback(title, description, "AI Explainer is not configured (missing API key in .env)")

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
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=settings.ai_temperature,
                max_tokens=settings.ai_max_tokens,
                timeout=settings.ai_timeout,
            )
            content = response.choices[0].message.content or "{}"
            content = _clean_json(content)
            data = json.loads(content)
            return AIExplanation(
                explanation=data.get("explanation", ""),
                exploitation_scenario=data.get("exploitation_scenario", ""),
                fix_snippet=data.get("fix_snippet", ""),
                from_ai=True,
            )
        except Exception as e:
            return self._fallback(title, description, f"{type(e).__name__}: {str(e)}")

    def _explain_with_gemini(self, prompt: str) -> AIExplanation:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={settings.gemini_api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }
        try:
            r = httpx.post(url, headers=headers, json=payload, timeout=settings.ai_timeout)
            r.raise_for_status()
            data = r.json()
            content = data["candidates"][0]["content"]["parts"][0]["text"]
            content = _clean_json(content)
            parsed = json.loads(content)
            return AIExplanation(
                explanation=parsed.get("explanation", ""),
                exploitation_scenario=parsed.get("exploitation_scenario", ""),
                fix_snippet=parsed.get("fix_snippet", ""),
                from_ai=True,
            )
        except Exception as e:
            return self._fallback("Gemini Call", f"Failed calling Gemini API: {str(e)}")

    def chat_vulnerability(
        self,
        *,
        finding,
        new_message: str,
        history: list,
    ) -> str:
        self._setup_client()
        context = (
            f"Vulnerability Title: {finding.title}\n"
            f"Severity: {finding.severity.value}\n"
            f"File Path: {finding.file_path or 'N/A'}\n"
            f"Line Number: {finding.line_number or 'N/A'}\n"
            f"Category: {finding.category or 'N/A'}\n"
            f"Description: {finding.description}\n"
            f"Code Snippet:\n{finding.code_snippet or 'Not available'}\n"
        )
        
        system_instruction = (
            f"You are a helpful security assistant for NeuroShield. The user is asking a question about "
            f"the following scanned vulnerability:\n\n{context}\n"
            f"Provide concise, accurate, and developer-friendly advice. Keep it actionable and relatively short."
        )

        messages = [{"role": "system", "content": system_instruction}]
        for msg in history:
            role = msg.role if hasattr(msg, "role") else msg.get("role")
            content = msg.content if hasattr(msg, "content") else msg.get("content")
            messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": new_message})

        if self._resolve_active_provider() == "gemini":
            return self._chat_with_gemini(messages)
        elif self.client:
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0.7,
                    max_tokens=600,
                    timeout=12.0,
                )
                return response.choices[0].message.content or "No response from AI."
            except Exception as e:
                return f"AI Chat failed: {type(e).__name__}: {str(e)}"
        else:
            return "AI Explainer is not configured. Add GEMINI_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY in .env."

    def _chat_with_gemini(self, messages: list) -> str:
        contents = []
        for msg in messages:
            role = msg["role"]
            if role == "system":
                contents.append({
                    "role": "user",
                    "parts": [{"text": f"[System Instruction] {msg['content']}"}]
                })
            else:
                contents.append({
                    "role": "model" if role == "assistant" else "user",
                    "parts": [{"text": msg["content"]}]
                })
        
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={settings.gemini_api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {"contents": contents}
            
            r = httpx.post(url, headers=headers, json=payload, timeout=15.0)
            r.raise_for_status()
            data = r.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            return f"Gemini API chat failed: {str(e)}"

    def _fallback(self, title: str, description: str | None, error_detail: str | None = None) -> AIExplanation:
        notice = ""
        # Check both description and error_detail for auth/token/quota/key problems
        check_text = (error_detail or "") + " " + (description or "")
        lower_err = check_text.lower()
        
        if any(word in lower_err for word in ["expire", "unauthorized", "401", "429", "quota", "token", "limit", "invalid", "credential", "key"]):
            notice = "⚠️ AI Explanation failed: API key has expired, is invalid, or free usage tokens/quota have been exhausted. Please configure a valid API key in settings.\n\n"
        elif error_detail:
            notice = f"⚠️ AI Explanation generation failed ({error_detail}). Showing static fallback guidance.\n\n"
        else:
            notice = "⚠️ AI Explanation temporarily unavailable. Showing static fallback guidance.\n\n"

        return AIExplanation(
            explanation=notice + (description or f"Security issue detected: {title}"),
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
            f"Refer to OWASP documentation: {settings.owasp_fallback_url}"
        )
