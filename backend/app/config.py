from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # --- Core ---
    app_name: str = "NeuroShield API"
    app_description: str = "Autonomous Code Security Intelligence Engine"
    app_version: str = "1.0.0"
    secret_key: str = "dev-secret-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24
    database_url: str = "sqlite:///./neuroshield.db"

    # --- Admin seed ---
    admin_email: str = "admin@neuroshield.local"
    admin_password: str = "admin123"

    # --- CORS ---
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Upload ---
    max_upload_size_mb: int = 10
    upload_dir: str = "./uploads"
    reports_dir: str = "./reports"

    # --- OpenAI / AI ---
    openai_api_key: str = ""
    gemini_api_key: str = ""
    groq_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    groq_model: str = "llama-3.1-8b-instant"
    ai_temperature: float = 0.2
    ai_max_tokens: int = 800
    ai_timeout: float = 8.0
    ai_auto_explain_count: int = 3
    ai_max_workers: int = 5
    owasp_fallback_url: str = "https://owasp.org/www-project-top-ten/"

    # --- SAST Scanner ---
    bandit_timeout: int = 25
    semgrep_timeout: int = 60
    semgrep_default_config: str = "p/security-audit"

    # --- CVE Scanner ---
    osv_api_url: str = "https://api.osv.dev/v1/query"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_http_timeout: float = 15.0
    cve_max_packages: int = 50
    cve_description_max_length: int = 500

    # --- Admin ---
    admin_scan_list_limit: int = 50

    # --- Preview ---
    preview_file_limit: int = 100

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def upload_path(self) -> Path:
        return Path(self.upload_dir)

    @property
    def reports_path(self) -> Path:
        return Path(self.reports_dir)

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
