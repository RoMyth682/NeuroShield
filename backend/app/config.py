from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    secret_key: str = "dev-secret-change-in-production"
    database_url: str = "sqlite:///./neuroshield.db"
    max_upload_size_mb: int = 10
    upload_dir: str = "./uploads"
    reports_dir: str = "./reports"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def upload_path(self) -> Path:
        return Path(self.upload_dir)

    @property
    def reports_path(self) -> Path:
        return Path(self.reports_dir)


settings = Settings()
