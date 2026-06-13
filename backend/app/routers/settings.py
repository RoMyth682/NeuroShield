"""Settings router — read & update AI configuration at runtime (admin only)."""
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth import get_current_user
from app.config import settings
from app.models.user import User

router = APIRouter(prefix="/api/settings", tags=["settings"])

ENV_PATH = Path(__file__).resolve().parent.parent.parent / ".env"

# All available Groq models (free tier)
GROQ_MODELS = [
    {"id": "llama-3.1-8b-instant",         "name": "Llama 3.1 8B Instant (Fast)",          "provider": "groq"},
    {"id": "llama-3.3-70b-versatile",       "name": "Llama 3.3 70B Versatile (Smart)",      "provider": "groq"},
    {"id": "meta-llama/llama-4-scout-17b-16e-instruct", "name": "Llama 4 Scout 17B",       "provider": "groq"},
]

OPENAI_MODELS = [
    {"id": "gpt-4o-mini",   "name": "GPT-4o Mini (Fast & cheap)",    "provider": "openai"},
    {"id": "gpt-4o",        "name": "GPT-4o (Most capable)",         "provider": "openai"},
    {"id": "gpt-4-turbo",   "name": "GPT-4 Turbo",                   "provider": "openai"},
    {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo (Cheapest)",      "provider": "openai"},
]

GEMINI_MODELS = [
    {"id": "gemini-2.5-flash", "name": "Gemini 2.5 Flash (Free)",    "provider": "gemini"},
    {"id": "gemini-3.5-flash", "name": "Gemini 3.5 Flash",           "provider": "gemini"},
    {"id": "gemini-2.5-pro",   "name": "Gemini 2.5 Pro",             "provider": "gemini"},
]


class AISettingsResponse(BaseModel):
    groq_api_key: str          # masked
    openai_api_key: str        # masked
    gemini_api_key: str        # masked
    active_provider: str       # "groq" | "openai" | "gemini" | "none"
    active_model: str
    groq_models: list
    openai_models: list
    gemini_models: list


class AISettingsPatch(BaseModel):
    groq_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    groq_model: Optional[str] = None
    openai_model: Optional[str] = None
    gemini_model: Optional[str] = None
    active_provider: Optional[str] = None


def _mask(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]


def _active_provider() -> str:
    if settings.active_provider in ("groq", "openai", "gemini"):
        if settings.active_provider == "groq" and settings.groq_api_key:
            return "groq"
        if settings.active_provider == "gemini" and settings.gemini_api_key:
            return "gemini"
        if settings.active_provider == "openai" and settings.openai_api_key:
            return "openai"

    if settings.groq_api_key:
        return "groq"
    if settings.gemini_api_key:
        return "gemini"
    if settings.openai_api_key:
        return "openai"
    return "none"


def _active_model() -> str:
    provider = _active_provider()
    if provider == "groq":
        return settings.groq_model or "llama-3.1-8b-instant"
    if provider == "openai":
        return settings.openai_model
    if provider == "gemini":
        return settings.gemini_model or "gemini-2.5-flash"
    return "none"


def _read_env_key(key: str) -> str:
    """Read a single key from the .env file without reloading entire app."""
    if not ENV_PATH.exists():
        return ""
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line[len(key) + 1:]
    return ""


def _write_env_keys(updates: dict[str, str]) -> None:
    """Update specific keys in the .env file, adding them if absent."""
    if not ENV_PATH.exists():
        ENV_PATH.write_text("", encoding="utf-8")
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()

    updated_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        written = False
        for key, value in updates.items():
            if stripped.startswith(f"{key}=") or stripped == key:
                new_lines.append(f"{key}={value}")
                updated_keys.add(key)
                written = True
                break
        if not written:
            new_lines.append(line)

    # Append any keys that weren't already in the file
    for key, value in updates.items():
        if key not in updated_keys:
            new_lines.append(f"{key}={value}")

    ENV_PATH.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def _require_admin(user: User) -> User:
    if user.role.value != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return user


@router.get("", response_model=AISettingsResponse)
def get_settings(current_user: User = Depends(get_current_user)):
    _require_admin(current_user)
    return AISettingsResponse(
        groq_api_key=_mask(settings.groq_api_key),
        openai_api_key=_mask(settings.openai_api_key),
        gemini_api_key=_mask(settings.gemini_api_key),
        active_provider=_active_provider(),
        active_model=_active_model(),
        groq_models=GROQ_MODELS,
        openai_models=OPENAI_MODELS,
        gemini_models=GEMINI_MODELS,
    )


@router.patch("", response_model=AISettingsResponse)
def update_settings(
    patch: AISettingsPatch,
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    env_updates: dict[str, str] = {}

    if patch.groq_api_key is not None:
        env_updates["GROQ_API_KEY"] = patch.groq_api_key
        settings.groq_api_key = patch.groq_api_key

    if patch.openai_api_key is not None:
        env_updates["OPENAI_API_KEY"] = patch.openai_api_key
        settings.openai_api_key = patch.openai_api_key

    if patch.gemini_api_key is not None:
        env_updates["GEMINI_API_KEY"] = patch.gemini_api_key
        settings.gemini_api_key = patch.gemini_api_key

    if patch.groq_model is not None:
        env_updates["GROQ_MODEL"] = patch.groq_model
        settings.groq_model = patch.groq_model

    if patch.openai_model is not None:
        env_updates["OPENAI_MODEL"] = patch.openai_model
        settings.openai_model = patch.openai_model

    if patch.gemini_model is not None:
        env_updates["GEMINI_MODEL"] = patch.gemini_model
        settings.gemini_model = patch.gemini_model

    if patch.active_provider is not None:
        env_updates["ACTIVE_PROVIDER"] = patch.active_provider
        settings.active_provider = patch.active_provider

    if env_updates:
        _write_env_keys(env_updates)

    return AISettingsResponse(
        groq_api_key=_mask(settings.groq_api_key),
        openai_api_key=_mask(settings.openai_api_key),
        gemini_api_key=_mask(settings.gemini_api_key),
        active_provider=_active_provider(),
        active_model=_active_model(),
        groq_models=GROQ_MODELS,
        openai_models=OPENAI_MODELS,
        gemini_models=GEMINI_MODELS,
    )
