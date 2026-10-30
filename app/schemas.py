"""Schémas Pydantic : validation des formulaires et sérialisation de l'API JSON."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import CheckStatus, LogSource, LogStatus

_EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=128)


class CnamCredentialIn(BaseModel):
    """Mot de passe et PIN vides = conserver les valeurs déjà enregistrées."""

    cnam_username: str = Field(min_length=3, max_length=255, pattern=_EMAIL_PATTERN)
    cnam_password: str | None = Field(default=None, max_length=256)
    cnam_pin: str | None = Field(default=None, pattern=r"^\d{4,8}$")
    check_interval_minutes: int = Field(default=5, ge=2, le=60)
    outlook_folder: str = Field(default="Emargements", min_length=1, max_length=100)

    @field_validator("cnam_password", "cnam_pin", mode="before")
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("cnam_username", "outlook_folder")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


DISCORD_WEBHOOK_PREFIXES = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
    "https://ptb.discord.com/api/webhooks/",
    "https://canary.discord.com/api/webhooks/",
)


class NotificationSettingsIn(BaseModel):
    notify_on_success: bool = False
    notify_on_failure: bool = False
    discord_notify_on_success: bool = False
    discord_notify_on_failure: bool = False
    discord_mention_on_success: bool = False
    discord_mention_on_failure: bool = False
    discord_webhook_url: str | None = Field(default=None, max_length=300)  # vide = inchangé
    clear_discord_webhook: bool = False
    discord_user_id: str | None = Field(default=None, pattern=r"^\d{17,20}$")  # « snowflake » Discord
    student_name: str | None = Field(default=None, max_length=100)

    @field_validator("discord_webhook_url", "discord_user_id", "student_name", mode="before")
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        return (value or "").strip() or None

    @field_validator("discord_webhook_url")
    @classmethod
    def _check_webhook(cls, value: str | None) -> str | None:
        # Liste blanche stricte : le serveur ne doit pas pouvoir joindre une URL arbitraire (SSRF).
        if value and not value.startswith(DISCORD_WEBHOOK_PREFIXES):
            raise ValueError("URL de webhook Discord invalide (https://discord.com/api/webhooks/...)")
        return value


class StatusOut(BaseModel):
    configured: bool
    auto_sign_enabled: bool = False
    busy: bool = False
    last_check_at: datetime | None = None
    last_status: CheckStatus = CheckStatus.NEVER
    last_message: str | None = None
    pending_code: str | None = None
    pending_attempts: int = 0


class SignatureLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    status: LogStatus
    source: LogSource
    session_code: str | None
    course_name: str | None
    message: str
