"""Configuration centralisée, lue depuis l'environnement (et un fichier `.env` optionnel).

Les secrets peuvent être fournis directement (`SECRET_KEY`, `SECRET_ENCRYPTION_KEY`)
ou via un fichier (`SECRET_KEY_FILE`, `SECRET_ENCRYPTION_KEY_FILE`), ce qui permet
d'utiliser les *secrets* Docker Compose sans exposer les clés dans l'environnement.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


def _read_secret_file(path: str | None) -> str | None:
    """Lit un secret depuis un fichier (format Docker secrets)."""
    if not path:
        return None
    secret_path = Path(path)
    if not secret_path.is_file():
        raise ValueError(f"Fichier secret introuvable : {path}")
    return secret_path.read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Application -------------------------------------------------------
    app_name: str = "CnamSign Web"
    app_base_url: str = "http://localhost:8000"  # utilisé dans les liens des notifications
    allow_registration: bool = True  # le tout premier compte peut toujours être créé (admin)
    session_cookie_secure: bool = False  # True derrière HTTPS
    session_max_age_hours: int = 12

    # --- Secrets -----------------------------------------------------------
    secret_key: str = ""
    secret_key_file: str | None = None
    # Une ou plusieurs clés Fernet séparées par des virgules (rotation : la 1re chiffre).
    secret_encryption_key: str = ""
    secret_encryption_key_file: str | None = None

    # --- Stockage ----------------------------------------------------------
    database_url: str = f"sqlite:///{(BASE_DIR / 'data' / 'cnamsign.db').as_posix()}"
    data_dir: Path = BASE_DIR / "data"  # profils navigateur et captures par utilisateur
    cnamsign_path: Path = BASE_DIR / "vendor" / "CnamSign"  # code upstream (non forké)
    screenshot_retention_days: int = 7

    # --- Planificateur -----------------------------------------------------
    scheduler_enabled: bool = True
    schedule_day_of_week: str = "mon-sat"
    schedule_hour: str = "8-19"  # 8h00 → 19h59
    timezone: str = "Europe/Paris"
    default_check_interval_minutes: int = Field(default=5, ge=2, le=60)
    max_concurrent_jobs: int = Field(default=1, ge=1, le=8)  # 1 Chromium ≈ 300-500 Mo de RAM
    job_timeout_seconds: int = 240
    max_sign_retries: int = 3
    headless: bool = True
    default_outlook_folder: str = "Emargements"

    # --- Notifications e-mail ---------------------------------------------------
    # Relais SMTP global. S'il n'est pas configuré, chaque utilisateur s'envoie le mail
    # à lui-même via smtp.office365.com avec son compte Le Cnam (voir notifier.py).
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_use_tls: bool = True  # STARTTLS (le port 465 utilise toujours SSL implicite)
    smtp_fallback_host: str = "smtp.office365.com"
    smtp_fallback_port: int = 587

    @model_validator(mode="after")
    def _load_and_check_secrets(self) -> "Settings":
        self.secret_key = _read_secret_file(self.secret_key_file) or self.secret_key
        self.secret_encryption_key = (
            _read_secret_file(self.secret_encryption_key_file) or self.secret_encryption_key
        )
        if len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY manquante ou trop courte (32 caractères minimum).")
        if not self.secret_encryption_key:
            raise ValueError("SECRET_ENCRYPTION_KEY manquante (voir README : génération de la clé Fernet).")
        return self

    @property
    def smtp_configured(self) -> bool:
        """True si un relais SMTP global est défini (sinon : repli Office 365 par utilisateur)."""
        return bool(self.smtp_host)


@lru_cache
def get_settings() -> Settings:
    return Settings()
