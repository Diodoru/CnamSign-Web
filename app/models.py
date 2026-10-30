"""Modèles SQLAlchemy. Les horodatages sont stockés en UTC « naïf »."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, false, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class LogStatus(str, enum.Enum):
    """Statut d'une entrée d'historique (événement notable uniquement)."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class LogSource(str, enum.Enum):
    AUTO = "AUTO"  # planificateur
    MANUAL = "MANUAL"  # bouton « Vérifier maintenant »


class CheckStatus(str, enum.Enum):
    """Résultat de la dernière vérification (affiché en temps réel)."""

    NEVER = "NEVER"
    NO_SIGNATURE = "NO_SIGNATURE"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    RETRYING = "RETRYING"  # code trouvé, signature échouée, nouvelle tentative au prochain cycle
    ERROR = "ERROR"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    credential: Mapped[CnamCredential | None] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    notification: Mapped[NotificationSetting | None] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    logs: Mapped[list[SignatureLog]] = relationship(back_populates="user", cascade="all, delete-orphan")


class CnamCredential(Base):
    """Identifiants Le Cnam d'un utilisateur, chiffrés au repos (Fernet)."""

    __tablename__ = "cnam_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)

    encrypted_cnam_username: Mapped[str] = mapped_column(Text)
    encrypted_cnam_password: Mapped[str] = mapped_column(Text)
    encrypted_cnam_pin: Mapped[str] = mapped_column(Text)  # PIN du clavier virtuel CnamSignE
    outlook_folder: Mapped[str] = mapped_column(String(100), default="Emargements")

    auto_sign_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    check_interval_minutes: Mapped[int] = mapped_column(Integer, default=5)

    last_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[CheckStatus] = mapped_column(
        Enum(CheckStatus, native_enum=False, length=20), default=CheckStatus.NEVER
    )
    last_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Code de session détecté par e-mail mais pas encore signé avec succès (retenté).
    pending_code: Mapped[str | None] = mapped_column(String(6), nullable=True)
    pending_email_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    pending_attempts: Mapped[int] = mapped_column(Integer, default=0)

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    user: Mapped[User] = relationship(back_populates="credential")


class SignatureLog(Base):
    __tablename__ = "signature_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    status: Mapped[LogStatus] = mapped_column(Enum(LogStatus, native_enum=False, length=20))
    source: Mapped[LogSource] = mapped_column(Enum(LogSource, native_enum=False, length=10))
    session_code: Mapped[str | None] = mapped_column(String(6), nullable=True)
    course_name: Mapped[str | None] = mapped_column(String(255), nullable=True)  # extrait du mail par l'upstream
    message: Mapped[str] = mapped_column(Text, default="")

    user: Mapped[User] = relationship(back_populates="logs")


class NotificationSetting(Base):
    __tablename__ = "notification_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)

    # Les e-mails partent vers l'adresse Le Cnam de l'utilisateur (CnamCredential).
    notify_on_success: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_failure: Mapped[bool] = mapped_column(Boolean, default=True)

    # Discord : l'URL du webhook suffit pour poster dans le salon, elle est donc chiffrée.
    # server_default : nécessaire pour ajouter la colonne NOT NULL à une base existante.
    encrypted_discord_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    discord_notify_on_success: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    discord_notify_on_failure: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Mention <@discord_user_id> dans le message, réglable par type d'événement.
    discord_user_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    discord_mention_on_success: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    discord_mention_on_failure: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    student_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    user: Mapped[User] = relationship(back_populates="notification")
