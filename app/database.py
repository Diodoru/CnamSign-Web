"""Configuration SQLAlchemy (SQLite par défaut, PostgreSQL possible via DATABASE_URL)."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.schema import CreateColumn

from app.config import get_settings

settings = get_settings()
_is_sqlite = settings.database_url.startswith("sqlite")

engine: Engine = create_engine(
    settings.database_url,
    # Les jobs APScheduler tournent dans d'autres threads que les requêtes web.
    connect_args={"check_same_thread": False, "timeout": 30} if _is_sqlite else {},
    pool_pre_ping=True,
)

if _is_sqlite:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record) -> None:  # pragma: no cover - trivial
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")  # lectures concurrentes pendant les écritures
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """Dépendance FastAPI : une session par requête."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Crée les répertoires et les tables manquantes."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if _is_sqlite and engine.url.database:
        Path(engine.url.database).parent.mkdir(parents=True, exist_ok=True)

    from app import models  # noqa: F401  (enregistre les modèles sur Base.metadata)

    Base.metadata.create_all(bind=engine)
    _migrate()


# Colonnes retirées des modèles (notifications Discord / e-mail libre).
_DROPPED_COLUMNS = {
    "notification_settings": ("encrypted_discord_webhook", "email_enabled", "email_to", "discord_enabled"),
}


def _migrate() -> None:
    """Migrations légères et idempotentes pour les bases créées par une version antérieure.

    Le projet n'utilise pas Alembic : ces quelques changements suffisent et restent sûrs
    à rejouer à chaque démarrage.
    """
    inspector = inspect(engine)
    with engine.begin() as conn:
        # Colonnes ajoutées aux modèles depuis la création de la base (create_all ne les ajoute pas).
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in existing:
                    ddl = CreateColumn(column).compile(dialect=engine.dialect)
                    conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {ddl}"))

        # L'interrupteur unique `discord_enabled` est remplacé par des cases par événement :
        # on reprend son état avant de supprimer la colonne (mention conservée pour les échecs).
        if inspector.has_table("notification_settings") and "discord_enabled" in {
            col["name"] for col in inspector.get_columns("notification_settings")
        }:
            conn.execute(text(
                "UPDATE notification_settings SET discord_notify_on_success = discord_enabled, "
                "discord_notify_on_failure = discord_enabled"
            ))

        for table, columns in _DROPPED_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            existing = {col["name"] for col in inspector.get_columns(table)}
            for column in columns:
                if column in existing:  # DROP COLUMN : SQLite ≥ 3.35 / PostgreSQL
                    conn.execute(text(f'ALTER TABLE {table} DROP COLUMN "{column}"'))
        # L'ancien statut CODE_REQUIRED n'existe plus (workflow 100 % automatique).
        conn.execute(text("UPDATE signature_logs SET status = 'FAILED' WHERE status = 'CODE_REQUIRED'"))
        conn.execute(text("UPDATE cnam_credentials SET last_status = 'RETRYING' WHERE last_status = 'CODE_REQUIRED'"))
