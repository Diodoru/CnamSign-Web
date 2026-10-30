"""Planification des vérifications et logique métier d'émargement (100 % automatique).

Un « tick » APScheduler toutes les minutes (pendant les créneaux de cours)
sélectionne les utilisateurs dont l'intervalle est écoulé et place leur
vérification dans un pool de threads borné (`MAX_CONCURRENT_JOBS`), car chaque
vérification lance un Chromium.

Cycle de vie d'un code de session détecté par e-mail :
  1. signature OK                         -> SUCCESS (+ e-mail si activé)
  2. échec                                -> RETRYING, nouvelle tentative au cycle suivant
  3. MAX_SIGN_RETRIES échecs consécutifs  -> FAILED (+ e-mail d'alerte si activé),
                                             le code est abandonné
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.database import SessionLocal
from app.models import CheckStatus, CnamCredential, LogSource, LogStatus, NotificationSetting, SignatureLog, utcnow
from app.services.cnam_service import CnamService
from app.services.notifier import Notifier

logger = logging.getLogger(__name__)

# Tolérance pour qu'un intervalle de 5 min ne devienne pas 6 avec un tick à la minute.
_TICK_TOLERANCE = timedelta(seconds=30)


class SignatureScheduler:
    def __init__(
        self,
        settings: Settings,
        service: CnamService,
        notifier: Notifier,
        session_factory: sessionmaker[Session] = SessionLocal,
    ) -> None:
        self._settings = settings
        self._service = service
        self._notifier = notifier
        self._session_factory = session_factory
        self._tz = ZoneInfo(settings.timezone)
        self._scheduler = BackgroundScheduler(timezone=self._tz)
        self._executor = ThreadPoolExecutor(
            max_workers=settings.max_concurrent_jobs, thread_name_prefix="cnam-job"
        )
        self._busy: set[int] = set()  # credential_id en file ou en cours
        self._lock = threading.Lock()

    # --- Cycle de vie ---------------------------------------------------------------

    def start(self) -> None:
        if self._settings.scheduler_enabled:
            self._scheduler.add_job(
                self._tick,
                CronTrigger(
                    day_of_week=self._settings.schedule_day_of_week,
                    hour=self._settings.schedule_hour,
                    minute="*",
                    timezone=self._tz,
                ),
                id="cnam-tick",
                max_instances=1,
                coalesce=True,
                misfire_grace_time=30,
            )
        self._scheduler.add_job(
            self._service.purge_old_screenshots, CronTrigger(hour=3, minute=0, timezone=self._tz), id="cleanup"
        )
        self._scheduler.start()
        logger.info(
            "Planificateur démarré (%s, %sh, %s job(s) simultané(s))",
            self._settings.schedule_day_of_week,
            self._settings.schedule_hour,
            self._settings.max_concurrent_jobs,
        )

    def shutdown(self) -> None:
        self._scheduler.shutdown(wait=False)
        self._executor.shutdown(wait=False, cancel_futures=True)

    # --- API utilisée par les routes -----------------------------------------------

    def is_busy(self, credential_id: int) -> bool:
        with self._lock:
            return credential_id in self._busy

    def trigger_now(self, credential_id: int) -> bool:
        """Lance immédiatement une vérification. False si une est déjà en cours."""
        return self._submit(credential_id, LogSource.MANUAL)

    # --- Interne ------------------------------------------------------------------------

    def _submit(self, credential_id: int, source: LogSource) -> bool:
        with self._lock:
            if credential_id in self._busy:
                return False
            self._busy.add(credential_id)
        self._executor.submit(self._run_job, credential_id, source)
        return True

    def _tick(self) -> None:
        now = utcnow()
        with self._session_factory() as db:
            credentials = db.scalars(select(CnamCredential).where(CnamCredential.auto_sign_enabled.is_(True))).all()
            due = [
                c.id
                for c in credentials
                if c.last_check_at is None
                or c.last_check_at + timedelta(minutes=c.check_interval_minutes) - _TICK_TOLERANCE <= now
            ]
        for credential_id in due:
            self._submit(credential_id, LogSource.AUTO)

    def _run_job(self, credential_id: int, source: LogSource) -> None:
        try:
            self._process(credential_id, source)
        except Exception:  # noqa: BLE001 - un job ne doit jamais tuer le pool
            logger.exception("Job d'émargement en erreur (credential %s)", credential_id)
        finally:
            with self._lock:
                self._busy.discard(credential_id)

    def _process(self, credential_id: int, source: LogSource) -> None:
        result = self._service.check_and_sign(credential_id)
        status, found_code, message = result["status"], result["code"], result["message"]
        course_name = result.get("course_name")
        event: LogStatus | None = None

        with self._session_factory() as db:
            credential = db.get(CnamCredential, credential_id)
            if credential is None:  # supprimé pendant l'exécution
                return
            credential.last_check_at = utcnow()

            if status == "SUCCESS":
                credential.last_status = CheckStatus.SUCCESS
                _clear_pending(credential)
                event = LogStatus.SUCCESS
            elif status == "NO_SIGNATURE":
                credential.last_status = CheckStatus.RETRYING if credential.pending_code else CheckStatus.NO_SIGNATURE
            elif status == "FAILED":  # code trouvé par e-mail mais signature refusée
                event, message = self._handle_failure(credential, found_code, result["email_date"], message)
            else:  # ERROR technique (timeout, crash Chromium...) : pas d'entrée d'historique
                credential.last_status = CheckStatus.ERROR

            credential.last_message = message
            if event is not None:
                db.add(
                    SignatureLog(
                        user_id=credential.user_id,
                        status=event,
                        source=source,
                        session_code=found_code,
                        course_name=course_name,
                        message=message,
                    )
                )
            db.commit()
            notification = db.scalar(
                select(NotificationSetting).where(NotificationSetting.user_id == credential.user_id)
            )

        if event is not None:
            self._notifier.notify(credential, notification, event, message, found_code, course_name)

    def _handle_failure(
        self, credential: CnamCredential, found_code: str, email_date: str | None, reason: str
    ) -> tuple[LogStatus | None, str]:
        max_retries = self._settings.max_sign_retries
        if credential.pending_code != found_code:
            credential.pending_code = found_code
            credential.pending_email_date = email_date
            credential.pending_attempts = 1
        else:
            credential.pending_attempts += 1

        if credential.pending_attempts >= max_retries:
            self._service.mark_processed(credential.id, found_code, email_date)
            credential.last_status = CheckStatus.FAILED
            _clear_pending(credential)
            return LogStatus.FAILED, f"Code {found_code} abandonné après {max_retries} tentatives : {reason}"

        credential.last_status = CheckStatus.RETRYING
        return None, (
            f"Code {found_code} : tentative {credential.pending_attempts}/{max_retries} échouée ({reason}). "
            "Nouvelle tentative au prochain cycle."
        )


def _clear_pending(credential: CnamCredential) -> None:
    credential.pending_code = None
    credential.pending_email_date = None
    credential.pending_attempts = 0
