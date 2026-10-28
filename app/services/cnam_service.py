"""Wrapper multi-utilisateurs autour du code upstream CnamSign.

Le code upstream est exécuté dans un sous-processus (`cnam_worker.py`) dont le
répertoire courant est propre à chaque utilisateur. Les identifiants sont
déchiffrés en mémoire juste avant l'appel, transmis par un pipe stdin, puis
oubliés : ils ne sont jamais écrits sur disque ni passés en argument.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.database import SessionLocal
from app.models import CnamCredential
from app.security import CredentialCipher

logger = logging.getLogger(__name__)

WORKER_SCRIPT = Path(__file__).with_name("cnam_worker.py")
RESULT_PREFIX = "__RESULT__"
# Variables d'environnement du serveur à ne jamais transmettre au worker.
_SENSITIVE_ENV_PREFIXES = ("SECRET_", "SMTP_", "DATABASE_URL")


class CnamWorkerError(RuntimeError):
    """Le worker n'a pas pu produire de résultat (timeout, crash, sortie illisible)."""


class CnamService:
    def __init__(
        self,
        settings: Settings,
        cipher: CredentialCipher,
        session_factory: sessionmaker[Session] = SessionLocal,
    ) -> None:
        self._settings = settings
        self._cipher = cipher
        self._session_factory = session_factory

    # --- Gestion des répertoires par utilisateur --------------------------------

    def user_workdir(self, user_id: int) -> Path:
        workdir = self._settings.data_dir / "users" / str(user_id)
        workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return workdir

    def reset_user_data(self, user_id: int) -> None:
        """Supprime profil navigateur (cookies SSO), captures et historique upstream."""
        shutil.rmtree(self._settings.data_dir / "users" / str(user_id), ignore_errors=True)

    def purge_old_screenshots(self) -> int:
        """Les captures upstream (`screenshots/`) s'accumulent : on borne leur durée de vie."""
        cutoff = time.time() - self._settings.screenshot_retention_days * 86400
        removed = 0
        for shot in (self._settings.data_dir / "users").glob("*/screenshots/*.png"):
            try:
                if shot.stat().st_mtime < cutoff:
                    shot.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def is_upstream_available(self) -> bool:
        return (self._settings.cnamsign_path / "signer.py").is_file()

    # --- API publique -------------------------------------------------------------

    def test_credentials(self, username: str, password: str, pin: str = "") -> bool:
        return self.diagnose_credentials(username, password, pin)[0]

    def diagnose_credentials(self, username: str, password: str, pin: str = "") -> tuple[bool, str]:
        """Teste une connexion CnamSignE dans un profil navigateur jetable."""
        with tempfile.TemporaryDirectory(prefix="cnam-test-") as tmp:
            payload = self._payload("test", username, password, pin, None)
            try:
                result, _ = self._run_worker(Path(tmp), payload)
            except CnamWorkerError as exc:
                return False, str(exc)
            finally:
                payload.clear()
        if "error" in result:
            return False, f"Erreur technique : {result['error']}"
        return bool(result.get("ok")), result.get("message", "")

    def check_and_sign(self, credential_id: int) -> dict[str, Any]:
        """Cherche un code de session dans Outlook et émarge automatiquement.

        Retourne `{"status", "code", "email_date", "message"}` où status vaut
        SUCCESS, FAILED (code trouvé mais signature refusée), NO_SIGNATURE ou ERROR.
        """
        with self._session_factory() as db:
            credential = db.get(CnamCredential, credential_id)
            if credential is None:
                raise ValueError(f"Identifiants CNAM #{credential_id} introuvables")
            user_id = credential.user_id
            folder = credential.outlook_folder
            # Déchiffrement en mémoire, uniquement pour la durée de l'appel.
            payload = self._payload(
                "check_and_sign",
                self._cipher.decrypt(credential.encrypted_cnam_username),
                self._cipher.decrypt(credential.encrypted_cnam_password),
                self._cipher.decrypt(credential.encrypted_cnam_pin),
                folder,
            )

        try:
            result, stderr = self._run_worker(self.user_workdir(user_id), payload)
        except CnamWorkerError as exc:
            return {"status": "ERROR", "code": None, "email_date": None, "message": str(exc)}
        finally:
            payload.clear()  # best effort : Python ne permet pas d'effacer une str en mémoire

        if "error" in result:
            return {"status": "ERROR", "code": None, "email_date": None, "message": result["error"]}

        found_code = result.get("code")
        if not found_code:
            return {"status": "NO_SIGNATURE", "code": None, "email_date": None,
                    "message": "Aucun nouveau code d'émargement dans la boîte mail."}
        if result.get("signed"):
            return {"status": "SUCCESS", "code": found_code, "email_date": result.get("date"),
                    "message": f"Émargement réussi avec le code {found_code}."}
        reason = _last_error_line(stderr) or "CnamSignE n'a pas confirmé la signature."
        return {"status": "FAILED", "code": found_code, "email_date": result.get("date"), "message": reason}

    def mark_processed(self, credential_id: int, code: str, email_date: str | None) -> None:
        """Indique à l'upstream de ne plus retenter ce code (fichier `processed_codes.txt`)."""
        with self._session_factory() as db:
            credential = db.get(CnamCredential, credential_id)
            if credential is None:
                return
            user_id = credential.user_id
        # Cette action n'ouvre pas de navigateur : aucun secret n'est nécessaire.
        payload = self._payload("mark", "", "", "", None)
        payload.update(code=code, date=email_date)
        try:
            self._run_worker(self.user_workdir(user_id), payload)
        except CnamWorkerError:
            logger.warning("Impossible de marquer le code %s comme traité (utilisateur %s)", code, user_id)

    # --- Interne -----------------------------------------------------------------

    def _payload(self, action: str, username: str, password: str, pin: str, folder: str | None) -> dict[str, Any]:
        return {
            "action": action,
            "username": username,
            "password": password,
            "pin": pin,
            "outlook_folder": folder or self._settings.default_outlook_folder,
            "headless": self._settings.headless,
            "cnamsign_path": str(self._settings.cnamsign_path.resolve()),
        }

    def _child_env(self) -> dict[str, str]:
        return {k: v for k, v in os.environ.items() if not k.startswith(_SENSITIVE_ENV_PREFIXES)}

    def _run_worker(self, workdir: Path, payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
        if not self.is_upstream_available():
            raise CnamWorkerError(f"Code CnamSign introuvable dans {self._settings.cnamsign_path}")

        # -I : mode isolé (ignore PYTHON*, n'ajoute pas le dossier du script au sys.path)
        cmd = [sys.executable, "-I", "-X", "utf8", str(WORKER_SCRIPT)]
        proc = subprocess.Popen(
            cmd,
            cwd=workdir,
            env=self._child_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=os.name == "posix",  # groupe de processus => kill de Chromium inclus
        )
        try:
            stdout, stderr = proc.communicate(json.dumps(payload), timeout=self._settings.job_timeout_seconds)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.communicate()
            raise CnamWorkerError(f"Délai dépassé ({self._settings.job_timeout_seconds} s)") from None

        for line in stderr.splitlines():
            logger.debug("[worker %s] %s", workdir.name, line)

        for line in reversed(stdout.splitlines()):
            if line.startswith(RESULT_PREFIX):
                return json.loads(line[len(RESULT_PREFIX):]), stderr
        raise CnamWorkerError(
            f"Le worker s'est arrêté sans résultat (code {proc.returncode}) : {_last_error_line(stderr) or 'aucun log'}"
        )


def _last_error_line(stderr: str) -> str | None:
    for line in reversed(stderr.splitlines()):
        if "[ERROR]" in line:
            return line.split(": ", 1)[-1].strip()
    return None


def _kill_tree(proc: subprocess.Popen[str]) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False)
    except (ProcessLookupError, OSError):
        proc.kill()
