"""Processus enfant isolé qui exécute le code *upstream* CnamSign pour UN utilisateur.

Ce script n'importe rien du paquet `app` : il est lancé par `CnamService` via
`python -I -X utf8 cnam_worker.py`, avec pour répertoire courant le dossier de
données de l'utilisateur.

Pourquoi un sous-processus plutôt qu'un import direct dans FastAPI ?
- le module upstream `config` lit les identifiants dans des variables globales
  à l'import : une seule identité possible par processus ;
- `browser_profile/`, `screenshots/` et `processed_codes.txt` sont des chemins
  relatifs au répertoire courant : un `cwd` par utilisateur suffit à les isoler ;
- `TimeoutWatchdog` repose sur SIGALRM, qui ne fonctionne que dans le thread
  principal d'un processus (pas dans un thread APScheduler) ;
- un blocage ou un crash de Chromium n'affecte jamais le serveur web.

Protocole : un objet JSON sur stdin (secrets inclus : jamais en argument de ligne
de commande ni dans un fichier), une ligne `__RESULT__{json}` sur stdout.
Les logs (upstream compris) partent sur stderr.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

RESULT_PREFIX = "__RESULT__"
logger = logging.getLogger("cnam_worker")


def _emit(result: dict[str, Any]) -> None:
    sys.stdout.write(RESULT_PREFIX + json.dumps(result) + "\n")
    sys.stdout.flush()


def _bootstrap(payload: dict[str, Any]) -> None:
    """Injecte l'identité de l'utilisateur AVANT l'import du `config` upstream."""
    os.environ["EMAIL"] = payload["username"]
    os.environ["PASSWORD"] = payload["password"]
    os.environ["PIN_CODE"] = payload.get("pin", "")
    os.environ["OUTLOOK_FOLDER"] = payload.get("outlook_folder") or "Emargements"
    os.environ["HEADLESS"] = "true" if payload.get("headless", True) else "false"
    sys.path.insert(0, payload["cnamsign_path"])


def action_test(_payload: dict[str, Any]) -> dict[str, Any]:
    """Connexion SSO + PIN sur CnamSignE, sans émarger (reprend tests/test_login.py)."""
    import config  # upstream
    from mail_watcher import clean_browser_locks
    from playwright.sync_api import sync_playwright
    from signer import BROWSER_PROFILE_DIR, URL_EMARGEMENT, CnamSigner

    clean_browser_locks()
    signer = CnamSigner()
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=BROWSER_PROFILE_DIR,
            headless=config.HEADLESS,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
            viewport={"width": 1280, "height": 800},
        )
        page = context.pages[0] if context.pages else context.new_page()
        try:
            page.goto(URL_EMARGEMENT, wait_until="networkidle", timeout=60000)
            signer._handle_login_sso(page)
            if config.CNAM_PIN:
                signer._handle_pin_if_present(page, config.CNAM_PIN, timeout_ms=4000)
            final_url = page.url
            ok = "cnamsigne.lecnam.net" in final_url and "idp.lecnam.net" not in final_url
            message = (
                "Connexion à CnamSignE réussie."
                if ok
                else "Connexion refusée : identifiants Le Cnam incorrects ou SSO indisponible."
            )
            return {"ok": ok, "message": message}
        finally:
            context.close()


def action_check_and_sign(payload: dict[str, Any]) -> dict[str, Any]:
    """Cherche un nouveau code dans Outlook puis, s'il y en a un, émarge."""
    from mail_watcher import MailWatcher
    from signer import CnamSigner

    watcher = MailWatcher()
    code = watcher.check_for_code(auto_mark=False)
    if not code:
        return {"code": None}
    email_date = watcher.last_detected_date
    # Matière extraite du sujet du mail (upstream ≥ cc5d91d) ; absente sur les versions plus anciennes.
    subject = getattr(watcher, "last_detected_subject", None)
    signed = CnamSigner().sign(code)
    if signed:
        watcher.mark_as_processed(code, email_date)
    return {"code": code, "date": email_date, "subject": subject, "signed": signed}


def action_mark(payload: dict[str, Any]) -> dict[str, Any]:
    """Marque un code comme traité (abandon après trop d'échecs)."""
    from mail_watcher import MailWatcher

    MailWatcher().mark_as_processed(payload["code"], payload.get("date"))
    return {"ok": True}


ACTIONS = {
    "test": action_test,
    "check_and_sign": action_check_and_sign,
    "mark": action_mark,
}


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        payload = json.loads(sys.stdin.read())
        _bootstrap(payload)
        result = ACTIONS[payload["action"]](payload)
    except Exception as exc:  # noqa: BLE001 - tout remonter proprement au parent
        logger.exception("Échec du worker")
        _emit({"error": f"{type(exc).__name__}: {exc}"})
        return 1
    _emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
