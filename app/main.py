"""Application FastAPI : authentification, dashboard HTMX et petite API JSON."""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.database import get_db, init_db
from app.models import CheckStatus, CnamCredential, LogStatus, NotificationSetting, SignatureLog, User, utcnow
from app.scheduler import SignatureScheduler
from app.schemas import (
    CnamCredentialIn,
    NotificationSettingsIn,
    RegisterIn,
    SignatureLogOut,
    StatusOut,
)
from app.security import (
    DecryptionError,
    csrf_tokens_match,
    generate_csrf_token,
    get_cipher,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from app.services.cnam_service import CnamService
from app.services.notifier import Notifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cnamsign_web")

settings = get_settings()
LOGS_PAGE_SIZE = 20

# --- Templates -------------------------------------------------------------------------

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
_tz = ZoneInfo(settings.timezone)


def _localdt(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.replace(tzinfo=timezone.utc).astimezone(_tz).strftime("%d/%m/%Y %H:%M:%S")


templates.env.filters["localdt"] = _localdt
templates.env.globals["STATUS_STYLES"] = {
    "SUCCESS": ("Signé", "bg-green-100 text-green-800"),
    "FAILED": ("Échec", "bg-red-100 text-red-800"),
    "RETRYING": ("Nouvelle tentative", "bg-amber-100 text-amber-800"),
    "NO_SIGNATURE": ("Rien à signer", "bg-slate-100 text-slate-700"),
    "ERROR": ("Erreur technique", "bg-red-100 text-red-800"),
    "NEVER": ("Jamais vérifié", "bg-slate-100 text-slate-500"),
}
templates.env.globals["app_name"] = settings.app_name


# --- Cycle de vie ------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    cipher = get_cipher()
    service = CnamService(settings, cipher)
    if not service.is_upstream_available():
        logger.warning("CnamSign introuvable dans %s : les vérifications échoueront.", settings.cnamsign_path)
    notifier = Notifier(settings, cipher)
    scheduler = SignatureScheduler(settings, service, notifier)
    app.state.service = service
    app.state.notifier = notifier
    app.state.scheduler = scheduler
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(title=settings.app_name, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="cnamsign_session",
    max_age=settings.session_max_age_hours * 3600,
    same_site="lax",
    https_only=settings.session_cookie_secure,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# --- Dépendances ---------------------------------------------------------------------------


class LoginRequired(Exception):
    pass


@app.exception_handler(LoginRequired)
async def _login_required_handler(request: Request, _exc: LoginRequired) -> Response:
    if request.headers.get("HX-Request"):
        return Response(status_code=200, headers={"HX-Redirect": "/login"})
    return RedirectResponse("/login", status_code=303)


def ensure_csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = request.session["csrf"] = generate_csrf_token()
    return token


async def verify_csrf(request: Request) -> None:
    """Jeton CSRF via l'en-tête HTMX (`hx-headers`) ou un champ caché de formulaire."""
    received = request.headers.get("X-CSRF-Token")
    if not received:
        received = (await request.form()).get("csrf_token")  # mis en cache par Starlette
    if not csrf_tokens_match(request.session.get("csrf"), received if isinstance(received, str) else None):
        raise HTTPException(status_code=403, detail="Jeton CSRF invalide, rechargez la page.")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("uid")
    user = db.get(User, user_id) if user_id else None
    if user is None:
        request.session.clear()
        raise LoginRequired()
    return user


def get_service(request: Request) -> CnamService:
    return request.app.state.service


def get_scheduler(request: Request) -> SignatureScheduler:
    return request.app.state.scheduler


def get_notifier(request: Request) -> Notifier:
    return request.app.state.notifier


DbDep = Annotated[Session, Depends(get_db)]
UserDep = Annotated[User, Depends(current_user)]
SchedulerDep = Annotated[SignatureScheduler, Depends(get_scheduler)]
CSRF = [Depends(verify_csrf)]


class LoginRateLimiter:
    """Limiteur en mémoire : N échecs par IP sur une fenêtre glissante."""

    def __init__(self, max_attempts: int = 10, window_seconds: int = 900) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allowed(self, key: str) -> bool:
        with self._lock:
            hits = self._failures[key]
            while hits and hits[0] < time.monotonic() - self._window:
                hits.popleft()
            return len(hits) < self._max

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._failures[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


login_limiter = LoginRateLimiter()


# --- Helpers de rendu --------------------------------------------------------------------------


def render(request: Request, template: str, status_code: int = 200, headers: dict[str, str] | None = None,
           **context: Any) -> HTMLResponse:
    context["csrf_token"] = ensure_csrf(request)
    return templates.TemplateResponse(request, template, context, status_code=status_code, headers=headers)


def alert(request: Request, kind: str, message: str, headers: dict[str, str] | None = None) -> HTMLResponse:
    return render(request, "components/alert.html", headers=headers, kind=kind, message=message)


def _validation_messages(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(p) for p in err['loc']) or 'formulaire'} : {err['msg']}" for err in exc.errors()]


def _status_context(user: User, scheduler: SignatureScheduler) -> dict[str, Any]:
    credential = user.credential
    return {"credential": credential, "busy": bool(credential and scheduler.is_busy(credential.id))}


def _credentials_context(user: User) -> dict[str, Any]:
    credential = user.credential
    cnam_username = ""
    if credential:
        try:
            cnam_username = get_cipher().decrypt(credential.encrypted_cnam_username)
        except DecryptionError:
            cnam_username = ""
    return {
        "credential": credential,
        "cnam_username": cnam_username,
        "default_interval": settings.default_check_interval_minutes,
        "default_folder": settings.default_outlook_folder,
    }


def _notifications_context(user: User) -> dict[str, Any]:
    recipient = None
    if user.credential:
        try:
            recipient = get_cipher().decrypt(user.credential.encrypted_cnam_username)
        except DecryptionError:
            recipient = None
    smtp_mode = (
        f"relais {settings.smtp_host}" if settings.smtp_configured
        else f"{settings.smtp_fallback_host} avec votre compte Le Cnam"
    )
    return {"notification": user.notification, "notify_recipient": recipient, "smtp_mode": smtp_mode}


def _logs_query(db: Session, user: User, status: str, days: int, page: int) -> dict[str, Any]:
    query = select(SignatureLog).where(SignatureLog.user_id == user.id)
    if status in LogStatus.__members__:
        query = query.where(SignatureLog.status == LogStatus(status))
    if days > 0:
        query = query.where(SignatureLog.timestamp >= utcnow() - timedelta(days=days))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    pages = max(1, -(-total // LOGS_PAGE_SIZE))
    page = min(max(page, 1), pages)
    logs = db.scalars(
        query.order_by(SignatureLog.timestamp.desc()).offset((page - 1) * LOGS_PAGE_SIZE).limit(LOGS_PAGE_SIZE)
    ).all()
    return {"logs": logs, "total": total, "page": page, "pages": pages}


def _registration_open(db: Session) -> bool:
    return settings.allow_registration or not db.scalar(select(func.count(User.id)))


# --- Pages publiques ---------------------------------------------------------------------------


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def index(request: Request) -> RedirectResponse:
    return RedirectResponse("/dashboard" if request.session.get("uid") else "/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: DbDep) -> HTMLResponse:
    return render(request, "login.html", mode="login", registration_open=_registration_open(db))


@app.post("/login", response_class=HTMLResponse, dependencies=CSRF)
def login(
    request: Request,
    db: DbDep,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
) -> Response:
    client_ip = request.client.host if request.client else "unknown"
    if not login_limiter.allowed(client_ip):
        return render(request, "login.html", status_code=429, mode="login", registration_open=_registration_open(db),
                      error="Trop de tentatives. Réessayez dans quelques minutes.")

    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not verify_password(password, user.hashed_password):
        login_limiter.record_failure(client_ip)
        return render(request, "login.html", status_code=401, mode="login", registration_open=_registration_open(db),
                      error="Identifiants incorrects.", username=username)

    if password_needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)
        db.commit()
    login_limiter.reset(client_ip)
    request.session.clear()  # nouvelle session : évite la fixation de session
    request.session.update(uid=user.id, csrf=generate_csrf_token())
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: DbDep) -> Response:
    if not _registration_open(db):
        return RedirectResponse("/login", status_code=303)
    return render(request, "login.html", mode="register", registration_open=True)


@app.post("/register", response_class=HTMLResponse, dependencies=CSRF)
def register(
    request: Request,
    db: DbDep,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    password_confirm: Annotated[str, Form()] = "",
) -> Response:
    if not _registration_open(db):
        raise HTTPException(status_code=403, detail="Inscriptions fermées.")

    def fail(message: str) -> HTMLResponse:
        return render(request, "login.html", status_code=400, mode="register", registration_open=True,
                      error=message, username=username)

    try:
        data = RegisterIn(username=username.strip(), password=password)
    except ValidationError as exc:
        return fail(" ; ".join(_validation_messages(exc)))
    if password != password_confirm:
        return fail("Les mots de passe ne correspondent pas.")
    if db.scalar(select(User).where(User.username == data.username)):
        return fail("Ce nom d'utilisateur est déjà pris.")

    is_first_user = not db.scalar(select(func.count(User.id)))
    user = User(username=data.username, hashed_password=hash_password(data.password), is_admin=is_first_user)
    db.add(user)
    db.commit()
    request.session.clear()
    request.session.update(uid=user.id, csrf=generate_csrf_token())
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout", dependencies=CSRF)
def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --- Dashboard -----------------------------------------------------------------------------------


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: UserDep, scheduler: SchedulerDep) -> HTMLResponse:
    context = {**_status_context(user, scheduler), **_credentials_context(user), **_notifications_context(user)}
    return render(
        request,
        "dashboard.html",
        user=user,
        **context,
        scheduler_enabled=settings.scheduler_enabled,
        schedule=f"{settings.schedule_day_of_week}, {settings.schedule_hour}h",
    )


@app.get("/partials/status", response_class=HTMLResponse)
def status_partial(request: Request, user: UserDep, scheduler: SchedulerDep) -> HTMLResponse:
    return render(request, "components/status.html", **_status_context(user, scheduler))


@app.get("/partials/notifications", response_class=HTMLResponse)
def notifications_partial(request: Request, user: UserDep) -> HTMLResponse:
    return render(request, "components/notifications_form.html", **_notifications_context(user))


@app.get("/partials/logs", response_class=HTMLResponse)
def logs_partial(
    request: Request,
    user: UserDep,
    db: DbDep,
    status: str = "",
    days: Annotated[int, Query(ge=0, le=3650)] = 30,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    return render(request, "components/logs.html", **_logs_query(db, user, status, days, page))


# --- Identifiants CNAM ------------------------------------------------------------------------------


@app.post("/cnam/credentials", response_class=HTMLResponse, dependencies=CSRF)
def save_credentials(
    request: Request,
    user: UserDep,
    db: DbDep,
    scheduler: SchedulerDep,
    service: Annotated[CnamService, Depends(get_service)],
    cnam_username: Annotated[str, Form()] = "",
    cnam_password: Annotated[str, Form()] = "",
    cnam_pin: Annotated[str, Form()] = "",
    check_interval_minutes: Annotated[str, Form()] = "5",
    outlook_folder: Annotated[str, Form()] = "Emargements",
    test_before_save: Annotated[bool, Form()] = False,
) -> HTMLResponse:
    """Route synchrone : FastAPI l'exécute dans un thread, le test Playwright ne bloque pas la boucle."""

    def respond(kind: str, message: str, headers: dict[str, str] | None = None) -> HTMLResponse:
        return render(request, "components/credentials_form.html", headers=headers,
                      **_credentials_context(user), alert_kind=kind, alert_message=message)

    try:
        data = CnamCredentialIn(
            cnam_username=cnam_username,
            cnam_password=cnam_password,
            cnam_pin=cnam_pin,
            check_interval_minutes=check_interval_minutes or settings.default_check_interval_minutes,
            outlook_folder=outlook_folder or settings.default_outlook_folder,
        )
    except ValidationError as exc:
        return respond("error", " ; ".join(_validation_messages(exc)))

    cipher = get_cipher()
    credential = user.credential
    if credential and scheduler.is_busy(credential.id):
        return respond("error", "Une vérification est en cours, réessayez dans une minute.")

    try:
        current_username = cipher.decrypt(credential.encrypted_cnam_username) if credential else None
        password = data.cnam_password or (cipher.decrypt(credential.encrypted_cnam_password) if credential else None)
        pin = data.cnam_pin or (cipher.decrypt(credential.encrypted_cnam_pin) if credential else None)
    except DecryptionError:
        current_username, password, pin = None, data.cnam_password, data.cnam_pin
    if not password or not pin:
        return respond("error", "Le mot de passe Le Cnam et le code PIN sont obligatoires.")

    secrets_changed = (
        credential is None or data.cnam_username != current_username or bool(data.cnam_password or data.cnam_pin)
    )
    if test_before_save and secrets_changed:
        ok, message = service.diagnose_credentials(data.cnam_username, password, pin)
        if not ok:
            return respond("error", f"Test de connexion échoué : {message} Rien n'a été enregistré.")

    if credential is None:
        credential = CnamCredential(user_id=user.id, auto_sign_enabled=False)
        db.add(credential)
    credential.encrypted_cnam_username = cipher.encrypt(data.cnam_username)
    credential.encrypted_cnam_password = cipher.encrypt(password)
    credential.encrypted_cnam_pin = cipher.encrypt(pin)
    credential.check_interval_minutes = data.check_interval_minutes
    credential.outlook_folder = data.outlook_folder
    if secrets_changed:
        # Nouveau compte = nouveau profil navigateur (les cookies SSO de l'ancien ne doivent pas servir).
        service.reset_user_data(user.id)
        credential.last_status = CheckStatus.NEVER
        credential.last_message = None
        credential.pending_code = credential.pending_email_date = None
        credential.pending_attempts = 0
    db.commit()
    db.refresh(user)

    tested = " (connexion testée avec succès)" if test_before_save and secrets_changed else ""
    return respond("success", f"Identifiants enregistrés et chiffrés{tested}.", headers={"HX-Trigger": "status-refresh, notifications-refresh"})


@app.post("/cnam/delete", response_class=HTMLResponse, dependencies=CSRF)
def delete_credentials(
    request: Request,
    user: UserDep,
    db: DbDep,
    scheduler: SchedulerDep,
    service: Annotated[CnamService, Depends(get_service)],
) -> HTMLResponse:
    credential = user.credential
    if credential and scheduler.is_busy(credential.id):
        return render(request, "components/credentials_form.html", **_credentials_context(user),
                      alert_kind="error", alert_message="Une vérification est en cours, réessayez dans une minute.")
    if credential:
        db.delete(credential)
        db.commit()
        db.refresh(user)
    service.reset_user_data(user.id)
    return render(request, "components/credentials_form.html", headers={"HX-Trigger": "status-refresh, notifications-refresh"},
                  **_credentials_context(user), alert_kind="success",
                  alert_message="Identifiants et données de navigation supprimés.")


@app.post("/cnam/toggle", response_class=HTMLResponse, dependencies=CSRF)
def toggle_auto_sign(request: Request, user: UserDep, db: DbDep, scheduler: SchedulerDep) -> HTMLResponse:
    if user.credential:
        user.credential.auto_sign_enabled = not user.credential.auto_sign_enabled
        db.commit()
    return render(request, "components/status.html", **_status_context(user, scheduler))


@app.post("/cnam/check-now", response_class=HTMLResponse, dependencies=CSRF)
def check_now(request: Request, user: UserDep, scheduler: SchedulerDep) -> HTMLResponse:
    if not user.credential:
        return alert(request, "error", "Enregistrez d'abord vos identifiants Le Cnam.")
    if not scheduler.trigger_now(user.credential.id):
        return alert(request, "info", "Une vérification est déjà en cours.")
    return alert(request, "info", "Vérification lancée (30 s à 2 min).", headers={"HX-Trigger": "status-refresh"})


# --- Notifications -------------------------------------------------------------------------------------


@app.post("/notifications", response_class=HTMLResponse, dependencies=CSRF)
def save_notifications(
    request: Request,
    user: UserDep,
    db: DbDep,
    notify_on_success: Annotated[bool, Form()] = False,
    notify_on_failure: Annotated[bool, Form()] = False,
) -> HTMLResponse:
    """Enregistrement automatique à chaque changement de case (hx-trigger="change")."""
    data = NotificationSettingsIn(notify_on_success=notify_on_success, notify_on_failure=notify_on_failure)
    setting = user.notification
    if setting is None:
        setting = NotificationSetting(user_id=user.id)
        db.add(setting)
    setting.notify_on_success = data.notify_on_success
    setting.notify_on_failure = data.notify_on_failure
    db.commit()
    db.refresh(user)
    return render(request, "components/notifications_form.html", **_notifications_context(user),
                  alert_kind="success", alert_message="Préférences enregistrées.")


@app.post("/notifications/test", response_class=HTMLResponse, dependencies=CSRF)
def test_notifications(
    request: Request, user: UserDep, notifier: Annotated[Notifier, Depends(get_notifier)]
) -> HTMLResponse:
    """Route synchrone : l'envoi SMTP (bloquant) s'exécute dans le threadpool FastAPI."""
    if user.credential is None:
        return alert(request, "error", "Enregistrez d'abord vos identifiants Le Cnam.")
    errors = notifier.send_test(user.credential)
    if errors:
        return alert(request, "error", " ; ".join(errors))
    return alert(request, "success", f"E-mail de test envoyé à {notifier.recipient(user.credential)}.")


# --- API JSON (authentifiée par la session) ---------------------------------------------------------------


@app.get("/api/status", response_model=StatusOut)
def api_status(user: UserDep, scheduler: SchedulerDep) -> StatusOut:
    credential = user.credential
    if credential is None:
        return StatusOut(configured=False)
    return StatusOut(
        configured=True,
        auto_sign_enabled=credential.auto_sign_enabled,
        busy=scheduler.is_busy(credential.id),
        last_check_at=credential.last_check_at,
        last_status=credential.last_status,
        last_message=credential.last_message,
        pending_code=credential.pending_code,
        pending_attempts=credential.pending_attempts,
    )


@app.get("/api/logs", response_model=list[SignatureLogOut])
def api_logs(
    user: UserDep,
    db: DbDep,
    status: str = "",
    days: Annotated[int, Query(ge=0, le=3650)] = 30,
    page: Annotated[int, Query(ge=1)] = 1,
) -> list[SignatureLog]:
    return list(_logs_query(db, user, status, days, page)["logs"])
