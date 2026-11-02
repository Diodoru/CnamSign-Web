"""Panneau d'administration SQLAdmin, monté sur /admin.

L'authentification réutilise la session de l'application web (cookie signé) :
pas de second formulaire de connexion, et seuls les comptes `is_admin` et
`is_active` y accèdent. Un utilisateur connecté mais non admin reçoit un 403.

Aucune donnée sensible n'est exposée : ni hash de mot de passe, ni identifiants
Le Cnam / PIN / webhook (chiffrés), qui ne sont de toute façon pas déchiffrés ici.

Personnalisation (sans modifier le paquet SQLAdmin) :
- interface en français : catalogue `admin_i18n/fr.po` compilé en mémoire et enregistré
  dans le registre de traductions de SQLAdmin ;
- thème sombre et sidebar : surcharges dans `templates/admin/sqladmin/` ;
- dates au format « 30 oct. 2026 à 11:51 », heure de Paris.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from babel.dates import format_datetime
from babel.messages.mofile import write_mo
from babel.messages.pofile import read_po
from babel.support import Translations
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from markupsafe import Markup
from sqladmin import Admin, ModelView
from sqladmin import i18n as sqladmin_i18n
from sqladmin.authentication import AuthenticationBackend
from sqladmin.filters import BooleanFilter, StaticValuesFilter
from sqladmin.i18n import I18nConfig

from app.config import get_settings
from app.database import SessionLocal, engine
from app.models import LogStatus, SignatureLog, User

_APP_DIR = Path(__file__).resolve().parent
ADMIN_LOCALE = "fr"
_settings = get_settings()
_tz = ZoneInfo(_settings.timezone)


# --- Traduction française ------------------------------------------------------------


def _register_french_catalog() -> None:
    """Compile `fr.po` en mémoire et l'ajoute aux catalogues de SQLAdmin (qui n'en fournit pas)."""
    with (_APP_DIR / "admin_i18n" / "fr.po").open("rb") as po_file:
        catalog = read_po(po_file, locale=ADMIN_LOCALE, domain="admin")
    buffer = io.BytesIO()
    write_mo(buffer, catalog)
    buffer.seek(0)
    sqladmin_i18n.translations[ADMIN_LOCALE] = Translations(buffer, domain="admin")


# --- Formatage -------------------------------------------------------------------------


def format_fr_datetime(value: datetime | None) -> str:
    """UTC naïf (stockage) -> « 30 oct. 2026 à 11:51 » à l'heure locale."""
    if value is None:
        return "—"
    return format_datetime(value.replace(tzinfo=timezone.utc), "d MMM y 'à' HH:mm", tzinfo=_tz, locale=ADMIN_LOCALE)


def _datetime_formatter(attribute: str):
    return lambda model, _attr: format_fr_datetime(_get_path(model, attribute))


def _get_path(obj: Any, path: str) -> Any:
    for part in path.split("."):
        obj = getattr(obj, part, None) if obj is not None else None
    return obj


_STATUS_BADGES = {
    LogStatus.SUCCESS: ("Succès", "badge-status-success"),
    LogStatus.FAILED: ("Échec", "badge-status-failed"),
}


def _status_formatter(model: SignatureLog, _attr: Any) -> Markup:
    label, css = _STATUS_BADGES.get(model.status, (str(model.status), ""))
    return Markup('<span class="badge {}">{}</span>').format(css, label)


# --- Authentification ----------------------------------------------------------------


class WebSessionAuthBackend(AuthenticationBackend):
    def __init__(self) -> None:
        super().__init__(secret_key="unused")
        # Pas de SessionMiddleware propre à l'admin : celle de l'application principale
        # fournit déjà request.session (même cookie, même clé).
        self.middlewares = []

    async def login(self, request: Request) -> Response | bool:
        return RedirectResponse("/login", status_code=303)

    async def logout(self, request: Request) -> Response | bool:
        # Le bouton de la sidebar ramène à l'application ; cette route reste par compatibilité.
        return RedirectResponse("/dashboard", status_code=303)

    async def authenticate(self, request: Request) -> Response | bool:
        user_id = request.session.get("uid")
        with SessionLocal() as db:
            user = db.get(User, user_id) if user_id else None
            is_active, is_admin = (user.is_active, user.is_admin) if user else (False, False)
        if not is_active:
            request.session.clear()
            return RedirectResponse("/login", status_code=303)
        if not is_admin:
            return HTMLResponse(
                "<h1>403 — Accès refusé</h1><p>Réservé aux administrateurs. <a href='/dashboard'>Retour</a></p>",
                status_code=403,
            )
        return True


# --- Vues --------------------------------------------------------------------------------


class UserAdmin(ModelView, model=User):
    name = "Utilisateur"
    name_plural = "Utilisateurs"
    icon = "fa-solid fa-users"

    # Liste : jamais le hash du mot de passe ni les données chiffrées.
    column_list = [User.id, User.username, User.is_active, User.is_admin, User.created_at,
                   "credential.last_check_at"]
    column_labels = {
        User.id: "ID",
        User.username: "Nom d'utilisateur",
        User.is_active: "Actif",
        User.is_admin: "Administrateur",
        User.created_at: "Date de création",
        "credential.last_check_at": "Dernière vérification",
    }
    column_formatters = {
        User.created_at: _datetime_formatter("created_at"),
        "credential.last_check_at": _datetime_formatter("credential.last_check_at"),
    }
    column_details_list = [User.id, User.username, User.is_active, User.is_admin, User.created_at]
    column_formatters_detail = {User.created_at: _datetime_formatter("created_at")}
    column_export_list = [User.id, User.username, User.is_active, User.is_admin, User.created_at]
    column_searchable_list = [User.username]
    column_sortable_list = [User.id, User.username, User.created_at]
    column_filters = [BooleanFilter(User.is_admin, title="Administrateur"), BooleanFilter(User.is_active, title="Actif")]
    column_default_sort = [(User.id, False)]

    # Seuls les droits sont modifiables ; un compte se crée via l'inscription (mot de passe haché).
    can_create = False
    form_columns = [User.is_active, User.is_admin]

    async def on_model_change(self, data: dict[str, Any], model: User, is_created: bool, request: Request) -> None:
        # Garde-fou : un admin ne peut pas se retirer ses propres droits (risque de verrouillage).
        if model.id == request.session.get("uid") and (data.get("is_admin") is False or data.get("is_active") is False):
            raise ValueError("Vous ne pouvez pas retirer vos propres droits d'administration ou désactiver votre compte.")

    async def on_model_delete(self, model: User, request: Request) -> None:
        if model.id == request.session.get("uid"):
            raise ValueError("Vous ne pouvez pas supprimer votre propre compte depuis l'administration.")


class SignatureLogAdmin(ModelView, model=SignatureLog):
    """Historique des émargements de tous les utilisateurs (lecture seule)."""

    name = "Émargement"
    name_plural = "Émargements"
    icon = "fa-solid fa-file-signature"

    column_list = [SignatureLog.id, SignatureLog.user, SignatureLog.course_name, SignatureLog.session_code,
                   SignatureLog.status, SignatureLog.timestamp]
    column_details_list = [SignatureLog.id, SignatureLog.user, SignatureLog.course_name, SignatureLog.session_code,
                           SignatureLog.status, SignatureLog.source, SignatureLog.message, SignatureLog.timestamp]
    column_labels = {
        SignatureLog.id: "ID",
        SignatureLog.user: "Utilisateur",
        SignatureLog.course_name: "Matière",
        SignatureLog.session_code: "Code",
        SignatureLog.status: "Statut",
        SignatureLog.source: "Origine",
        SignatureLog.message: "Message",
        SignatureLog.timestamp: "Date d'émargement",
        "user.username": "Utilisateur",  # libellé du champ de recherche
    }
    column_formatters = {
        SignatureLog.status: _status_formatter,
        SignatureLog.timestamp: _datetime_formatter("timestamp"),
    }
    column_formatters_detail = column_formatters
    column_searchable_list = [SignatureLog.course_name, SignatureLog.session_code, "user.username"]
    column_filters = [
        StaticValuesFilter(SignatureLog.status, values=[(s.value, label) for s, (label, _) in _STATUS_BADGES.items()],
                           title="Statut"),
    ]
    column_sortable_list = [SignatureLog.id, SignatureLog.timestamp, SignatureLog.course_name, SignatureLog.status]
    column_default_sort = [(SignatureLog.timestamp, True)]  # plus récent d'abord
    column_export_list = [SignatureLog.id, SignatureLog.course_name, SignatureLog.session_code,
                          SignatureLog.status, SignatureLog.timestamp]

    # Journal d'audit : consultable et exportable, jamais modifié depuis l'admin.
    can_create = False
    can_edit = False
    can_delete = False


# --- Montage ---------------------------------------------------------------------------------


def setup_admin(app: FastAPI) -> Admin:
    """Monte le panneau /admin sur l'application FastAPI."""
    _register_french_catalog()

    # Routes déclarées avant le montage : prioritaires sur celles de SQLAdmin.
    @app.get("/admin/login", include_in_schema=False)
    def _admin_login() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    @app.get("/admin", include_in_schema=False)
    @app.get("/admin/", include_in_schema=False)
    def _admin_home() -> RedirectResponse:  # page d'accueil vide de SQLAdmin -> liste des utilisateurs
        return RedirectResponse("/admin/user/list", status_code=303)

    admin = Admin(
        app,
        engine,  # SQLAdmin crée sa propre sessionmaker (ne modifie pas SessionLocal)
        base_url="/admin",
        title=f"{_settings.app_name} · Administration",  # titre de l'onglet ; la sidebar est dans layout.html
        templates_dir=str(_APP_DIR / "templates" / "admin"),
        authentication_backend=WebSessionAuthBackend(),
        i18n_config=I18nConfig(default_locale=ADMIN_LOCALE, language_cookie_name=None, language_header_name=None),
    )
    admin.templates.env.globals["app_name"] = _settings.app_name
    admin.add_view(UserAdmin)
    admin.add_view(SignatureLogAdmin)
    return admin
