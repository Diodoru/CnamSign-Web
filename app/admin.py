"""Panneau d'administration SQLAdmin, monté sur /admin.

L'authentification réutilise la session de l'application web (cookie signé) :
pas de second formulaire de connexion, et seuls les comptes `is_admin` et
`is_active` y accèdent. Un utilisateur connecté mais non admin reçoit un 403.

Aucune donnée sensible n'est exposée : ni hash de mot de passe, ni identifiants
Le Cnam / PIN / webhook (chiffrés), qui ne sont de toute façon pas déchiffrés ici.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from sqladmin.filters import BooleanFilter

from app.config import get_settings
from app.database import SessionLocal, engine
from app.models import User


class WebSessionAuthBackend(AuthenticationBackend):
    def __init__(self) -> None:
        super().__init__(secret_key="unused")
        # Pas de SessionMiddleware propre à l'admin : celle de l'application principale
        # fournit déjà request.session (même cookie, même clé).
        self.middlewares = []

    async def login(self, request: Request) -> Response | bool:
        return RedirectResponse("/login", status_code=303)

    async def logout(self, request: Request) -> Response | bool:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

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


class UserAdmin(ModelView, model=User):
    name = "Utilisateur"
    name_plural = "Utilisateurs"
    icon = "fa-solid fa-users"

    # Liste : jamais le hash du mot de passe ni les données chiffrées.
    column_list = [User.id, User.username, User.is_active, User.is_admin, User.created_at,
                   "credential.last_check_at"]
    column_labels = {
        User.username: "Identifiant",
        User.is_active: "Actif",
        User.is_admin: "Admin",
        User.created_at: "Créé le (UTC)",
        "credential.last_check_at": "Dernière vérification (UTC)",
    }
    column_details_list = [User.id, User.username, User.is_active, User.is_admin, User.created_at]
    column_export_list = [User.id, User.username, User.is_active, User.is_admin, User.created_at]
    column_searchable_list = [User.username]
    column_sortable_list = [User.id, User.username, User.created_at]
    column_filters = [BooleanFilter(User.is_admin, title="Admin"), BooleanFilter(User.is_active, title="Actif")]
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


def setup_admin(app: FastAPI) -> Admin:
    """Monte le panneau /admin sur l'application FastAPI."""

    @app.get("/admin/login", include_in_schema=False)
    def _admin_login() -> RedirectResponse:  # déclarée avant le montage : prioritaire sur /admin
        return RedirectResponse("/login", status_code=303)

    admin = Admin(
        app,
        engine,  # SQLAdmin crée sa propre sessionmaker (ne modifie pas SessionLocal)
        base_url="/admin",
        title=f"{get_settings().app_name} · Administration",
        authentication_backend=WebSessionAuthBackend(),
    )
    admin.add_view(UserAdmin)
    return admin
