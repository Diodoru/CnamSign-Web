"""Notifications par e-mail (texte + HTML), envoyées à l'adresse Le Cnam de l'utilisateur.

Deux modes d'envoi :
- relais global : variables SMTP_* définies dans l'environnement ;
- repli : sans relais, l'utilisateur s'envoie le mail à lui-même via
  smtp.office365.com:587 avec ses propres identifiants Le Cnam (déchiffrés en mémoire).

Le notifier est appelé depuis les threads du planificateur ou depuis des routes
synchrones (threadpool FastAPI) : `smtplib` bloquant ne gêne donc pas la boucle async.
"""
from __future__ import annotations

import html
import logging
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from app.config import Settings
from app.models import CnamCredential, LogStatus, NotificationSetting
from app.security import CredentialCipher, DecryptionError

logger = logging.getLogger(__name__)

_TEMPLATES = {
    LogStatus.SUCCESS: ("✅ Émargement réussi", "#16a34a"),
    LogStatus.FAILED: ("❌ Échec de l'émargement", "#dc2626"),
}


@dataclass(frozen=True)
class SmtpTarget:
    host: str
    port: int
    username: str | None
    password: str | None = field(repr=False)
    from_email: str
    use_tls: bool
    is_fallback: bool


class Notifier:
    def __init__(self, settings: Settings, cipher: CredentialCipher) -> None:
        self._settings = settings
        self._cipher = cipher

    @property
    def dashboard_url(self) -> str:
        return self._settings.app_base_url.rstrip("/") + "/dashboard"

    # --- API publique -------------------------------------------------------------

    def recipient(self, credential: CnamCredential) -> str:
        """Adresse Le Cnam de l'utilisateur : destinataire de toutes ses notifications."""
        return self._cipher.decrypt(credential.encrypted_cnam_username)

    @staticmethod
    def should_notify(setting: NotificationSetting | None, status: LogStatus) -> bool:
        if setting is None:  # préférences jamais enregistrées : valeurs par défaut (tout activé)
            return True
        return setting.notify_on_success if status is LogStatus.SUCCESS else setting.notify_on_failure

    def notify(
        self,
        credential: CnamCredential,
        setting: NotificationSetting | None,
        status: LogStatus,
        message: str,
        session_code: str | None = None,
    ) -> list[str]:
        """Envoie l'e-mail si l'utilisateur l'a demandé. Ne lève jamais d'exception."""
        if not self.should_notify(setting, status):
            return []
        title, color = _TEMPLATES[status]
        details = [("Code de session", session_code)] if session_code else []
        return self._send(credential, title, message, color, details)

    def send_test(self, credential: CnamCredential) -> list[str]:
        return self._send(credential, "🔔 Test de notification",
                          "Vos notifications CnamSign Web fonctionnent.", "#4f46e5", [])

    # --- Interne -----------------------------------------------------------------

    def _send(
        self, credential: CnamCredential, title: str, message: str, color: str, details: list[tuple[str, str]]
    ) -> list[str]:
        try:
            recipient = self.recipient(credential)
            target = self._smtp_target(credential)
        except DecryptionError as exc:
            logger.warning("Notification impossible (utilisateur %s) : %s", credential.user_id, exc)
            return [str(exc)]

        mail = self._build_message(target.from_email, recipient, title, message, color, details)
        try:
            self._deliver(target, mail)
        except (smtplib.SMTPException, OSError) as exc:
            hint = (
                " (repli Office 365 : l'authentification SMTP est peut-être désactivée sur le compte Le Cnam ;"
                " configurez un relais SMTP global)"
                if target.is_fallback
                else ""
            )
            logger.warning("E-mail non envoyé (utilisateur %s, %s) : %s", credential.user_id, target.host, exc)
            return [f"Envoi via {target.host} impossible : {exc}{hint}"]
        return []

    def _smtp_target(self, credential: CnamCredential) -> SmtpTarget:
        s = self._settings
        if s.smtp_configured:
            return SmtpTarget(
                host=s.smtp_host or "",
                port=s.smtp_port,
                username=s.smtp_username,
                password=s.smtp_password,
                from_email=s.smtp_from_email or s.smtp_username or "",
                use_tls=s.smtp_use_tls,
                is_fallback=False,
            )
        # Repli : le compte Le Cnam de l'utilisateur s'envoie le mail à lui-même.
        username = self._cipher.decrypt(credential.encrypted_cnam_username)
        return SmtpTarget(
            host=s.smtp_fallback_host,
            port=s.smtp_fallback_port,
            username=username,
            password=self._cipher.decrypt(credential.encrypted_cnam_password),
            from_email=username,
            use_tls=True,
            is_fallback=True,
        )

    def _build_message(
        self, sender: str, recipient: str, title: str, message: str, color: str, details: list[tuple[str, str]]
    ) -> EmailMessage:
        app_name = self._settings.app_name
        mail = EmailMessage()
        mail["Subject"] = f"[{app_name}] {title}"
        mail["From"] = sender
        mail["To"] = recipient
        mail["Date"] = formatdate(localtime=True)
        mail["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1] or None)

        text_details = "".join(f"{label} : {value}\n" for label, value in details)
        mail.set_content(f"{title}\n\n{message}\n\n{text_details}\nTableau de bord : {self.dashboard_url}\n")

        e = html.escape
        rows = "".join(
            f'<tr><td style="padding:4px 12px 4px 0;color:#64748b">{e(label)}</td>'
            f'<td style="padding:4px 0;font-family:monospace;font-size:15px">{e(value)}</td></tr>'
            for label, value in details
        )
        mail.add_alternative(
            f"""<!doctype html>
<html lang="fr"><body style="margin:0;background:#f8fafc;font-family:Segoe UI,Arial,sans-serif;color:#1e293b">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
           style="max-width:520px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px">
      <tr><td style="padding:20px 24px;border-top:4px solid {color};border-radius:12px 12px 0 0">
        <h1 style="margin:0 0 12px;font-size:18px">{e(title)}</h1>
        <p style="margin:0 0 16px;line-height:1.5">{e(message)}</p>
        <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:20px">{rows}</table>
        <a href="{e(self.dashboard_url)}"
           style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px">
          Ouvrir le tableau de bord</a>
      </td></tr>
    </table>
    <p style="font-size:12px;color:#94a3b8;margin-top:12px">{e(app_name)} — notification automatique</p>
  </td></tr></table>
</body></html>""",
            subtype="html",
        )
        return mail

    @staticmethod
    def _deliver(target: SmtpTarget, mail: EmailMessage) -> None:
        smtp_cls = smtplib.SMTP_SSL if target.port == 465 else smtplib.SMTP
        with smtp_cls(target.host, target.port, timeout=20) as smtp:
            if smtp_cls is smtplib.SMTP and target.use_tls:
                smtp.starttls()
            if target.username and target.password:
                smtp.login(target.username, target.password)
            smtp.send_message(mail)
