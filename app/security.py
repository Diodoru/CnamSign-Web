"""Hachage des mots de passe web (Argon2id) et chiffrement des secrets CNAM (Fernet)."""
from __future__ import annotations

import hmac
import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import get_settings

# --- Mots de passe de l'application web ---------------------------------------

_hasher = PasswordHasher()  # Argon2id, paramètres par défaut recommandés


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


# --- Chiffrement au repos des identifiants CNAM -------------------------------


class DecryptionError(RuntimeError):
    """Jeton illisible : mauvaise clé maître ou donnée corrompue."""


class CredentialCipher:
    """Chiffrement symétrique authentifié des secrets stockés en base.

    Fernet = AES-CBC + HMAC-SHA256 avec une clé de 256 bits (dont 128 bits pour AES).
    Plusieurs clés peuvent être fournies, séparées par des virgules : la première
    chiffre, toutes peuvent déchiffrer (rotation de clé sans interruption).
    """

    def __init__(self, keys: str) -> None:
        try:
            fernets = [Fernet(key.strip().encode()) for key in keys.split(",") if key.strip()]
        except ValueError as exc:
            raise ValueError(
                "SECRET_ENCRYPTION_KEY invalide : clé Fernet attendue (32 octets en base64 url-safe)."
            ) from exc
        if not fernets:
            raise ValueError("SECRET_ENCRYPTION_KEY vide.")
        self._fernet = MultiFernet(fernets)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise DecryptionError("Impossible de déchiffrer le secret (clé maître différente ?)") from exc

    def rotate(self, token: str) -> str:
        """Re-chiffre un jeton avec la clé primaire actuelle."""
        return self._fernet.rotate(token.encode("ascii")).decode("ascii")


@lru_cache
def get_cipher() -> CredentialCipher:
    return CredentialCipher(get_settings().secret_encryption_key)


# --- CSRF ----------------------------------------------------------------------


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_tokens_match(expected: str | None, received: str | None) -> bool:
    return bool(expected and received) and hmac.compare_digest(expected, received)
