"""Adaptateur argon2 du port PasswordHasher."""

import secrets

from argon2 import PasswordHasher as Argon2
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Argon2PasswordHasher:
    def __init__(self, argon2: Argon2 | None = None) -> None:
        self._argon2 = argon2 if argon2 is not None else Argon2()
        # Hash jetable mais aux mêmes paramètres : vérifier un email inconnu coûte autant.
        self._dummy_hash = self._argon2.hash(secrets.token_urlsafe(32))

    def hash(self, password: str) -> str:
        return self._argon2.hash(password)

    def verify(self, password_hash: str | None, password: str) -> bool:
        try:
            self._argon2.verify(password_hash or self._dummy_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        return password_hash is not None

    def needs_rehash(self, password_hash: str) -> bool:
        return self._argon2.check_needs_rehash(password_hash)
