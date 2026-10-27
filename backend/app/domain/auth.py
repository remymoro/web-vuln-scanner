"""Cas d'usage d'authentification : ils ne connaissent que les ports, jamais argon2 ni la base."""

from typing import Protocol

from app.domain.ports import UserRepository
from app.domain.user import User

MIN_PASSWORD_LENGTH = 12
# Borne haute : un mot de passe énorme ferait travailler argon2 pour rien.
MAX_PASSWORD_LENGTH = 128


class InvalidPasswordError(ValueError):
    """Le mot de passe ne respecte pas la politique."""


class InvalidCredentialsError(Exception):
    """Email inconnu ou mot de passe faux : volontairement indiscernables."""


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password_hash: str | None, password: str) -> bool:
        """Avec None, fait un calcul factice de même durée et renvoie False."""
        ...

    def needs_rehash(self, password_hash: str) -> bool: ...


def check_password_policy(password: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise InvalidPasswordError(
            f"password must be {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters"
        )


def register_user(users: UserRepository, hasher: PasswordHasher, email: str, password: str) -> User:
    check_password_policy(password)
    user = User.create(email, hasher.hash(password))
    users.add(user)
    return user


def authenticate_user(
    users: UserRepository, hasher: PasswordHasher, email: str, password: str
) -> User:
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InvalidCredentialsError
    user = users.get_by_email(email)
    # Même travail que l'email existe ou non : la durée ne révèle pas les comptes.
    password_hash = None if user is None else user.password_hash
    if not hasher.verify(password_hash, password) or user is None:
        raise InvalidCredentialsError
    if hasher.needs_rehash(user.password_hash):
        users.update_password_hash(user.id, hasher.hash(password))
    return user
