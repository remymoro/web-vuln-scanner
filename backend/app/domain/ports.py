"""Ports : ce dont le domaine a besoin, sans dire comment c'est fait."""

import uuid
from typing import Protocol

from app.domain.user import User


class UserRepository(Protocol):
    def add(self, user: User) -> None:
        """Enregistre l'utilisateur ; lève EmailAlreadyUsedError si l'email est pris."""
        ...

    def get_by_id(self, user_id: uuid.UUID) -> User | None: ...

    def get_by_email(self, email: str) -> User | None: ...

    def update_password_hash(self, user_id: uuid.UUID, password_hash: str) -> None: ...
