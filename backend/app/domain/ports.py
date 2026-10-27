"""Ports : ce dont le domaine a besoin, sans dire comment c'est fait."""

import uuid
from datetime import datetime
from typing import Protocol

from app.domain.targets import RegisteredTarget
from app.domain.user import User


class UserRepository(Protocol):
    def add(self, user: User) -> None:
        """Enregistre l'utilisateur ; lève EmailAlreadyUsedError si l'email est pris."""
        ...

    def get_by_id(self, user_id: uuid.UUID) -> User | None: ...

    def get_by_email(self, email: str) -> User | None: ...

    def update_password_hash(self, user_id: uuid.UUID, password_hash: str) -> None: ...


class TargetRepository(Protocol):
    def add(self, target: RegisteredTarget) -> None:
        """Enregistre la cible ; lève TargetAlreadyRegisteredError en cas de doublon."""
        ...

    def get(self, target_id: uuid.UUID) -> RegisteredTarget | None: ...

    def list_for_user(self, user_id: uuid.UUID) -> list[RegisteredTarget]: ...

    def mark_verified(self, target_id: uuid.UUID, at: datetime) -> None: ...


class TxtRecordResolver(Protocol):
    def txt_records(self, name: str) -> list[str]:
        """TXT du nom exact ; [] si absent, DnsLookupError si le DNS est injoignable."""
        ...
