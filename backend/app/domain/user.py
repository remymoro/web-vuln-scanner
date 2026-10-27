import uuid
from dataclasses import dataclass
from datetime import UTC, datetime


class EmailAlreadyUsedError(Exception):
    """Un compte existe déjà pour cet email."""


def normalize_email(email: str) -> str:
    # Remy@Example.test et remy@example.test désignent le même compte.
    normalized = email.strip().lower()
    local, separator, domain = normalized.partition("@")
    if not separator or not local or not domain or "@" in domain:
        raise ValueError(f"Invalid email: {email!r}")
    return normalized


@dataclass(frozen=True)
class User:
    id: uuid.UUID
    email: str
    password_hash: str
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "email", normalize_email(self.email))
        if not self.password_hash:
            raise ValueError("password_hash must not be empty")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")

    @classmethod
    def create(cls, email: str, password_hash: str) -> "User":
        return cls(uuid.uuid4(), email, password_hash, datetime.now(UTC))
