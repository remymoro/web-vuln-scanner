"""Ports : ce dont le domaine a besoin, sans dire comment c'est fait."""

import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from app.domain.finding import Finding
from app.domain.scans import Scan
from app.domain.target import Target
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


class Scanner(Protocol):
    name: str

    def run(self, target: Target) -> list[Finding]: ...


class ScanRepository(Protocol):
    def add(self, scan: Scan) -> None: ...

    def get(self, scan_id: uuid.UUID) -> Scan | None: ...

    def get_active_for_target(self, target_id: uuid.UUID) -> Scan | None: ...

    def list_for_target(self, target_id: uuid.UUID) -> list[Scan]:
        """Les vingt derniers scans, du plus récent au plus ancien."""
        ...

    def list_for_target_since(self, target_id: uuid.UUID, since: datetime) -> list[Scan]: ...

    def save(self, scan: Scan) -> None: ...

    def replace_findings(self, scan_id: uuid.UUID, findings: Iterable[Finding]) -> None: ...

    def get_findings(self, scan_id: uuid.UUID) -> list[Finding]: ...


class ScanQueue(Protocol):
    def enqueue(self, scan_id: uuid.UUID) -> None:
        """Enfile le scan ; lève QueueUnavailableError si la file est injoignable."""
        ...
