"""Cibles déclarées et preuve de propriété par DNS TXT."""

from __future__ import annotations

import hmac
import ipaddress
import re
import secrets
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from app.domain.target import Target

if TYPE_CHECKING:
    from app.domain.ports import TargetRepository, TxtRecordResolver


class TargetNotFoundError(Exception):
    """La cible est absente ou appartient à un autre utilisateur."""


class TargetAlreadyRegisteredError(Exception):
    """Cet utilisateur a déjà déclaré ce domaine."""


class TargetNotVerifiedError(Exception):
    """La propriété de la cible doit être prouvée avant un scan."""


class OwnershipNotProvenError(Exception):
    """Le TXT attendu est absent."""


class DnsLookupError(Exception):
    """La résolution DNS a échoué."""


def normalize_domain(url_or_host: str) -> str:
    if not url_or_host or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url_or_host):
        raise ValueError("Invalid domain or URL")
    if "://" in url_or_host:
        parsed = urlsplit(url_or_host)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Scheme must be http or https")
        if "@" in parsed.netloc:
            raise ValueError("Userinfo is forbidden")
        if "[" in parsed.netloc or "]" in parsed.netloc:
            raise ValueError("IP literals are forbidden")
        if ":" in parsed.netloc and parsed.port not in {80, 443}:
            raise ValueError("Port must be 80 or 443")
        host = parsed.hostname or ""
    else:
        host = url_or_host
    try:
        domain = host.encode("idna").decode("ascii").lower().removesuffix(".")
    except UnicodeError as exc:
        raise ValueError("Invalid IDNA domain") from exc
    # Le codec idna (IDNA 2003) remplace certains caractères (faß.de -> fass.de) :
    # on refuserait sinon de prouver un autre domaine que celui déclaré.
    if not host.isascii():
        declared = re.sub("[。．｡]", ".", host).lower().removesuffix(".")
        if domain.encode("ascii").decode("idna") != declared:
            raise ValueError("Unsupported internationalized domain")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2:
        raise ValueError("Domain must contain multiple labels and at most 253 characters")
    if any(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels
    ):
        raise ValueError("Invalid domain label")
    if labels[-1] == "localhost":
        raise ValueError("Localhost is forbidden")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("IP literals are forbidden")


@dataclass(frozen=True)
class RegisteredTarget:
    id: uuid.UUID
    user_id: uuid.UUID
    domain: str
    verification_token: str
    created_at: datetime
    verified_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain", normalize_domain(self.domain))
        if not self.verification_token:
            raise ValueError("verification_token must not be empty")
        if self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if self.verified_at is not None and self.verified_at.utcoffset() is None:
            raise ValueError("verified_at must be timezone-aware")

    @classmethod
    def create(cls, user_id: uuid.UUID, url_or_host: str) -> RegisteredTarget:
        return cls(
            uuid.uuid4(),
            user_id,
            normalize_domain(url_or_host),
            secrets.token_urlsafe(32),
            datetime.now(UTC),
        )

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None

    @property
    def dns_record_name(self) -> str:
        return self.domain

    @property
    def dns_record_value(self) -> str:
        return f"scanner-verify={self.verification_token}"

    def mark_verified(self, at: datetime) -> RegisteredTarget:
        return replace(self, verified_at=at)

    def scan_target(self) -> Target:
        if not self.is_verified:
            raise TargetNotVerifiedError
        return Target(url=f"https://{self.domain}/")


def register_target(
    targets: TargetRepository, user_id: uuid.UUID, url_or_host: str
) -> RegisteredTarget:
    target = RegisteredTarget.create(user_id, url_or_host)
    targets.add(target)
    return target


def verify_target(
    targets: TargetRepository,
    resolver: TxtRecordResolver,
    user_id: uuid.UUID,
    target_id: uuid.UUID,
    now: datetime,
) -> RegisteredTarget:
    target = targets.get(target_id)
    if target is None or target.user_id != user_id:
        raise TargetNotFoundError
    if target.is_verified:
        return target
    expected = target.dns_record_value.encode("utf-8")
    for record in resolver.txt_records(target.dns_record_name):
        if hmac.compare_digest(record.strip().encode("utf-8"), expected):
            verified = target.mark_verified(now)
            targets.mark_verified(target.id, now)
            return verified
    raise OwnershipNotProvenError(
        f"Expected TXT record at {target.dns_record_name}: {target.dns_record_value}"
    )
