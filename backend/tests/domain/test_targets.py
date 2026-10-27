import uuid
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from app.domain.target import Target
from app.domain.targets import (
    DnsLookupError,
    OwnershipNotProvenError,
    RegisteredTarget,
    TargetAlreadyRegisteredError,
    TargetNotFoundError,
    TargetNotVerifiedError,
    normalize_domain,
    register_target,
    verify_target,
)
from tests.fakes import FakeTxtResolver


class InMemoryTargetRepository:
    def __init__(self):
        self.targets: dict[uuid.UUID, RegisteredTarget] = {}

    def add(self, target: RegisteredTarget) -> None:
        if any(t.domain == target.domain for t in self.list_for_user(target.user_id)):
            raise TargetAlreadyRegisteredError(target.domain)
        self.targets[target.id] = target

    def get(self, target_id: uuid.UUID) -> RegisteredTarget | None:
        return self.targets.get(target_id)

    def list_for_user(self, user_id: uuid.UUID) -> list[RegisteredTarget]:
        return [t for t in self.targets.values() if t.user_id == user_id]

    def mark_verified(self, target_id: uuid.UUID, at: datetime) -> None:
        self.targets[target_id] = self.targets[target_id].mark_verified(at)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("www.Example.COM.", "www.example.com"),
        ("https://Example.COM/path?query=1#fragment", "example.com"),
        ("HTTP://EXAMPLE.COM:80/", "example.com"),
        ("https://example.com:443/", "example.com"),
        ("http://example.com:443/", "example.com"),
        ("https://example.com:80/", "example.com"),
        ("https://example.com./", "example.com"),
        ("https://BÜCHER.de:443/books", "xn--bcher-kva.de"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("例え.テスト", "xn--r8jz45g.xn--zckzah"),
        ("example。com。", "example.com"),
        ("my-site.example.com", "my-site.example.com"),
        ("a" * 63 + ".com", "a" * 63 + ".com"),
        (".".join(["a" * 63] * 3 + ["b" * 61]), ".".join(["a" * 63] * 3 + ["b" * 61])),
    ],
)
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "LOCALHOST.",
        "app.localhost",
        "a.b.localhost.",
        "example",
        "127.0.0.1",
        "https://127.0.0.1:443/",
        "https://127.0.0.1./",
        "::1",
        "[::1]",
        "https://[::1]/",
        "https://[2001:4860:4860::8888]/",
        "ftp://example.com/",
        "mailto:hello@example.com",
        "https:example.com",
        "https://user@example.com/",
        "https://user:pass@example.com/",
        "https://@example.com/",
        "user@example.com",
        "https://example.com:8080/",
        "https://example.com:/",
        "https://example.com:abc/",
        "https://example.com:65536/",
        "example.com:443",
        "https:///example.com",
        "https://",
        "//example.com",
        "example.com/path",
        "example.com?query=1",
        "example.com#fragment",
        ".example.com",
        "a..example.com",
        "example.com..",
        "-example.com",
        "example-.com",
        "under_score.example.com",
        "*.example.com",
        "exa%mple.com",
        "https://example.com\\evil.com/",
        " example.com",
        "example.com ",
        "https://exa\nmple.com/",
        "example.com\x00",
        "https://example.com\t/",
        "a" * 64 + ".com",
        ".".join(["a" * 63] * 4),
        "https://[example.com]/",
        "https://[broken/",
        "\ud800.example.com",
        # IDNA 2003 les transformerait en un autre domaine (fass.de, example.com).
        "faß.de",
        "ｅxample.com",
    ],
)
def test_normalize_domain_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        normalize_domain(value)


@pytest.fixture
def targets():
    return InMemoryTargetRepository()


@pytest.fixture
def target(targets):
    return register_target(targets, uuid.uuid4(), "https://EXAMPLE.com/path")


def test_create_generates_token_and_utc_date():
    user_id = uuid.uuid4()
    first = RegisteredTarget.create(user_id, "EXAMPLE.com")
    second = RegisteredTarget.create(user_id, "example.com")
    assert isinstance(first.id, uuid.UUID)
    assert first.id != second.id
    assert first.user_id == user_id
    assert first.domain == "example.com"
    assert len(first.verification_token) == 43
    assert first.verification_token != second.verification_token
    assert first.created_at.utcoffset() == timedelta(0)
    assert not first.is_verified
    assert first.verified_at is None
    assert first.dns_record_name == "example.com"
    assert first.dns_record_value == f"scanner-verify={first.verification_token}"
    with pytest.raises(FrozenInstanceError):
        first.domain = "other.com"


def test_entity_requires_token_and_aware_dates(target):
    with pytest.raises(ValueError):
        replace(target, verification_token="")
    with pytest.raises(ValueError):
        replace(target, created_at=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        target.mark_verified(datetime(2026, 1, 1))


def test_only_verified_target_can_be_scanned(target):
    with pytest.raises(TargetNotVerifiedError):
        target.scan_target()
    now = datetime.now(UTC)
    verified = target.mark_verified(now)
    assert verified is not target
    assert not target.is_verified
    assert verified.is_verified
    assert verified.verified_at == now
    assert verified.scan_target() == Target(url="https://example.com/")


def test_register_stores_normalized_target_and_rejects_duplicate(targets, target):
    assert targets.get(target.id) == target
    with pytest.raises(TargetAlreadyRegisteredError):
        register_target(targets, target.user_id, "example.com.")
    other = register_target(targets, uuid.uuid4(), "example.com")
    assert other.user_id != target.user_id


def test_register_rejects_invalid_url_without_storing(targets):
    with pytest.raises(ValueError):
        register_target(targets, uuid.uuid4(), "ftp://example.com")
    assert targets.targets == {}


@pytest.mark.parametrize("padding", ["", " \t\n"])
def test_verify_accepts_exact_txt_with_surrounding_spaces(targets, target, padding):
    resolver = FakeTxtResolver(["unrelated TXT", padding + target.dns_record_value + padding])
    now = datetime.now(UTC)
    verified = verify_target(targets, resolver, target.user_id, target.id, now)
    assert verified == target.mark_verified(now)
    assert targets.get(target.id) == verified
    assert resolver.calls == ["example.com"]


@pytest.mark.parametrize(
    "record",
    [
        None,
        "{value}x",
        "x{value}",
        "{value} other",
        '"{value}"',
        "{value}\u00e9",
        "SCANNER-VERIFY={token}",
        "scanner-verify= {token}",
    ],
)
def test_verify_rejects_missing_or_almost_matching_txt(targets, target, record):
    records = (
        []
        if record is None
        else [record.format(value=target.dns_record_value, token=target.verification_token)]
    )
    resolver = FakeTxtResolver(records)
    with pytest.raises(OwnershipNotProvenError) as caught:
        verify_target(targets, resolver, target.user_id, target.id, datetime.now(UTC))
    assert target.dns_record_name in str(caught.value)
    assert target.dns_record_value in str(caught.value)
    assert not targets.get(target.id).is_verified


@pytest.mark.parametrize("missing", [False, True])
def test_missing_and_other_users_target_are_hidden_without_dns(targets, target, missing):
    resolver = FakeTxtResolver([target.dns_record_value])
    with pytest.raises(TargetNotFoundError):
        verify_target(
            targets,
            resolver,
            uuid.uuid4(),
            uuid.uuid4() if missing else target.id,
            datetime.now(UTC),
        )
    assert resolver.calls == []


def test_already_verified_skips_dns_and_keeps_timestamp(targets, target):
    now = datetime.now(UTC)
    targets.mark_verified(target.id, now)
    resolver = FakeTxtResolver(error=DnsLookupError())
    verified = verify_target(targets, resolver, target.user_id, target.id, now + timedelta(days=1))
    assert verified.verified_at == now
    assert resolver.calls == []


def test_dns_failure_does_not_verify_target(targets, target):
    with pytest.raises(DnsLookupError):
        verify_target(
            targets,
            FakeTxtResolver(error=DnsLookupError()),
            target.user_id,
            target.id,
            datetime.now(UTC),
        )
    assert not targets.get(target.id).is_verified


def test_parent_domains_proof_does_not_verify_subdomain(targets, target):
    resolver = FakeTxtResolver([target.dns_record_value])
    verify_target(targets, resolver, target.user_id, target.id, datetime.now(UTC))
    subdomain = register_target(targets, target.user_id, "www.example.com")
    with pytest.raises(OwnershipNotProvenError):
        verify_target(targets, resolver, target.user_id, subdomain.id, datetime.now(UTC))
    assert resolver.calls == ["example.com", "www.example.com"]
    assert not targets.get(subdomain.id).is_verified
