import pytest
from argon2 import PasswordHasher as Argon2

from app.domain.auth import PasswordHasher
from app.infra.passwords import Argon2PasswordHasher

FAST = {"time_cost": 1, "memory_cost": 8, "parallelism": 1}


@pytest.fixture
def hasher() -> PasswordHasher:
    return Argon2PasswordHasher(Argon2(**FAST))


def test_hash_is_salted_argon2id(hasher):
    first, second = hasher.hash("secret password"), hasher.hash("secret password")
    assert first.startswith("$argon2id$")
    assert first != second
    assert "secret password" not in first


def test_verify(hasher):
    password_hash = hasher.hash("secret password")
    assert hasher.verify(password_hash, "secret password")
    assert not hasher.verify(password_hash, "other password")


@pytest.mark.parametrize("password_hash", [None, "", "not-a-hash", "$argon2id$broken"])
def test_verify_never_accepts_missing_or_invalid_hash(hasher, password_hash):
    assert not hasher.verify(password_hash, "secret password")


def test_needs_rehash_when_parameters_change(hasher):
    old_hash = hasher.hash("secret password")
    stronger = Argon2PasswordHasher(Argon2(**{**FAST, "time_cost": 2}))
    assert not hasher.needs_rehash(old_hash)
    assert stronger.needs_rehash(old_hash)
