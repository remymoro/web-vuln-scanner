import uuid

import pytest

from app.domain.auth import (
    InvalidCredentialsError,
    InvalidPasswordError,
    authenticate_user,
    register_user,
)
from app.domain.ports import UserRepository
from app.domain.user import EmailAlreadyUsedError, User

PASSWORD = "correct horse battery"


class InMemoryUserRepository:
    def __init__(self):
        self.users: dict[uuid.UUID, User] = {}

    def add(self, user: User) -> None:
        if self.get_by_email(user.email) is not None:
            raise EmailAlreadyUsedError(user.email)
        self.users[user.id] = user

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self.users.get(user_id)

    def get_by_email(self, email: str) -> User | None:
        return next((u for u in self.users.values() if u.email == email.strip().lower()), None)

    def update_password_hash(self, user_id: uuid.UUID, password_hash: str) -> None:
        user = self.users[user_id]
        self.users[user_id] = User(user.id, user.email, password_hash, user.created_at)


class FakeHasher:
    """Hash lisible : "v1:<mot de passe>". Note chaque vérification."""

    def __init__(self, version: str = "v1"):
        self.version = version
        self.verified: list[str | None] = []

    def hash(self, password: str) -> str:
        return f"{self.version}:{password}"

    def verify(self, password_hash: str | None, password: str) -> bool:
        self.verified.append(password_hash)
        return password_hash is not None and password_hash.split(":", 1)[1] == password

    def needs_rehash(self, password_hash: str) -> bool:
        return not password_hash.startswith(f"{self.version}:")


@pytest.fixture
def users() -> UserRepository:
    return InMemoryUserRepository()


def test_register_stores_hash_not_password(users):
    user = register_user(users, FakeHasher(), "Remy@Example.test", PASSWORD)
    assert users.get_by_id(user.id) == user
    assert user.email == "remy@example.test"
    assert user.password_hash == f"v1:{PASSWORD}"


@pytest.mark.parametrize("password", ["a" * 11, "a" * 129])
def test_register_enforces_password_policy(users, password):
    with pytest.raises(InvalidPasswordError):
        register_user(users, FakeHasher(), "remy@example.test", password)
    assert users.users == {}


def test_register_duplicate_email(users):
    register_user(users, FakeHasher(), "remy@example.test", PASSWORD)
    with pytest.raises(EmailAlreadyUsedError):
        register_user(users, FakeHasher(), "REMY@example.test", PASSWORD)


def test_authenticate_success(users):
    user = register_user(users, FakeHasher(), "remy@example.test", PASSWORD)
    assert authenticate_user(users, FakeHasher(), " Remy@example.test", PASSWORD) == user


def test_wrong_password_and_unknown_email_look_the_same(users):
    register_user(users, FakeHasher(), "remy@example.test", PASSWORD)
    hasher = FakeHasher()
    with pytest.raises(InvalidCredentialsError):
        authenticate_user(users, hasher, "remy@example.test", "wrong password!")
    with pytest.raises(InvalidCredentialsError):
        authenticate_user(users, hasher, "nobody@example.test", PASSWORD)
    # L'email inconnu déclenche aussi une vérification (factice) : même durée.
    assert hasher.verified == [f"v1:{PASSWORD}", None]


def test_overlong_password_is_rejected_without_hashing(users):
    hasher = FakeHasher()
    with pytest.raises(InvalidCredentialsError):
        authenticate_user(users, hasher, "remy@example.test", "a" * 129)
    assert hasher.verified == []


def test_outdated_hash_is_upgraded_on_login(users):
    user = register_user(users, FakeHasher("v1"), "remy@example.test", PASSWORD)
    authenticate_user(users, FakeHasher("v2"), "remy@example.test", PASSWORD)
    assert users.get_by_id(user.id).password_hash == f"v2:{PASSWORD}"
