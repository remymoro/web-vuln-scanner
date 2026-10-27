import uuid

import pytest
from sqlalchemy import select

from app.domain.ports import UserRepository
from app.domain.user import EmailAlreadyUsedError, User
from app.infra.models import UserModel
from app.infra.user_repository import SqlAlchemyUserRepository


@pytest.fixture
def repository(db_session) -> UserRepository:
    return SqlAlchemyUserRepository(db_session)


def test_add_then_get_returns_an_equal_domain_user(repository):
    user = User.create("remy@example.test", "hash")
    repository.add(user)
    assert repository.get_by_id(user.id) == user
    assert repository.get_by_email("remy@example.test") == user


def test_get_by_email_ignores_case_and_spaces(repository):
    user = User.create("remy@example.test", "hash")
    repository.add(user)
    assert repository.get_by_email("  REMY@example.TEST ") == user


@pytest.mark.parametrize("email", ["missing@example.test", "not-an-email"])
def test_unknown_email_returns_none(repository, email):
    assert repository.get_by_email(email) is None


def test_unknown_id_returns_none(repository):
    assert repository.get_by_id(uuid.uuid4()) is None


def test_duplicate_email_raises_domain_error_and_keeps_session_usable(repository, db_session):
    first = User.create("remy@example.test", "hash")
    repository.add(first)
    with pytest.raises(EmailAlreadyUsedError):
        repository.add(User.create("Remy@Example.test", "other"))
    # Le doublon est annulé seul : le premier compte reste et la session fonctionne.
    other = User.create("other@example.test", "hash")
    repository.add(other)
    assert db_session.scalars(select(UserModel.email).order_by(UserModel.email)).all() == [
        "other@example.test",
        "remy@example.test",
    ]


def test_update_password_hash(repository):
    user = User.create("remy@example.test", "old")
    other = User.create("other@example.test", "keep")
    repository.add(user)
    repository.add(other)
    repository.update_password_hash(user.id, "new")
    assert repository.get_by_id(user.id).password_hash == "new"
    assert repository.get_by_id(other.id).password_hash == "keep"


def test_update_password_hash_rejects_empty_hash(repository):
    with pytest.raises(ValueError):
        repository.update_password_hash(uuid.uuid4(), "")


def test_repository_never_commits(repository, db_session):
    repository.add(User.create("remy@example.test", "hash"))
    assert db_session.in_transaction()
    db_session.rollback()
    assert repository.get_by_email("remy@example.test") is None
