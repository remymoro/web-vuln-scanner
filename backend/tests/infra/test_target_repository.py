import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.domain.ports import TargetRepository
from app.domain.targets import RegisteredTarget, TargetAlreadyRegisteredError
from app.domain.user import User
from app.infra.models import TargetModel, UserModel
from app.infra.target_repository import SqlAlchemyTargetRepository
from app.infra.user_repository import SqlAlchemyUserRepository


@pytest.fixture
def repository(db_session) -> TargetRepository:
    return SqlAlchemyTargetRepository(db_session)


@pytest.fixture
def user(db_session):
    user = User.create("remy@example.test", "hash")
    SqlAlchemyUserRepository(db_session).add(user)
    return user


@pytest.fixture
def target(repository, user):
    target = RegisteredTarget.create(user.id, "https://EXAMPLE.com:443/path")
    repository.add(target)
    return target


def test_add_then_get_returns_equal_domain_target(repository, target, db_session):
    db_session.expire_all()
    assert repository.get(target.id) == target
    assert repository.list_for_user(target.user_id) == [target]


def test_unknown_target_returns_none(repository):
    assert repository.get(uuid.uuid4()) is None


def test_list_only_returns_users_targets(repository, target, db_session):
    other_user = User.create("other@example.test", "hash")
    SqlAlchemyUserRepository(db_session).add(other_user)
    other_target = RegisteredTarget.create(other_user.id, "example.com")
    repository.add(other_target)
    assert repository.list_for_user(target.user_id) == [target]
    assert repository.list_for_user(other_user.id) == [other_target]
    assert repository.list_for_user(uuid.uuid4()) == []


def test_duplicate_domain_raises_domain_error_and_keeps_session_usable(repository, target):
    with pytest.raises(TargetAlreadyRegisteredError):
        repository.add(RegisteredTarget.create(target.user_id, "EXAMPLE.com."))
    other = RegisteredTarget.create(target.user_id, "other.example.com")
    repository.add(other)
    assert repository.get(target.id) == target
    assert repository.get(other.id) == other


def test_other_integrity_errors_are_not_translated(repository):
    with pytest.raises(IntegrityError, match="fk_targets_user_id_users"):
        repository.add(RegisteredTarget.create(uuid.uuid4(), "example.com"))
    assert repository.list_for_user(uuid.uuid4()) == []


def test_deleting_user_cascades_to_targets(repository, target, db_session):
    db_session.execute(delete(UserModel).where(UserModel.id == target.user_id))
    assert repository.get(target.id) is None


def test_mark_verified_updates_only_given_target(repository, target, db_session):
    other = RegisteredTarget.create(target.user_id, "other.example.com")
    repository.add(other)
    now = datetime.now(UTC)
    repository.mark_verified(target.id, now)
    db_session.expire_all()
    assert repository.get(target.id) == target.mark_verified(now)
    assert repository.get(other.id) == other


def test_add_preserves_verification_date(repository, user):
    target = RegisteredTarget.create(user.id, "example.com").mark_verified(datetime.now(UTC))
    repository.add(target)
    assert repository.get(target.id) == target


def test_target_defaults_are_filled(db_session, user):
    model = TargetModel(user_id=user.id, domain="example.com", verification_token="token")
    db_session.add(model)
    db_session.flush()
    db_session.refresh(model)
    assert isinstance(model.id, uuid.UUID)
    assert model.created_at.tzinfo is not None
    assert model.verified_at is None


def test_add_never_commits(repository, user, db_session):
    repository.add(RegisteredTarget.create(user.id, "example.com"))
    assert db_session.in_transaction()
    db_session.rollback()
    assert db_session.scalars(select(TargetModel)).all() == []


def test_mark_verified_never_commits(repository, target, db_session):
    repository.mark_verified(target.id, datetime.now(UTC))
    assert db_session.in_transaction()
    db_session.rollback()
    assert repository.get(target.id) is None
