import uuid

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from app.infra.db import Base
from app.infra.models import UserModel
from tests.conftest import alembic_config


def test_migrations_round_trip(migrated_engine):
    command.downgrade(alembic_config(), "base")
    assert not inspect(migrated_engine).has_table("users")
    command.upgrade(alembic_config(), "head")
    assert inspect(migrated_engine).has_table("users")


def test_models_match_migrations(migrated_engine):
    # Un modèle modifié sans nouvelle migration ferait échouer ce test.
    with migrated_engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []


def test_user_defaults_are_filled(db_session):
    user = UserModel(email="remy@example.test", password_hash="hash")
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    assert isinstance(user.id, uuid.UUID)
    assert user.created_at.tzinfo is not None
    assert db_session.scalar(select(UserModel.email).where(UserModel.id == user.id)) == (
        "remy@example.test"
    )


def test_email_is_unique(db_session):
    db_session.add(UserModel(email="same@example.test", password_hash="a"))
    db_session.flush()
    db_session.add(UserModel(email="same@example.test", password_hash="b"))
    with pytest.raises(IntegrityError, match="uq_users_email"):
        db_session.flush()


def test_each_test_starts_with_an_empty_table(db_session):
    assert db_session.scalars(select(UserModel)).all() == []
