import uuid
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from app.domain.user import User, normalize_email


def test_create_generates_id_and_aware_timestamp():
    user = User.create("remy@example.test", "hash")
    assert isinstance(user.id, uuid.UUID)
    assert user.created_at.tzinfo is not None
    assert User.create("remy@example.test", "hash").id != user.id


def test_email_is_normalized():
    assert User.create("  Remy@Example.TEST ", "hash").email == "remy@example.test"


@pytest.mark.parametrize("email", ["", "remy", "@example.test", "remy@", "a@b@c", "   "])
def test_invalid_email_is_rejected(email):
    with pytest.raises(ValueError, match="email"):
        normalize_email(email)


def test_empty_password_hash_is_rejected():
    with pytest.raises(ValueError, match="password_hash"):
        User.create("remy@example.test", "")


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError, match="timezone"):
        User(uuid.uuid4(), "remy@example.test", "hash", datetime(2026, 1, 1))


def test_user_is_immutable():
    user = User(uuid.uuid4(), "remy@example.test", "hash", datetime.now(UTC))
    with pytest.raises(FrozenInstanceError):
        user.email = "other@example.test"
