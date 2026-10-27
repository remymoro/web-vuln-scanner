import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.api.tokens import InvalidTokenError, create_access_token, decode_access_token
from app.config import Settings

SECRET = "t" * 32


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        database_url="postgresql+psycopg://x:y@localhost/z",
        jwt_secret=SECRET,
        access_token_minutes=15,
    )


def test_round_trip(settings):
    user_id = uuid.uuid4()
    assert decode_access_token(create_access_token(user_id, settings), settings) == user_id


def test_expiry_follows_settings(settings):
    now = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
    claims = jwt.decode(
        create_access_token(uuid.uuid4(), settings, now=now),
        SECRET,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert claims["exp"] - claims["iat"] == 15 * 60


def test_expired_token(settings):
    past = datetime.now(UTC) - timedelta(hours=1)
    with pytest.raises(InvalidTokenError):
        decode_access_token(create_access_token(uuid.uuid4(), settings, now=past), settings)


def forge(claims, key=SECRET, algorithm="HS256"):
    return jwt.encode(claims, key, algorithm=algorithm)


def valid_claims(**overrides):
    now = datetime.now(UTC)
    return {"sub": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(minutes=5)} | overrides


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(forge(valid_claims(), key="w" * 32), id="wrong-secret"),
        pytest.param(forge(valid_claims(), key=None, algorithm="none"), id="alg-none"),
        pytest.param(forge(valid_claims(), key="h" * 64, algorithm="HS512"), id="other-alg"),
        pytest.param(forge({k: v for k, v in valid_claims().items() if k != "sub"}), id="no-sub"),
        pytest.param(forge({k: v for k, v in valid_claims().items() if k != "exp"}), id="no-exp"),
        pytest.param(forge(valid_claims(sub="not-a-uuid")), id="bad-sub"),
        pytest.param("not.a.jwt", id="garbage"),
    ],
)
def test_invalid_tokens_are_rejected(settings, token):
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings)


def test_tampered_token_is_rejected(settings):
    header, payload, signature = create_access_token(uuid.uuid4(), settings).split(".")
    forged_payload = jwt.utils.base64url_encode(b'{"sub":"' + str(uuid.uuid4()).encode() + b'"}')
    with pytest.raises(InvalidTokenError):
        decode_access_token(f"{header}.{forged_payload.decode()}.{signature}", settings)
