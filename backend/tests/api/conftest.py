import pytest
from argon2 import PasswordHasher as Argon2
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api.main import create_app
from app.config import Settings
from app.infra.passwords import Argon2PasswordHasher
from tests.conftest import TEST_DATABASE_URL


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, database_url=TEST_DATABASE_URL, jwt_secret="t" * 32)


@pytest.fixture
def app(settings, migrated_engine):
    # argon2 au minimum : mêmes chemins de code, tests rapides.
    hasher = Argon2PasswordHasher(Argon2(time_cost=1, memory_cost=8, parallelism=1))
    return create_app(settings, password_hasher=hasher)


@pytest.fixture
def client(app, migrated_engine):
    # Les routes valident vraiment leurs transactions : on vide les tables après chaque test.
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    with migrated_engine.begin() as connection:
        connection.execute(text("TRUNCATE users"))
