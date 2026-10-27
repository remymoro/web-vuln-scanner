import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.infra.db import create_db_engine

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://scanner:scanner@localhost:5433/scanner_test"
)
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6380/0")


@pytest.fixture
def redis_connection():
    connection = Redis.from_url(TEST_REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
    try:
        connection.flushdb()
    except RedisError:
        connection.close()
        pytest.fail(
            "Redis de test injoignable. Lancer : "
            "docker compose -f docker-compose.test.yml up -d --wait",
            pytrace=False,
        )
    try:
        yield connection
    finally:
        connection.flushdb()
        connection.close()


def alembic_config() -> Config:
    config = Config(Path(__file__).resolve().parents[1] / "alembic.ini")
    config.attributes["database_url"] = TEST_DATABASE_URL
    return config


@pytest.fixture(scope="session")
def migrated_engine():
    engine = create_db_engine(TEST_DATABASE_URL)
    try:
        with engine.connect():
            pass
    except OperationalError:
        pytest.fail(
            "PostgreSQL de test injoignable. Lancer : "
            "docker compose -f docker-compose.test.yml up -d --wait",
            pytrace=False,
        )
    # Repartir d'un schéma vide, puis appliquer toutes les migrations.
    command.downgrade(alembic_config(), "base")
    command.upgrade(alembic_config(), "head")
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(migrated_engine):
    # Chaque test écrit dans une transaction annulée à la fin : la base reste propre.
    with migrated_engine.connect() as connection:
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()
