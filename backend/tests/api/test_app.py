import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select

from app.api.deps import SessionDep
from app.api.main import create_app
from app.config import Settings
from app.domain.user import User
from app.infra.models import UserModel
from app.infra.user_repository import SqlAlchemyUserRepository


def count_users(engine) -> int:
    with engine.connect() as connection:
        return connection.scalar(select(func.count()).select_from(UserModel))


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_reports_unavailable_database(migrated_engine):
    settings = Settings(
        _env_file=None,
        redis_url="redis://localhost:6380/0",
        database_url="postgresql+psycopg://scanner:scanner@127.0.0.1:1/none",
        jwt_secret="t" * 32,
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.get("/health")
    assert response.status_code == 503


def test_successful_request_commits(app, client, migrated_engine):
    @app.post("/_test/users")
    def add_user(session: SessionDep) -> None:
        SqlAlchemyUserRepository(session).add(User.create("remy@example.test", "hash"))

    assert client.post("/_test/users").status_code == 200
    assert count_users(migrated_engine) == 1


def test_failing_request_rolls_back(app, client, migrated_engine):
    @app.post("/_test/fail")
    def add_then_fail(session: SessionDep) -> None:
        SqlAlchemyUserRepository(session).add(User.create("remy@example.test", "hash"))
        raise RuntimeError("boom")

    assert client.post("/_test/fail").status_code == 500
    assert count_users(migrated_engine) == 0


def test_failing_commit_is_not_reported_as_success(app, client, migrated_engine):
    @app.post("/_test/late-conflict")
    def add_conflicting_users(session: SessionDep) -> None:
        # Pas de flush : le conflit n'éclate qu'au commit, après la fin de la route.
        session.add(UserModel(email="remy@example.test", password_hash="a"))
        session.add(UserModel(email="remy@example.test", password_hash="b"))

    assert client.post("/_test/late-conflict").status_code == 500
    assert count_users(migrated_engine) == 0


def test_each_app_has_its_own_settings(settings):
    assert create_app(settings).state.settings is settings


def test_invalid_configuration_prevents_startup(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x:y@localhost/z")
    from app.config import get_settings

    get_settings.cache_clear()
    try:
        with pytest.raises(ValidationError):
            create_app()
    finally:
        get_settings.cache_clear()
