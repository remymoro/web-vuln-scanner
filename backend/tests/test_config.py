import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings

DATABASE_URL = "postgresql+psycopg://scanner:scanner@localhost:5432/scanner"
SECRET = "s" * 32


@pytest.fixture
def env(monkeypatch, tmp_path):
    # Isoler du .env et de l'environnement du poste de développement.
    monkeypatch.chdir(tmp_path)
    for name in ("DATABASE_URL", "JWT_SECRET", "JWT_ALGORITHM", "ACCESS_TOKEN_MINUTES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("JWT_SECRET", SECRET)
    return monkeypatch


def test_reads_environment_with_defaults(env):
    settings = Settings()
    assert settings.database_url == DATABASE_URL
    assert settings.jwt_secret.get_secret_value() == SECRET
    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_minutes == 30


def test_secret_is_hidden_in_repr(env):
    assert SECRET not in repr(Settings())


def test_reads_dotenv_file(env, tmp_path):
    env.delenv("JWT_SECRET")
    (tmp_path / ".env").write_text(f"JWT_SECRET={'d' * 32}\n", encoding="utf-8")
    assert Settings().jwt_secret.get_secret_value() == "d" * 32


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("JWT_SECRET", "too-short"),
        ("DATABASE_URL", "sqlite:///scanner.db"),
        ("JWT_ALGORITHM", "none"),
        ("ACCESS_TOKEN_MINUTES", "0"),
        ("ACCESS_TOKEN_MINUTES", "1441"),
    ],
)
def test_invalid_values_are_rejected(env, name, value):
    env.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize("name", ["DATABASE_URL", "JWT_SECRET"])
def test_required_values(env, name):
    env.delenv(name)
    with pytest.raises(ValidationError):
        Settings()


def test_get_settings_is_cached(env):
    get_settings.cache_clear()
    try:
        assert get_settings() is get_settings()
    finally:
        get_settings.cache_clear()
