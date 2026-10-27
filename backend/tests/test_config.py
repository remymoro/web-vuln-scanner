import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings

DATABASE_URL = "postgresql+psycopg://scanner:scanner@localhost:5432/scanner"
SECRET = "s" * 32


@pytest.fixture
def env(monkeypatch, tmp_path):
    # Isoler du .env et de l'environnement du poste de développement.
    monkeypatch.chdir(tmp_path)
    for name in (
        "DATABASE_URL",
        "JWT_SECRET",
        "JWT_ALGORITHM",
        "ACCESS_TOKEN_MINUTES",
        "REDIS_URL",
        "SCAN_TIMEOUT_SECONDS",
        "SCAN_PENDING_TIMEOUT_SECONDS",
        "SCAN_COOLDOWN_SECONDS",
        "APP_ENV",
        "DEV_SSRF_ALLOWED_HOSTS",
        "DEV_EXTRA_CA_FILE",
        "DNS_NAMESERVERS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6380/0")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("JWT_SECRET", SECRET)
    return monkeypatch


def test_reads_environment_with_defaults(env):
    settings = Settings()
    assert settings.database_url == DATABASE_URL
    assert settings.jwt_secret.get_secret_value() == SECRET
    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_minutes == 30
    assert settings.redis_url == "redis://localhost:6380/0"
    assert settings.scan_timeout_seconds == 300
    assert settings.scan_pending_timeout_seconds == 3600
    assert settings.scan_cooldown_seconds == 600
    assert settings.app_env == "production"
    assert settings.dev_ssrf_allowed_hosts == []
    assert settings.dev_extra_ca_file is None
    assert settings.dns_nameservers is None


def test_secret_is_hidden_in_repr(env):
    assert SECRET not in repr(Settings())


def test_reads_dotenv_file(env, tmp_path):
    env.delenv("JWT_SECRET")
    (tmp_path / ".env").write_text(f"JWT_SECRET={'d' * 32}\n", encoding="utf-8")
    assert Settings().jwt_secret.get_secret_value() == "d" * 32


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("REDIS_URL", "http://localhost:6380"),
        ("REDIS_URL", "redis://"),
        ("SCAN_TIMEOUT_SECONDS", "0"),
        ("SCAN_TIMEOUT_SECONDS", "3601"),
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


@pytest.mark.parametrize("name", ["DATABASE_URL", "JWT_SECRET", "REDIS_URL"])
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


def test_accepts_secure_redis(env):
    env.setenv("REDIS_URL", "rediss://redis.example.test:6380/0")
    assert Settings().redis_url.startswith("rediss://")


@pytest.mark.parametrize("app_env", ["production", "test"])
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DEV_SSRF_ALLOWED_HOSTS", '["demo.scanner.test"]'),
        ("DEV_EXTRA_CA_FILE", "/certs/ca.crt"),
    ],
)
def test_demo_exceptions_rejected_outside_development(env, app_env, name, value):
    env.setenv("APP_ENV", app_env)
    env.setenv(name, value)
    with pytest.raises(ValidationError, match="app_env=development"):
        Settings()


def test_development_exceptions_read_from_environment(env):
    env.setenv("APP_ENV", "development")
    env.setenv("DEV_SSRF_ALLOWED_HOSTS", '["demo.scanner.test"]')
    env.setenv("DEV_EXTRA_CA_FILE", "/certs/ca.crt")
    settings = Settings()
    assert settings.dev_ssrf_allowed_hosts == ["demo.scanner.test"]
    assert str(settings.dev_extra_ca_file) == "/certs/ca.crt"


@pytest.mark.parametrize("app_env", ["production", "test", "development"])
def test_explicit_nameservers_allowed_in_every_environment(env, app_env):
    env.setenv("APP_ENV", app_env)
    env.setenv("DNS_NAMESERVERS", '["172.30.53.53", "::1"]')
    assert [str(ip) for ip in Settings().dns_nameservers] == ["172.30.53.53", "::1"]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("APP_ENV", "staging"),
        ("DNS_NAMESERVERS", '["dns.scanner.test"]'),
        ("DNS_NAMESERVERS", "[]"),
        ("DEV_SSRF_ALLOWED_HOSTS", '["*.scanner.test"]'),
        ("DEV_SSRF_ALLOWED_HOSTS", '["https://demo.scanner.test"]'),
        ("DEV_SSRF_ALLOWED_HOSTS", '["demo.scanner.test."]'),
        ("DEV_SSRF_ALLOWED_HOSTS", '["127.0.0.1"]'),
    ],
)
def test_invalid_demo_or_dns_settings(env, name, value):
    env.setenv("APP_ENV", "development")
    env.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()
