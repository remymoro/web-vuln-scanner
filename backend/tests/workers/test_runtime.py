from pathlib import Path
from unittest.mock import Mock

import pytest

from app.config import Settings
from app.workers import jobs


@pytest.mark.parametrize("app_env", ["development", "test", "production"])
def test_worker_passes_demo_options_only_in_development(monkeypatch, app_env):
    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://x:y@localhost/z",
        redis_url="redis://localhost:6380/0",
        jwt_secret="t" * 32,
        app_env="development",
        dev_ssrf_allowed_hosts=["demo.scanner.test"],
        dev_extra_ca_file=Path("/certs/ca.crt"),
    ).model_copy(update={"app_env": app_env})
    factory = Mock()
    monkeypatch.setattr(jobs, "get_settings", lambda: settings)
    monkeypatch.setattr(jobs, "get_worker_sessions", Mock())
    monkeypatch.setattr(jobs, "create_safe_client", factory)
    monkeypatch.setattr(jobs.atexit, "register", Mock())
    runtime = jobs.build_worker_runtime()
    factory.assert_called_once_with(
        allowed_hosts=["demo.scanner.test"] if app_env == "development" else (),
        extra_ca_file=Path("/certs/ca.crt") if app_env == "development" else None,
    )
    assert len(runtime.scanners) == 1
