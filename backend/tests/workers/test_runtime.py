from pathlib import Path
from unittest.mock import Mock

import pytest

from app.config import Settings
from app.domain.scoring import DEFAULT_POLICY
from app.infra.scanners_config import ScannerConfig
from app.scanners import plugins
from app.workers import jobs
from tests.fakes import FakeScanner


@pytest.mark.parametrize("app_env", ["development", "test", "production"])
def test_worker_passes_demo_options_only_in_development(monkeypatch, app_env):
    from app.scanners import sslyze_probe

    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://x:y@localhost/z",
        redis_url="redis://localhost:6380/0",
        jwt_secret="t" * 32,
        app_env="development",
        dev_ssrf_allowed_hosts=["demo.scanner.test"],
        dev_extra_ca_file=Path("/certs/ca.crt"),
    ).model_copy(update={"app_env": app_env})
    monkeypatch.setenv("ZAP_API_KEY", "test-zap-key")
    monkeypatch.delenv("ZAP_API_URL", raising=False)
    factory = Mock()
    monkeypatch.setattr(jobs, "get_settings", lambda: settings)
    monkeypatch.setattr(jobs, "get_worker_sessions", Mock())
    monkeypatch.setattr(jobs, "create_safe_client", factory)
    monkeypatch.setattr(jobs.atexit, "register", Mock())
    probe_factory = Mock()
    monkeypatch.setattr(sslyze_probe, "SslyzeProbe", probe_factory)
    load = Mock(wraps=jobs.load_scanners)
    monkeypatch.setattr(jobs, "load_scanners", load)
    runtime = jobs.build_worker_runtime()
    factory.assert_called_once_with(
        allowed_hosts=["demo.scanner.test"] if app_env == "development" else (),
        extra_ca_file=Path("/certs/ca.crt") if app_env == "development" else None,
    )
    expected_scanners = (
        ["headers", "tls", "ratelimit", "waf", "zap"]
        if app_env == "development"
        else ["headers", "tls", "ratelimit", "waf"]
    )
    assert [scanner.name for scanner in runtime.scanners] == expected_scanners
    assert load.call_args.kwargs == {
        "allowed_hosts": ["demo.scanner.test"] if app_env == "development" else (),
        "extra_ca_file": Path("/certs/ca.crt") if app_env == "development" else None,
        "app_env": app_env,
    }
    probe_factory.assert_called_once_with(
        network_timeout=3,
        network_max_retries=0,
        extra_ca_file=Path("/certs/ca.crt") if app_env == "development" else None,
    )


def test_worker_provides_safe_client_to_plugin(monkeypatch, tmp_path):
    from types import SimpleNamespace

    factory = Mock(return_value=FakeScanner(name="external"))
    point = SimpleNamespace(name="external", load=Mock(return_value=factory))
    safe_client = Mock()
    monkeypatch.setattr(plugins, "entry_points", lambda **kwargs: [point])
    monkeypatch.setattr(jobs, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(jobs, "get_settings", lambda: Mock(app_env="production"))
    monkeypatch.setattr(jobs, "get_worker_sessions", Mock())
    monkeypatch.setattr(jobs, "load_scoring_policy", lambda path: DEFAULT_POLICY)
    monkeypatch.setattr(jobs, "load_scanners_config", lambda path: [ScannerConfig("external", {})])
    create_client = Mock(return_value=safe_client)
    monkeypatch.setattr(jobs, "create_safe_client", create_client)
    monkeypatch.setattr(jobs.atexit, "register", Mock())
    runtime = jobs.build_worker_runtime()
    assert runtime.scanners == (factory.return_value,)
    assert factory.call_args.args[0].client is safe_client
    create_client.assert_called_once_with(allowed_hosts=(), extra_ca_file=None)


def test_startup_fails_before_listening_to_redis(monkeypatch):
    def invalid_configuration():
        raise ValueError("Unknown scanner: missing")

    monkeypatch.setattr(jobs, "get_worker_runtime", invalid_configuration)
    worker = Mock()
    monkeypatch.setattr(jobs, "Worker", worker)
    redis = Mock()
    monkeypatch.setattr(jobs, "Redis", redis)
    with pytest.raises(ValueError, match="Unknown scanner: missing"):
        jobs.main()
    redis.from_url.assert_not_called()
    worker.assert_not_called()


def test_client_is_closed_when_plugin_configuration_fails(monkeypatch):
    monkeypatch.setattr(jobs, "get_settings", lambda: Mock(app_env="production"))
    monkeypatch.setattr(jobs, "get_worker_sessions", Mock())
    client = Mock()
    monkeypatch.setattr(jobs, "create_safe_client", lambda **kwargs: client)

    def invalid_plugin(*args, **kwargs):
        raise ValueError("Invalid Scanner contract")

    monkeypatch.setattr(jobs, "load_scanners", invalid_plugin)
    with pytest.raises(ValueError, match="Invalid Scanner contract"):
        jobs.build_worker_runtime()
    client.close.assert_called_once_with()
