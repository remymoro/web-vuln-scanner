from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.infra.scanners_config import ScannerConfig
from app.scanners import plugins
from app.scanners.plugins import ScannerContext, load_scanners
from app.security.ssrf import create_safe_client
from tests.fakes import FakeScanner


def entry_point(name, factory):
    return SimpleNamespace(name=name, load=Mock(return_value=factory))


def discover(monkeypatch, *points):
    discovery = Mock(return_value=points)
    monkeypatch.setattr(plugins, "entry_points", discovery)
    return discovery


def test_plugin_is_loaded_with_options_and_safe_client(monkeypatch, tmp_path):
    factory = Mock(return_value=FakeScanner(name="external", category="TLS"))
    point = entry_point("external", factory)
    discovery = discover(monkeypatch, point)
    with create_safe_client() as client:
        (scanner,) = load_scanners([ScannerConfig("external", {"limit": 7})], client, tmp_path)
        assert scanner is factory.return_value
        (context,) = factory.call_args.args
        assert context.client is client
        assert context.options == {"limit": 7}
        assert context.config_dir == tmp_path
        assert not client.follow_redirects
        assert client.trust_env is False
    point.load.assert_called_once_with()
    discovery.assert_called_once_with(group="web_vuln_scanner.scanners")


def test_unlisted_plugin_is_never_imported_or_called(monkeypatch):
    point = entry_point("unlisted", Mock(side_effect=AssertionError("must never run")))
    discover(monkeypatch, point)
    config_dir = Path(__file__).resolve().parents[2] / "config"
    with create_safe_client() as client:
        (scanner,) = load_scanners([ScannerConfig("headers", {})], client, config_dir)
    assert scanner.name == "headers"
    assert scanner.category == "en-têtes HTTP"
    point.load.assert_not_called()
    point.load.return_value.assert_not_called()


def test_unknown_scanner_is_rejected(monkeypatch, tmp_path):
    discover(monkeypatch)
    with pytest.raises(ValueError, match="Unknown scanner.*unknown"):
        load_scanners([ScannerConfig("unknown", {})], Mock(), tmp_path)


@pytest.mark.parametrize("names", [("headers",), ("external", "external")])
def test_conflicting_names_fail_without_loading_plugins(monkeypatch, tmp_path, names):
    points = [entry_point(name, Mock()) for name in names]
    discover(monkeypatch, *points)
    with pytest.raises(ValueError, match="name conflict"):
        load_scanners([ScannerConfig("headers", {})], Mock(), tmp_path)
    for point in points:
        point.load.assert_not_called()


@pytest.mark.parametrize(
    "scanner",
    [
        None,
        object(),
        SimpleNamespace(name="other", category="TLS", run=lambda target: []),
        SimpleNamespace(name="external", category=None, run=lambda target: []),
        SimpleNamespace(name="external", category="", run=lambda target: []),
        SimpleNamespace(name="external", category="TLS", run=None),
    ],
)
def test_invalid_contract(monkeypatch, tmp_path, scanner):
    discover(monkeypatch, entry_point("external", lambda context: scanner))
    with pytest.raises(ValueError, match="Invalid Scanner contract.*external"):
        load_scanners([ScannerConfig("external", {})], Mock(), tmp_path)


def test_factory_must_be_callable(monkeypatch, tmp_path):
    discover(monkeypatch, entry_point("external", object()))
    with pytest.raises(ValueError, match="factory must be callable.*external"):
        load_scanners([ScannerConfig("external", {})], Mock(), tmp_path)


def test_invalid_run_signature(monkeypatch, tmp_path):
    scanner = SimpleNamespace(name="external", category="TLS", run=lambda: [])
    discover(monkeypatch, entry_point("external", lambda context: scanner))
    with pytest.raises(ValueError, match="Invalid Scanner run signature.*external"):
        load_scanners([ScannerConfig("external", {})], Mock(), tmp_path)


def test_import_failure_names_the_plugin(monkeypatch, tmp_path):
    point = entry_point("external", Mock())
    point.load.side_effect = ImportError("missing module")
    discover(monkeypatch, point)
    with pytest.raises(ValueError, match="Cannot load scanner factory.*external"):
        load_scanners([ScannerConfig("external", {})], Mock(), tmp_path)


def test_configuration_order_is_preserved(monkeypatch, tmp_path):
    points = [
        entry_point(name, lambda context, name=name: FakeScanner(name=name))
        for name in ("first", "second")
    ]
    discover(monkeypatch, *points)
    scanners = load_scanners(
        [ScannerConfig(name, {}) for name in ("second", "first")], Mock(), tmp_path
    )
    assert [scanner.name for scanner in scanners] == ["second", "first"]


@pytest.mark.parametrize("options", [{"unknown": True}, {"rules": 5}])
def test_builtin_options_are_validated(monkeypatch, tmp_path, options):
    discover(monkeypatch)
    with pytest.raises(ValueError, match="headers"):
        load_scanners([ScannerConfig("headers", options)], Mock(), tmp_path)


def test_context_is_frozen_and_options_are_copied(tmp_path):
    options = {"limit": 3}
    hosts = {"demo.scanner.test"}
    ca = tmp_path / "ca.crt"
    context = ScannerContext(Mock(), tmp_path, options, hosts, ca)
    options["limit"] = 8
    hosts.clear()
    assert context.options == {"limit": 3}
    assert context.allowed_hosts == frozenset({"demo.scanner.test"})
    assert context.extra_ca_file == ca
    with pytest.raises(FrozenInstanceError):
        context.config_dir = Path("elsewhere")
    with pytest.raises(TypeError):
        context.options["limit"] = 8
    with pytest.raises(FrozenInstanceError):
        context.allowed_hosts = frozenset()
    with pytest.raises(FrozenInstanceError):
        context.extra_ca_file = None


@pytest.mark.parametrize(
    "options",
    [
        {"unknown": True},
        {"rules": ""},
        {"rules": 5},
        {"network_timeout": True},
        {"network_timeout": 0},
        {"network_timeout": 11},
        {"network_timeout": 1.5},
        {"network_timeout": "3"},
        {"network_max_retries": True},
        {"network_max_retries": -1},
        {"network_max_retries": 3},
        {"network_max_retries": "0"},
    ],
)
def test_tls_options_are_validated(monkeypatch, tmp_path, options):
    discover(monkeypatch)
    with pytest.raises(ValueError, match="tls"):
        load_scanners([ScannerConfig("tls", options)], Mock(), tmp_path)


def test_tls_factory_receives_network_options_and_rules(monkeypatch):
    from app.scanners import sslyze_probe

    discover(monkeypatch)
    probe = Mock()
    monkeypatch.setattr(sslyze_probe, "SslyzeProbe", probe)
    config_dir = Path(__file__).resolve().parents[2] / "config"
    ca = Path("/trust/ca.crt")
    scanners = load_scanners(
        [ScannerConfig("tls", {"network_timeout": 2, "network_max_retries": 1})],
        Mock(),
        config_dir,
        allowed_hosts={"demo.scanner.test"},
        extra_ca_file=ca,
    )
    assert [(scanner.name, scanner.category) for scanner in scanners] == [("tls", "TLS")]
    probe.assert_called_once_with(network_timeout=2, network_max_retries=1, extra_ca_file=ca)
