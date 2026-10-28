import logging
import socket
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
import respx
from redis.exceptions import RedisError

from app.domain.finding import Severity
from app.domain.scoring import DEFAULT_POLICY, score
from app.domain.target import Target
from app.infra.zap_rules_config import load_zap_rules
from app.scanners.zap import (
    ZAP_LOCK_KEY,
    RedisZapLock,
    ZapAlert,
    ZapBusyError,
    ZapHttpProbe,
    ZapPassiveScanner,
    ZapProbeError,
    analyze_zap,
    create_zap_internal_client,
)
from app.security.ssrf import SsrfBlockedError

API_URL = "http://zap:8080"
API_KEY = "super-secret-zap-key-do-not-log"
TARGET = Target("https://demo.scanner.test/")
RULES = load_zap_rules(Path(__file__).resolve().parents[2] / "config/zap_rules.yaml")


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeZapLock:
    def __init__(self, *, busy: bool = False) -> None:
        self.busy = busy
        self.entered = 0
        self.exited = 0
        self.active = False

    def __enter__(self):
        if self.busy:
            raise ZapBusyError("ZAP is already busy")
        self.entered += 1
        self.active = True
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.active = False
        self.exited += 1


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Real DNS or TCP network access is forbidden")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")


@pytest.fixture
def dns(monkeypatch):
    addresses = ["93.184.215.14"]
    calls: list[tuple[str, int]] = []

    def getaddrinfo(host, port, *, type):
        assert type == socket.SOCK_STREAM
        calls.append((host, port))
        return [(socket.AF_INET, type, socket.IPPROTO_TCP, "", (ip, port)) for ip in addresses]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return addresses, calls


@pytest.mark.parametrize(
    ("risk", "severity", "points"),
    [
        ("High", Severity.HIGH, 25),
        ("Medium", Severity.MEDIUM, 10),
        ("Low", Severity.LOW, 3),
        ("Informational", Severity.INFO, 0),
    ],
)
def test_risk_translation_and_scoring(risk, severity, points):
    alert = ZapAlert(
        plugin_id="10020",
        name="Anti-clickjacking Header",
        risk=risk,
        confidence="Medium",
        url="https://example.test/login",
        description="En-tête X-Frame-Options absent.",
        solution="Ajouter X-Frame-Options ou frame-ancestors.",
    )
    (finding,) = analyze_zap([alert], RULES)
    assert finding.id == "zap.10020"
    assert finding.scanner == "zap"
    assert finding.category == "Analyse passive (ZAP)"
    assert finding.severity is severity
    assert finding.title == "Anti-clickjacking Header"
    assert finding.description == "En-tête X-Frame-Options absent."
    assert finding.recommendation == "Ajouter X-Frame-Options ou frame-ancestors."
    assert finding.evidence == "1 page touchée : https://example.test/login"
    assert score([finding], DEFAULT_POLICY).score == 100 - points


def test_alerts_are_grouped_by_plugin_id_with_up_to_three_example_urls():
    alerts = [
        ZapAlert(
            plugin_id="10020",
            name="Anti-clickjacking Header",
            risk="Medium",
            confidence="Medium",
            url=f"https://example.test/page-{i}",
            description="Description",
            solution="Solution",
        )
        for i in range(1, 5)
    ] + [
        # Doublon sur la même URL : ne compte pas comme une cinquième page.
        ZapAlert(
            plugin_id="10020",
            name="Anti-clickjacking Header",
            risk="Medium",
            confidence="High",
            url="https://example.test/page-1",
            description="Description",
            solution="Solution",
        ),
        ZapAlert(
            plugin_id="10027",
            name="Information Disclosure - Suspicious Comments",
            risk="Informational",
            confidence="Low",
            url="https://example.test/app.js",
            description="Commentaire sensible.",
            solution="Retirer les commentaires.",
        ),
    ]
    findings = analyze_zap(alerts, RULES)
    assert [f.id for f in findings] == ["zap.10020", "zap.10027"]
    assert findings[0].evidence == (
        "4 pages touchées : https://example.test/page-1, "
        "https://example.test/page-2, https://example.test/page-3"
    )
    assert "page-4" not in findings[0].evidence
    assert findings[1].evidence == "1 page touchée : https://example.test/app.js"


def test_false_positives_are_ignored():
    alerts = [
        ZapAlert(
            plugin_id="10020",
            name="Anti-clickjacking Header",
            risk="Medium",
            confidence="False Positive",
            url="https://example.test/fp",
        ),
        ZapAlert(
            plugin_id="10020",
            name="Anti-clickjacking Header",
            risk="Medium",
            confidence="false positive",
            url="https://example.test/fp2",
        ),
    ]
    assert analyze_zap(alerts, RULES) == []


@pytest.mark.parametrize(
    "plugin_id",
    ["10010", "10011", "10021", "10035", "10038", "10054", "10055", "10063"],
)
def test_rules_covered_by_headers_scanner_are_excluded(plugin_id):
    alert = ZapAlert(
        plugin_id=plugin_id,
        name=f"Excluded {plugin_id}",
        risk="Medium",
        confidence="High",
        url="https://example.test/",
    )
    assert analyze_zap([alert], RULES) == []


def test_evidence_is_bounded_to_200_characters():
    alerts = [
        ZapAlert(
            plugin_id="10020",
            name="Anti-clickjacking Header",
            risk="Medium",
            confidence="High",
            url=f"https://example.test/{'a' * 120}-{i}",
        )
        for i in range(3)
    ]
    (finding,) = analyze_zap(alerts, RULES)
    assert len(finding.evidence) == 200
    assert finding.evidence.endswith("...")


@pytest.mark.parametrize(
    "alert",
    [
        ZapAlert(plugin_id="abc", name="Bad", risk="Low", confidence="High"),
        ZapAlert(plugin_id="", name="Bad", risk="Low", confidence="High"),
        ZapAlert(plugin_id="10020", name="Bad", risk="Critical", confidence="High"),
    ],
)
def test_invalid_alert_in_analyze_zap_raises_error(alert):
    with pytest.raises(ZapProbeError):
        analyze_zap([alert], RULES)


def test_dataclasses_are_frozen():
    with pytest.raises(FrozenInstanceError):
        RULES[0].name = "changed"
    alert = ZapAlert(plugin_id="10020", name="Test", risk="Low", confidence="High")
    with pytest.raises(FrozenInstanceError):
        alert.risk = "High"


def _mock_full_zap_flow(router: respx.MockRouter, *, alerts: list[dict] | None = None):
    router.get(f"{API_URL}/JSON/context/action/newContext/").respond(200, json={"contextId": "1"})
    router.get(f"{API_URL}/JSON/context/action/includeInContext/").respond(
        200, json={"Result": "OK"}
    )
    router.get(f"{API_URL}/JSON/spider/action/setOptionMaxDepth/").respond(
        200, json={"Result": "OK"}
    )
    router.get(f"{API_URL}/JSON/spider/action/scan/").respond(200, json={"scan": "7"})
    router.get(f"{API_URL}/JSON/spider/view/status/").mock(
        side_effect=[
            httpx.Response(200, json={"status": "40"}),
            httpx.Response(200, json={"status": "100"}),
        ]
    )
    router.get(f"{API_URL}/JSON/pscan/view/recordsToScan/").mock(
        side_effect=[
            httpx.Response(200, json={"recordsToScan": "3"}),
            httpx.Response(200, json={"recordsToScan": "0"}),
        ]
    )
    router.get(f"{API_URL}/JSON/alert/view/alerts/").respond(
        200,
        json={
            "alerts": alerts
            if alerts is not None
            else [
                {
                    "pluginId": "10038",
                    "name": "Content Security Policy (CSP) Header Not Set",
                    "risk": "Medium",
                    "confidence": "High",
                    "url": "https://demo.scanner.test/",
                    "description": "CSP absent",
                    "solution": "Définir CSP",
                },
                {
                    "pluginId": "10020",
                    "name": "Anti-clickjacking Header",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "url": "https://demo.scanner.test/",
                    "description": "X-Frame-Options absent",
                    "solution": "Ajouter frame-ancestors",
                },
                {
                    "pluginId": "10020",
                    "name": "Anti-clickjacking Header",
                    "risk": "Medium",
                    "confidence": "Medium",
                    "url": "https://demo.scanner.test/login",
                    "description": "X-Frame-Options absent",
                    "solution": "Ajouter frame-ancestors",
                },
                {
                    "pluginId": "10099",
                    "name": "Ignored FP",
                    "risk": "High",
                    "confidence": "False Positive",
                    "url": "https://demo.scanner.test/",
                    "description": "FP",
                    "solution": "Rien",
                },
            ]
        },
    )
    router.get(f"{API_URL}/JSON/context/action/removeContext/").respond(200, json={"Result": "OK"})


def test_complete_passive_scan_workflow(dns, caplog):
    dns[0][:] = ["172.20.0.10"]
    clock = FakeClock()
    lock = FakeZapLock()
    probe = ZapHttpProbe(
        API_URL,
        API_KEY,
        clock=clock,
        sleep=clock.sleep,
        context_name_factory=lambda: "scan-ctx-1",
    )
    scanner = ZapPassiveScanner(
        probe,
        RULES,
        allowed_hosts={"demo.scanner.test"},
        lock=lock,
    )
    with caplog.at_level(logging.DEBUG), respx.mock(assert_all_called=True) as router:
        _mock_full_zap_flow(router)
        (finding,) = scanner.run(TARGET)
        calls = list(router.calls)

    assert dns[1] == [("demo.scanner.test", 443)]
    assert lock.entered == 1
    assert lock.exited == 1
    assert not lock.active
    assert clock.sleeps == [1.0, 1.0]
    assert finding.id == "zap.10020"
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence == (
        "2 pages touchées : https://demo.scanner.test/, https://demo.scanner.test/login"
    )

    paths = [call.request.url.path for call in calls]
    assert paths == [
        "/JSON/context/action/newContext/",
        "/JSON/context/action/includeInContext/",
        "/JSON/spider/action/setOptionMaxDepth/",
        "/JSON/spider/action/scan/",
        "/JSON/spider/view/status/",
        "/JSON/spider/view/status/",
        "/JSON/pscan/view/recordsToScan/",
        "/JSON/pscan/view/recordsToScan/",
        "/JSON/alert/view/alerts/",
        "/JSON/context/action/removeContext/",
    ]
    assert not any("/ascan/" in path for path in paths)
    for call in calls:
        assert call.request.url.params["apikey"] == API_KEY
        assert call.request.headers["x-zap-api-key"] == API_KEY

    include_params = calls[1].request.url.params
    assert include_params["contextName"] == "scan-ctx-1"
    assert include_params["regex"] == r"^https://demo\.scanner\.test/.*"

    depth_params = calls[2].request.url.params
    assert depth_params["Integer"] == "3"

    scan_params = calls[3].request.url.params
    assert scan_params["url"] == "https://demo.scanner.test/"
    assert scan_params["maxChildren"] == "50"
    assert scan_params["recurse"] == "true"
    assert scan_params["contextName"] == "scan-ctx-1"
    assert scan_params["subtreeOnly"] == "true"

    assert calls[4].request.url.params["scanId"] == "7"
    assert calls[8].request.url.params["baseurl"] == "https://demo.scanner.test"
    assert calls[9].request.url.params["contextName"] == "scan-ctx-1"

    assert API_KEY not in caplog.text
    assert API_KEY not in repr(probe)


@pytest.mark.parametrize(
    "failing_step",
    [
        "includeInContext",
        "setOptionMaxDepth",
        "scan",
        "status",
        "recordsToScan",
        "alerts",
    ],
)
def test_context_is_always_removed_when_an_error_occurs(dns, failing_step):
    clock = FakeClock()
    lock = FakeZapLock()
    probe = ZapHttpProbe(
        API_URL,
        API_KEY,
        clock=clock,
        sleep=clock.sleep,
        context_name_factory=lambda: "ctx-err",
    )
    scanner = ZapPassiveScanner(probe, RULES, lock=lock)

    with respx.mock(assert_all_called=False) as router:
        router.get(f"{API_URL}/JSON/context/action/newContext/").respond(
            200, json={"contextId": "1"}
        )
        router.get(f"{API_URL}/JSON/context/action/includeInContext/").respond(
            500 if failing_step == "includeInContext" else 200,
            json={"Result": "OK"},
        )
        router.get(f"{API_URL}/JSON/spider/action/setOptionMaxDepth/").respond(
            500 if failing_step == "setOptionMaxDepth" else 200,
            json={"Result": "OK"},
        )
        router.get(f"{API_URL}/JSON/spider/action/scan/").respond(
            200,
            json={} if failing_step == "scan" else {"scan": "1"},
        )
        router.get(f"{API_URL}/JSON/spider/view/status/").respond(
            200,
            json={"status": "invalid"} if failing_step == "status" else {"status": "100"},
        )
        router.get(f"{API_URL}/JSON/pscan/view/recordsToScan/").respond(
            200,
            json={"recordsToScan": "-1"}
            if failing_step == "recordsToScan"
            else {"recordsToScan": "0"},
        )
        router.get(f"{API_URL}/JSON/alert/view/alerts/").respond(
            200,
            json={"alerts": "not-a-list"} if failing_step == "alerts" else {"alerts": []},
        )
        remove_route = router.get(f"{API_URL}/JSON/context/action/removeContext/").respond(
            200, json={"Result": "OK"}
        )

        with pytest.raises(ZapProbeError):
            scanner.run(Target("https://example.test/"))

        assert remove_route.call_count == 1
        assert remove_route.calls[0].request.url.params["contextName"] == "ctx-err"
        assert lock.entered == 1
        assert lock.exited == 1


def test_spider_timeout_removes_context_and_raises(dns):
    clock = FakeClock()
    probe = ZapHttpProbe(
        API_URL,
        API_KEY,
        spider_timeout=5,
        poll_interval=2.0,
        clock=clock,
        sleep=clock.sleep,
        context_name_factory=lambda: "ctx-spider-timeout",
    )
    scanner = ZapPassiveScanner(probe, RULES)
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{API_URL}/JSON/context/action/newContext/").respond(
            200, json={"contextId": "1"}
        )
        router.get(f"{API_URL}/JSON/context/action/includeInContext/").respond(
            200, json={"Result": "OK"}
        )
        router.get(f"{API_URL}/JSON/spider/action/setOptionMaxDepth/").respond(
            200, json={"Result": "OK"}
        )
        router.get(f"{API_URL}/JSON/spider/action/scan/").respond(200, json={"scan": "3"})
        status_route = router.get(f"{API_URL}/JSON/spider/view/status/").respond(
            200, json={"status": "50"}
        )
        remove_route = router.get(f"{API_URL}/JSON/context/action/removeContext/").respond(
            200, json={"Result": "OK"}
        )
        with pytest.raises(ZapProbeError, match="spider timeout"):
            scanner.run(Target("https://example.test/"))

        assert status_route.call_count == 4
        assert remove_route.call_count == 1


def test_passive_scan_timeout_removes_context_and_raises(dns):
    clock = FakeClock()
    probe = ZapHttpProbe(
        API_URL,
        API_KEY,
        passive_timeout=5,
        poll_interval=2.0,
        clock=clock,
        sleep=clock.sleep,
        context_name_factory=lambda: "ctx-pscan-timeout",
    )
    scanner = ZapPassiveScanner(probe, RULES)
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{API_URL}/JSON/context/action/newContext/").respond(
            200, json={"contextId": "1"}
        )
        router.get(f"{API_URL}/JSON/context/action/includeInContext/").respond(
            200, json={"Result": "OK"}
        )
        router.get(f"{API_URL}/JSON/spider/action/setOptionMaxDepth/").respond(
            200, json={"Result": "OK"}
        )
        router.get(f"{API_URL}/JSON/spider/action/scan/").respond(200, json={"scan": "3"})
        router.get(f"{API_URL}/JSON/spider/view/status/").respond(200, json={"status": "100"})
        pscan_route = router.get(f"{API_URL}/JSON/pscan/view/recordsToScan/").respond(
            200, json={"recordsToScan": "12"}
        )
        remove_route = router.get(f"{API_URL}/JSON/context/action/removeContext/").respond(
            200, json={"Result": "OK"}
        )
        with pytest.raises(ZapProbeError, match="passive scan timeout"):
            scanner.run(Target("https://example.test/"))

        assert pscan_route.call_count == 4
        assert remove_route.call_count == 1


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("connection refused"), httpx.ReadTimeout("timed out")],
)
def test_unreachable_zap_raises_probe_error_without_leaking_api_key(dns, caplog, error):
    probe = ZapHttpProbe(API_URL, API_KEY)
    scanner = ZapPassiveScanner(probe, RULES)
    with caplog.at_level(logging.DEBUG), respx.mock(assert_all_called=True) as router:
        router.get(f"{API_URL}/JSON/context/action/newContext/").mock(side_effect=error)
        with pytest.raises(ZapProbeError) as caught:
            scanner.run(Target("https://example.test/"))
    assert API_KEY not in str(caught.value)
    assert caught.value.__cause__ is None
    assert API_KEY not in caplog.text


def test_busy_lock_raises_without_calling_zap(dns):
    lock = FakeZapLock(busy=True)
    probe = ZapHttpProbe(API_URL, API_KEY)
    scanner = ZapPassiveScanner(probe, RULES, lock=lock)
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(ZapBusyError):
            scanner.run(Target("https://example.test/"))
        assert len(router.calls) == 0


@pytest.mark.parametrize(
    "ips",
    [["10.0.0.1"], ["127.0.0.1"], ["169.254.169.254"], ["93.184.215.14", "10.0.0.1"]],
)
def test_private_ip_is_rejected_before_lock_and_zap(dns, ips):
    dns[0][:] = ips
    lock = FakeZapLock()
    probe = ZapHttpProbe(API_URL, API_KEY)
    scanner = ZapPassiveScanner(probe, RULES, lock=lock)
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(SsrfBlockedError):
            scanner.run(Target("https://example.test/"))
        assert len(router.calls) == 0
    assert lock.entered == 0


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "https://user@example.test/", "https://example.test:8443/", "https://"],
)
def test_invalid_target_url_fails_before_dns_lock_and_zap(dns, url):
    lock = FakeZapLock()
    probe = ZapHttpProbe(API_URL, API_KEY)
    scanner = ZapPassiveScanner(probe, RULES, lock=lock)
    with respx.mock(assert_all_called=False) as router:
        with pytest.raises(SsrfBlockedError):
            scanner.run(Target(url))
        assert len(router.calls) == 0
    assert dns[1] == []
    assert lock.entered == 0


def test_allowed_demo_host_still_rejects_loopback_and_other_private_hosts(dns):
    dns[0][:] = ["127.0.0.1"]
    probe = Mock()
    scanner = ZapPassiveScanner(probe, RULES, allowed_hosts={"demo.scanner.test"})
    with pytest.raises(SsrfBlockedError):
        scanner.run(Target("https://demo.scanner.test/"))
    dns[0][:] = ["172.20.0.10"]
    with pytest.raises(SsrfBlockedError):
        scanner.run(Target("https://other.scanner.test/"))
    probe.scan.assert_not_called()


@pytest.mark.parametrize(
    "forbidden_url",
    [
        "https://example.test/",
        "http://other:8080/JSON/core/view/version/",
        "https://zap:8080/JSON/core/view/version/",
        "http://zap:9090/JSON/core/view/version/",
        "http://zap:8080/UI/core/",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_internal_client_refuses_any_call_outside_configured_zap_api(forbidden_url):
    with respx.mock(assert_all_called=False) as router:
        with create_zap_internal_client(API_URL) as client:
            assert not client.follow_redirects
            assert client.trust_env is False
            with pytest.raises(ZapProbeError, match="Internal ZAP client"):
                client.get(forbidden_url)
        assert len(router.calls) == 0


def test_redis_lock_acquires_waits_and_releases_atomically():
    clock = FakeClock()
    redis = Mock()
    redis.set.side_effect = [False, True]
    lock = RedisZapLock(redis, wait_timeout=1.0, poll_interval=0.25, clock=clock, sleep=clock.sleep)
    with lock:
        assert redis.set.call_count == 2
    assert clock.sleeps == [0.25]
    token = redis.set.call_args.args[1]
    redis.set.assert_called_with(ZAP_LOCK_KEY, token, nx=True, ex=180)
    redis.eval.assert_called_once()
    assert redis.eval.call_args.args[1:] == (1, ZAP_LOCK_KEY, token)


def test_redis_lock_times_out_when_already_held():
    clock = FakeClock()
    redis = Mock()
    redis.set.return_value = False
    lock = RedisZapLock(redis, wait_timeout=0.5, poll_interval=0.2, clock=clock, sleep=clock.sleep)
    with pytest.raises(ZapBusyError):
        with lock:
            pass
    assert clock.sleeps == pytest.approx([0.2, 0.2, 0.1])
    redis.eval.assert_not_called()


def test_redis_lock_translates_redis_errors():
    redis = Mock()
    redis.set.side_effect = RedisError("redis down")
    lock = RedisZapLock(redis, wait_timeout=0.1)
    with pytest.raises(ZapProbeError, match="Redis lock"):
        with lock:
            pass
    redis.set.side_effect = None
    redis.set.return_value = True
    redis.eval.side_effect = RedisError("redis down on release")
    with pytest.raises(ZapProbeError, match="release"):
        with lock:
            pass
