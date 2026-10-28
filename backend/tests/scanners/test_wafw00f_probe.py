import gzip
import socket
from inspect import signature
from pathlib import Path

import httpx
import pytest
import requests
import respx

from app.domain.target import Target
from app.infra.waf_rules_config import load_waf_rules
from app.scanners import wafw00f_probe as adapter
from app.scanners.waf import WafProbeError, WafScanner
from app.security.ssrf import SsrfBlockedError, create_safe_client

TARGET = Target("https://example.test/path?test=1")
RULES = load_waf_rules(Path(__file__).resolve().parents[2] / "config/waf_rules.yaml")


@pytest.fixture(autouse=True)
def no_requests_or_real_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("requests, real DNS and real network are forbidden")

    monkeypatch.setattr(requests, "get", forbidden)
    monkeypatch.setattr(requests.Session, "request", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")


@pytest.mark.parametrize(
    ("headers", "rule_id", "count"),
    [
        ({"server": "cloudflare", "cf-ray": "example"}, "waf.detected", 2),
        ({"CF-Ray": "example"}, "waf.detected", 2),
        ({"Set-Cookie": "__cfduid=secret; Secure"}, "waf.detected", 2),
        ({"server": "nginx"}, "waf.absent", 7),
    ],
)
def test_full_scan_uses_real_signatures_and_never_requests(headers, rule_id, count):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(host="example.test", path="/path").respond(
            200, headers=headers, text="ordinary page"
        )
        with create_safe_client() as client:
            (finding,) = WafScanner(adapter.Wafw00fProbe(client), RULES).run(TARGET)
            assert not client.is_closed
        assert finding.id == rule_id
        if rule_id == "waf.detected":
            assert finding.evidence == "WAF détecté : Cloudflare (Cloudflare Inc.)"
        assert "secret" not in finding.evidence
        assert route.call_count == len(router.calls) == count
        for call in router.calls:
            assert call.request.method == "GET"
            assert call.request.url.host == "example.test"
            assert call.request.url.scheme == "https"
            assert call.request.url.path == "/path"
            assert call.request.url.params["test"] == "1"
        # centralAttack conserve bien ses trois paramètres (XSS, SQL, LFI).
        assert len(router.calls[1].request.url.params) == 4
        if count == 7:
            assert "user-agent" in router.calls[2].request.headers
            assert "user-agent" not in router.calls[3].request.headers


def test_real_generic_detection_without_name_is_detected():
    def respond(request):
        return httpx.Response(403 if len(request.url.params) > 1 else 200, text="blocked")

    with respx.mock(assert_all_called=True) as router:
        route = router.get(host="example.test", path="/path").mock(side_effect=respond)
        with create_safe_client() as client:
            (finding,) = WafScanner(adapter.Wafw00fProbe(client), RULES).run(TARGET)
        assert finding.id == "waf.detected"
        assert finding.evidence == "WAF détecté : non identifié"
        assert route.call_count == 5


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_never_followed_even_if_client_and_engine_request_it(status):
    with respx.mock(assert_all_called=True) as router:
        router.get(host="example.test", path="/path").respond(
            status, headers={"Location": "http://169.254.169.254/"}
        )
        with create_safe_client() as client:
            client.follow_redirects = True
            engine = adapter._SafeWAFW00F(client, TARGET, 3)
            engine.allowredir = True
            engine.identwaf(findall=False)
            engine.genericdetect()
        assert len(router.calls) == 7
        assert all(call.request.url.host == "example.test" for call in router.calls)


def test_request_preserves_headers_params_and_ignores_path_and_mutated_target():
    with respx.mock(assert_all_called=True) as router:
        router.get(host="example.test", path="/path").respond(200)
        with create_safe_client() as client:
            engine = adapter._SafeWAFW00F(client, TARGET, 3)
            engine.target = "https://other.test/"
            engine.Request(
                headers={"X-Probe": "sentinel"},
                path="//other.test/escape",
                params={"attack": '<script>alert("XSS")</script>', "test": "2"},
            )
        request = router.calls[-1].request
        assert request.url.host == "example.test"
        assert request.url.path == "/path"
        assert request.url.params.get_list("test") == ["1", "2"]
        assert request.url.params["attack"] == '<script>alert("XSS")</script>'
        assert dict(request.headers) == {"host": "example.test", "x-probe": "sentinel"}


def test_body_stream_stops_at_exactly_100_kib_and_closes():
    bodies = []

    class BoundedBody(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            for _ in range(25):
                yield b"x" * 4096
            pytest.fail("Body read past 100 KiB")

        def close(self):
            self.closed = True

    def respond(request):
        body = BoundedBody()
        bodies.append(body)
        return httpx.Response(200, stream=body)

    with respx.mock(assert_all_called=True) as router:
        router.get(TARGET.url).mock(side_effect=respond)
        with create_safe_client() as client:
            engine = adapter._SafeWAFW00F(client, TARGET, 3)
        assert len(engine.rq.content) == 100 * 1024
        assert engine.rq.text == "x" * (100 * 1024)
        assert all(body.closed for body in bodies)


def test_decoded_body_is_bounded_even_with_large_chunk():
    with respx.mock(assert_all_called=True) as router:
        router.get(TARGET.url).respond(200, content=b"x" * (150 * 1024))
        with create_safe_client() as client:
            engine = adapter._SafeWAFW00F(client, TARGET, 3)
        assert len(engine.rq.content) == adapter.MAX_RESPONSE_SIZE


def test_response_translation_decodes_once_and_preserves_reason_headers_and_url():
    with respx.mock(assert_all_called=True) as router:
        router.get(TARGET.url).respond(
            999,
            headers={"Content-Encoding": "gzip", "Content-Type": "text/html; charset=iso-8859-1"},
            content=gzip.compress("été".encode("iso-8859-1")),
            extensions={"reason_phrase": b"No Hacking"},
        )
        with create_safe_client() as client:
            engine = adapter._SafeWAFW00F(client, TARGET, 3)
        assert engine.rq.reason == "No Hacking"
        assert engine.rq.status_code == 999
        assert engine.rq.url == TARGET.url
        assert engine.rq.text == "été"
        assert engine.rq.content == "été".encode("iso-8859-1")
        assert engine.rq.headers["CONTENT-TYPE"] == "text/html; charset=iso-8859-1"


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("failed"), httpx.ReadTimeout("slow"), SsrfBlockedError("blocked")],
)
@pytest.mark.parametrize("successful_before_error", [0, 1, 4, 6])
def test_network_error_propagates_without_absent_finding(error, successful_before_error):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(host="example.test", path="/path").mock(
            side_effect=[httpx.Response(200) for _ in range(successful_before_error)] + [error]
        )
        with create_safe_client() as client:
            with pytest.raises(type(error)) as caught:
                WafScanner(adapter.Wafw00fProbe(client), RULES).run(TARGET)
        assert caught.value is error
        assert route.call_count == successful_before_error + 1


def test_stream_error_closes_response_and_propagates():
    class BrokenBody(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b"partial"
            raise httpx.ReadTimeout("incomplete body")

        def close(self):
            self.closed = True

    body = BrokenBody()
    with respx.mock(assert_all_called=True) as router:
        router.get(TARGET.url).respond(200, stream=body)
        with create_safe_client() as client:
            with pytest.raises(httpx.ReadTimeout):
                WafScanner(adapter.Wafw00fProbe(client), RULES).run(TARGET)
        assert body.closed


def test_body_deadline_is_an_error_and_closes_response(monkeypatch):
    times = iter([0, 4])
    monkeypatch.setattr(adapter, "monotonic", lambda: next(times))
    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).respond(200, content=b"body")
        with create_safe_client() as client:
            with pytest.raises(httpx.ReadTimeout, match="deadline"):
                adapter.Wafw00fProbe(client).scan(TARGET)
        assert route.calls[0].response.is_closed


def test_timeouts_are_short_and_do_not_extend_client_limits():
    def respond(request):
        assert request.extensions["timeout"] == {"connect": 0.25, "read": 2, "write": 2, "pool": 2}
        return httpx.Response(200)

    with respx.mock(assert_all_called=True) as router:
        router.get(host="example.test", path="/path").mock(side_effect=respond)
        with create_safe_client() as client:
            client.timeout = httpx.Timeout(None, connect=0.25)
            adapter.Wafw00fProbe(client, network_timeout=2).scan(TARGET)
            assert client.timeout.read is None


def test_request_budget_stops_before_sending_eighth_request():
    with respx.mock(assert_all_called=True) as router:
        router.get(TARGET.url).respond(200)
        with create_safe_client() as client:
            engine = adapter._SafeWAFW00F(client, TARGET, 3)
            for _ in range(6):
                engine.Request()
            with pytest.raises(WafProbeError, match="budget"):
                engine.Request()
        assert len(router.calls) == 7


def test_audited_parent_request_signature():
    assert adapter.__version__ == "2.4.2"
    assert str(signature(adapter.WAFW00F.Request)) == (
        "(self, headers=None, path=None, params={}, delay=0)"
    )
    adapter.validate_wafw00f_contract()


@pytest.mark.parametrize("changed", ["signature", "version"])
def test_changed_wafw00f_is_rejected_at_startup_before_network(monkeypatch, changed):
    if changed == "signature":
        monkeypatch.setattr(adapter.WAFW00F, "Request", lambda self, new_argument: None)
    else:
        monkeypatch.setattr(adapter, "__version__", "2.4.3")
    with respx.mock(assert_all_called=True) as router:
        with create_safe_client() as client:
            with pytest.raises(ValueError, match="audit required"):
                adapter.Wafw00fProbe(client)
        assert len(router.calls) == 0
