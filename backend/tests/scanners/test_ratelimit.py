from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import httpx
import pytest
import respx

from app.domain.finding import Severity
from app.domain.target import Target
from app.infra.ratelimit_rules_config import load_ratelimit_rules
from app.scanners.base import Scanner
from app.scanners.ratelimit import (
    BurstResult,
    RateLimitScanner,
    analyze_ratelimit,
    collect_burst,
)
from app.security.ssrf import SsrfBlockedError, create_safe_client

TARGET = Target("https://example.test/path?test=1")
RULES = load_ratelimit_rules(Path(__file__).resolve().parents[2] / "config/ratelimit_rules.yaml")


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_absent_analysis_uses_rule_and_quantified_evidence():
    result = BurstResult(30, 1.25)
    (finding,) = analyze_ratelimit(result, RULES)
    assert finding.id == "ratelimit.absent"
    assert finding.severity is Severity.LOW
    assert (finding.scanner, finding.category) == ("ratelimit", "Limitation de débit")
    assert (finding.title, finding.description, finding.recommendation) == (
        RULES[0].title,
        RULES[0].description,
        RULES[0].recommendation,
    )
    assert finding.title == "Aucune limitation de débit détectée"
    assert "Seule la page d'accueil" in finding.description
    assert finding.evidence == ("30 requêtes en 1,2 s, aucune réponse 429 ni en-tête de limitation")
    assert len(finding.evidence) <= 200
    custom_rule = replace(RULES[0], severity=Severity.INFO)
    assert analyze_ratelimit(result, [custom_rule])[0].severity is Severity.INFO


def test_result_and_rule_are_frozen():
    with pytest.raises(FrozenInstanceError):
        BurstResult(5, 0.2).signal = "429"
    with pytest.raises(FrozenInstanceError):
        RULES[0].title = "changed"


@pytest.mark.parametrize("limited_at", [1, 3, 5])
def test_429_stops_immediately_without_finding(limited_at):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).mock(
            side_effect=[httpx.Response(200) for _ in range(limited_at - 1)] + [httpx.Response(429)]
        )
        with create_safe_client() as client:
            scanner: Scanner = RateLimitScanner(client, RULES, max_requests=5, clock=FakeClock())
            assert (scanner.name, scanner.category) == ("ratelimit", "Limitation de débit")
            assert scanner.run(TARGET) == []
            assert not client.is_closed
        assert route.call_count == limited_at


@pytest.mark.parametrize(
    ("status", "headers", "signal"),
    [
        (429, {}, "429"),
        (503, {"Retry-After": "30"}, "503 + Retry-After"),
        (503, {"retry-after": ""}, "503 + Retry-After"),
        (200, {"RateLimit-Limit": "100"}, "RateLimit-Limit"),
        (200, {"RateLimit-Policy": '"default";q=100;w=60'}, "RateLimit-Policy"),
        (200, {"RateLimit": '"default";r=99;t=60'}, "RateLimit"),
        (200, {"X-RateLimit-Limit": "100"}, "X-RateLimit-Limit"),
        (200, {"x-ratelimit-remaining": "99"}, "X-RateLimit-Remaining"),
        (200, {"ratelimit-limit": ""}, "RateLimit-Limit"),
        (503, {"RateLimit-Limit": "100"}, "RateLimit-Limit"),
    ],
)
def test_limit_signals_are_recorded_and_stop_at_first_response(status, headers, signal):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).respond(status, headers=headers)
        with create_safe_client() as client:
            result = collect_burst(client, TARGET, clock=FakeClock())
        assert result == BurstResult(1, 0.0, signal)
        assert analyze_ratelimit(result, RULES) == []
        assert route.call_count == 1


@pytest.mark.parametrize("max_requests", [5, 30, 100])
@pytest.mark.parametrize(
    ("status", "headers"), [(200, {}), (503, {}), (200, {"Retry-After": "30"})]
)
def test_without_signal_sends_exactly_maximum_and_returns_one_finding(
    max_requests, status, headers
):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).respond(status, headers=headers)
        with create_safe_client() as client:
            scanner = RateLimitScanner(client, RULES, max_requests=max_requests, clock=FakeClock())
            (finding,) = scanner.run(TARGET)
        assert finding.id == "ratelimit.absent"
        assert finding.evidence.startswith(f"{max_requests} requêtes en 0,0 s")
        assert route.call_count == len(router.calls) == max_requests
        assert all(call.request.method == "GET" for call in router.calls)


@pytest.mark.parametrize(("response_time", "count"), [(0.5, 6), (1, 3), (3, 1), (4, 1)])
def test_duration_budget_stops_burst_without_real_wait(response_time, count):
    clock = FakeClock()

    def respond(request):
        clock.advance(response_time)
        return httpx.Response(200)

    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).mock(side_effect=respond)
        with create_safe_client() as client:
            (finding,) = RateLimitScanner(client, RULES, clock=clock).run(TARGET)
        assert route.call_count == count
        duration = f"{count * response_time:.1f}".replace(".", ",")
        assert finding.evidence.startswith(f"{count} requêtes en {duration} s")


def test_no_request_starts_if_budget_already_expired():
    times = iter([0, 3, 3])
    with respx.mock(assert_all_called=True) as router:
        with create_safe_client() as client:
            result = collect_burst(client, TARGET, clock=lambda: next(times))
        assert result == BurstResult(0, 3)
        assert len(router.calls) == 0


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_never_followed_even_if_client_enables_them(status):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).respond(
            status, headers={"Location": "http://169.254.169.254/"}
        )
        with httpx.Client(follow_redirects=True) as client:
            RateLimitScanner(client, RULES, max_requests=5, clock=FakeClock()).run(TARGET)
        assert route.call_count == len(router.calls) == 5
        assert all(str(call.request.url) == TARGET.url for call in router.calls)


@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("failed"), httpx.ReadTimeout("slow"), SsrfBlockedError("blocked")],
)
@pytest.mark.parametrize("successful_before_error", [0, 2])
def test_network_errors_propagate_even_after_successful_responses(error, successful_before_error):
    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).mock(
            side_effect=[httpx.Response(200) for _ in range(successful_before_error)] + [error]
        )
        with create_safe_client() as client:
            with pytest.raises(type(error)) as caught:
                RateLimitScanner(client, RULES, clock=FakeClock()).run(TARGET)
        assert caught.value is error
        assert route.call_count == successful_before_error + 1


def test_timeouts_respect_client_and_remaining_budget():
    clock = FakeClock()

    def respond(request):
        remaining = 3 - clock.now
        assert request.extensions["timeout"] == {
            "connect": min(0.25, remaining),
            "read": remaining,
            "write": remaining,
            "pool": remaining,
        }
        clock.advance(1)
        return httpx.Response(200)

    with respx.mock(assert_all_called=True) as router:
        route = router.get(TARGET.url).mock(side_effect=respond)
        with create_safe_client() as client:
            client.timeout = httpx.Timeout(None, connect=0.25)
            result = collect_burst(client, TARGET, clock=clock)
            assert client.timeout.read is None
        assert route.call_count == result.requests_count == 3


def test_responses_close_before_next_request_without_reading_body():
    bodies = []

    class UnreadBody(httpx.SyncByteStream):
        def __init__(self):
            self.closed = False

        def __iter__(self):
            pytest.fail("Response body must not be read")

        def close(self):
            self.closed = True

    def respond(request):
        assert all(body.closed for body in bodies)
        body = UnreadBody()
        bodies.append(body)
        return httpx.Response(200, stream=body)

    with respx.mock(assert_all_called=True) as router:
        router.get(TARGET.url).mock(side_effect=respond)
        with create_safe_client() as client:
            collect_burst(client, TARGET, max_requests=5, clock=FakeClock())
        assert len(bodies) == 5
        assert all(body.closed for body in bodies)
