from dataclasses import FrozenInstanceError
from pathlib import Path

import httpx
import pytest
import respx

from app.domain.finding import Severity
from app.domain.target import Target
from app.infra.header_rules_config import load_header_rules
from app.scanners.base import Scanner
from app.scanners.headers import CheckType, HeaderRule, HeadersScanner, analyze_headers


def make_rule(check, value=None, header="X-Test"):
    return HeaderRule(
        id="headers.test",
        header=header,
        check=check,
        severity=Severity.MEDIUM,
        title="En-tête incorrect",
        description="Description",
        recommendation="Correction",
        value=value,
    )


@pytest.mark.parametrize(
    ("check", "value", "observed", "bad"),
    [
        (CheckType.PRESENT, None, None, True),
        (CheckType.PRESENT, None, "", False),
        (CheckType.EQUALS, "nosniff", "NOSNIFF", False),
        (CheckType.EQUALS, "nosniff", " nosniff ", False),
        (CheckType.EQUALS, "nosniff", "other", True),
        (CheckType.EQUALS, "nosniff", None, True),
        (CheckType.MIN_MAX_AGE, 31536000, "max-age=31536000", False),
        (CheckType.MIN_MAX_AGE, 31536000, 'includeSubDomains; MAX-AGE = "63072000"', False),
        (CheckType.MIN_MAX_AGE, 31536000, "max-age=300", True),
        (CheckType.MIN_MAX_AGE, 31536000, "includeSubDomains", True),
        (CheckType.MIN_MAX_AGE, 31536000, "max-age=nope", True),
        (CheckType.MIN_MAX_AGE, 31536000, "max-age=1.5", True),
        (CheckType.MIN_MAX_AGE, 31536000, None, True),
        (CheckType.MUST_NOT_CONTAIN, "unsafe-inline", "default-src 'self'", False),
        (CheckType.MUST_NOT_CONTAIN, "unsafe-inline", "script-src 'UNSAFE-INLINE'", True),
        (CheckType.MUST_NOT_CONTAIN, "unsafe-inline", None, True),
    ],
)
def test_checks(check, value, observed, bad):
    rule = make_rule(check, value)
    headers = httpx.Headers({} if observed is None else {rule.header: observed})
    findings = analyze_headers(headers, [rule])
    assert len(findings) == int(bad)
    if bad:
        finding = findings[0]
        assert finding.id == rule.id
        assert finding.scanner == "headers"
        assert finding.category == "en-têtes HTTP"
        assert finding.severity is rule.severity
        assert (finding.title, finding.description, finding.recommendation) == (
            rule.title,
            rule.description,
            rule.recommendation,
        )
        assert (observed if observed is not None else "absent") in finding.evidence


@pytest.mark.parametrize(
    ("check", "value"),
    [
        (CheckType.PRESENT, "x"),
        (CheckType.COOKIE_FLAGS, 1),
        (CheckType.EQUALS, None),
        (CheckType.EQUALS, 1),
        (CheckType.MUST_NOT_CONTAIN, None),
        (CheckType.MUST_NOT_CONTAIN, 2),
        (CheckType.MIN_MAX_AGE, "10"),
        (CheckType.MIN_MAX_AGE, True),
        (CheckType.MIN_MAX_AGE, -1),
        (CheckType.MIN_MAX_AGE, None),
    ],
)
def test_invalid_rule_value(check, value):
    with pytest.raises(ValueError, match="value"):
        make_rule(check, value)


def test_rule_is_immutable():
    rule = make_rule(CheckType.PRESENT)
    with pytest.raises(FrozenInstanceError):
        rule.value = "x"


def test_evidence_truncates_observed_value():
    observed = "x" * 201
    evidence = analyze_headers(
        httpx.Headers({"X-Test": observed}), [make_rule(CheckType.EQUALS, "nosniff")]
    )[0].evidence
    assert "x" * 200 in evidence
    assert "x" * 201 not in evidence


def test_cookie_flags_and_secret_redaction():
    headers = httpx.Headers(
        [
            ("Set-Cookie", "session=secret-token; Secure; Path=/"),
            ("Set-Cookie", "prefs=private-value; HttpOnly; SameSite=Lax"),
        ]
    )
    findings = analyze_headers(headers, [make_rule(CheckType.COOKIE_FLAGS, header="Set-Cookie")])
    assert [f.id for f in findings] == [
        "headers.test.httponly",
        "headers.test.samesite",
        "headers.test.secure",
    ]
    assert all("session" in f.evidence for f in findings[:2])
    assert "prefs" in findings[2].evidence
    assert all(
        "secret-token" not in f.evidence and "private-value" not in f.evidence for f in findings
    )


@pytest.mark.parametrize("cookie", [None, "session=secret; secure; HTTPONLY; samesite=Strict"])
def test_cookie_flags_ok(cookie):
    headers = httpx.Headers({} if cookie is None else {"Set-Cookie": cookie})
    assert analyze_headers(headers, [make_rule(CheckType.COOKIE_FLAGS)]) == []


def test_cookie_value_is_not_treated_as_flag():
    findings = analyze_headers(
        httpx.Headers({"Set-Cookie": "session=Secure; Path=/HttpOnly/SameSite"}),
        [make_rule(CheckType.COOKIE_FLAGS)],
    )
    assert len(findings) == 3


def default_rules():
    return load_header_rules(Path(__file__).resolve().parents[2] / "config/header_rules.yaml")


def test_well_configured_site():
    headers = httpx.Headers(
        {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Set-Cookie": "session=secret; Secure; HttpOnly; SameSite=Lax",
        }
    )
    assert analyze_headers(headers, default_rules()) == []


def test_badly_configured_site():
    findings = analyze_headers(httpx.Headers({"Set-Cookie": "session=secret"}), default_rules())
    assert {f.id for f in findings} == {
        "headers.hsts",
        "headers.csp",
        "headers.x_content_type_options",
        "headers.referrer_policy",
        "headers.permissions_policy",
        "headers.cookie.secure",
        "headers.cookie.httponly",
        "headers.cookie.samesite",
    }


@pytest.mark.parametrize("status", [200, 301])
def test_scanner_gets_once_without_following_redirects(status):
    url = "https://example.test/"
    with respx.mock(assert_all_called=True) as router:
        route = router.get(url).mock(
            return_value=httpx.Response(
                status,
                headers={"Location": "https://redirect.test/"},
            )
        )
        with httpx.Client(follow_redirects=True) as client:
            scanner: Scanner = HeadersScanner(client, [make_rule(CheckType.PRESENT)])
            assert scanner.name == "headers"
            assert len(scanner.run(Target(url))) == 1
        assert route.call_count == 1
        assert len(router.calls) == 1
        assert router.calls[0].request.method == "GET"
        assert str(router.calls[0].request.url) == url


def test_httpx_errors_propagate():
    error = httpx.ConnectError("connection failed")
    with respx.mock(assert_all_called=True) as router:
        router.get("https://example.test/").mock(side_effect=error)
        with httpx.Client() as client:
            with pytest.raises(httpx.ConnectError) as caught:
                HeadersScanner(client, []).run(Target("https://example.test/"))
    assert caught.value is error


def test_respx_blocks_unmocked_requests():
    with respx.mock(assert_all_called=True):
        with httpx.Client() as client:
            with pytest.raises(AssertionError):
                client.get("https://unmocked.test/")
