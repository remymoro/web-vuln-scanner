import socket
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.domain.finding import Severity
from app.domain.target import Target
from app.infra.tls_rules_config import load_tls_rules
from app.scanners.tls import (
    TlsCertificate,
    TlsProbeError,
    TlsProtocol,
    TlsReport,
    TlsScanner,
    TlsWeakCipher,
    analyze_tls,
)
from app.security.ssrf import SsrfBlockedError

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)
CERTIFICATE = TlsCertificate(NOW + timedelta(days=90), True, True)
CLEAN = TlsReport(
    NOW,
    frozenset({TlsProtocol.TLS_1_2, TlsProtocol.TLS_1_3}),
    certificates=(CERTIFICATE,),
)
RULES = load_tls_rules(Path(__file__).resolve().parents[2] / "config/tls_rules.yaml")


def test_clean_report_has_no_findings():
    assert analyze_tls(CLEAN, RULES) == []


@pytest.mark.parametrize(
    ("protocol", "suffix", "severity"),
    [
        (TlsProtocol.SSL_2_0, "ssl_2_0", Severity.HIGH),
        (TlsProtocol.SSL_3_0, "ssl_3_0", Severity.HIGH),
        (TlsProtocol.TLS_1_0, "tls_1_0", Severity.MEDIUM),
        (TlsProtocol.TLS_1_1, "tls_1_1", Severity.MEDIUM),
    ],
)
def test_old_protocols(protocol, suffix, severity):
    report = replace(CLEAN, accepted_protocols=CLEAN.accepted_protocols | {protocol})
    (finding,) = analyze_tls(report, RULES)
    assert finding.id == f"tls.protocol.{suffix}"
    assert finding.severity is severity
    assert protocol in finding.evidence
    assert (finding.scanner, finding.category) == ("tls", "TLS")
    rule = next(rule for rule in RULES if rule.id == finding.id)
    assert (finding.title, finding.description, finding.recommendation) == (
        rule.title,
        rule.description,
        rule.recommendation,
    )


def test_tls_1_3_absent():
    (finding,) = analyze_tls(
        replace(CLEAN, accepted_protocols=frozenset({TlsProtocol.TLS_1_2})), RULES
    )
    assert finding.id == "tls.protocol.tls_1_3_missing"
    assert finding.severity is Severity.LOW


def test_weak_ciphers_are_grouped_with_protocol_and_deduplicated():
    suites = (
        TlsWeakCipher(TlsProtocol.TLS_1_2, "TLS_RSA_WITH_RC4_128_SHA"),
        TlsWeakCipher(TlsProtocol.TLS_1_1, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    )
    (finding,) = analyze_tls(replace(CLEAN, weak_cipher_suites=(*suites, suites[0])), RULES)
    assert finding.id == "tls.weak_ciphers"
    assert finding.severity is Severity.HIGH
    assert "TLS 1.2 : TLS_RSA_WITH_RC4_128_SHA" in finding.evidence
    assert "TLS 1.1 : TLS_RSA_WITH_3DES_EDE_CBC_SHA" in finding.evidence
    assert "(2)" in finding.evidence


def test_weak_cipher_evidence_is_bounded():
    suites = tuple(TlsWeakCipher(TlsProtocol.TLS_1_2, f"RC4_{i}_" + "x" * 500) for i in range(100))
    (finding,) = analyze_tls(replace(CLEAN, weak_cipher_suites=suites), RULES)
    assert len(finding.evidence) <= 1000
    assert finding.evidence.endswith("...")


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (timedelta(seconds=-1), "expired"),
        (timedelta(0), "expired"),
        (timedelta(seconds=1), "expiring"),
        (timedelta(days=30, seconds=-1), "expiring"),
        (timedelta(days=30), None),
        (timedelta(days=31), None),
    ],
)
def test_expiration_boundaries_and_no_double_penalty(delta, expected):
    certificate = replace(CERTIFICATE, expires_at=NOW + delta)
    findings = analyze_tls(replace(CLEAN, certificates=(certificate,)), RULES)
    assert [finding.id for finding in findings] == (
        [] if expected is None else [f"tls.certificate.{expected}"]
    )
    if findings:
        assert findings[0].severity is (Severity.HIGH if expected == "expired" else Severity.MEDIUM)
        assert certificate.expires_at.isoformat() in findings[0].evidence


def test_expiration_threshold_comes_from_rules():
    rules = tuple(replace(rule, days=60) if rule.days else rule for rule in RULES)
    certificate = replace(CERTIFICATE, expires_at=NOW + timedelta(days=40))
    (finding,) = analyze_tls(replace(CLEAN, certificates=(certificate,)), rules)
    assert finding.id == "tls.certificate.expiring"


@pytest.mark.parametrize(
    ("field", "suffix"), [("hostname_matches", "hostname"), ("chain_trusted", "untrusted")]
)
def test_bad_certificate_is_detected_among_multiple_deployments(field, suffix):
    certificate = replace(CERTIFICATE, **{field: False})
    report = replace(CLEAN, certificates=(CERTIFICATE, certificate, certificate))
    (finding,) = analyze_tls(report, RULES)
    assert finding.id == f"tls.certificate.{suffix}"
    assert finding.severity is Severity.HIGH
    assert "Certificat 2" in finding.evidence


@pytest.mark.parametrize("field", ["heartbleed", "robot", "openssl_ccs"])
def test_vulnerabilities(field):
    (finding,) = analyze_tls(replace(CLEAN, **{field: True}), RULES)
    assert finding.id == f"tls.{field}"
    assert finding.severity is Severity.HIGH


def test_probe_error_cannot_be_scored_as_clean_or_as_missing_tls_1_3():
    with pytest.raises(TlsProbeError):
        analyze_tls(TlsReport(NOW, errors=("connectivity",)), RULES)


def test_report_copies_collections_and_is_frozen():
    protocols = {TlsProtocol.TLS_1_3}
    certificates = [CERTIFICATE]
    report = TlsReport(NOW, protocols, certificates=certificates)
    protocols.clear()
    certificates.clear()
    assert report.accepted_protocols == frozenset({TlsProtocol.TLS_1_3})
    assert report.certificates == (CERTIFICATE,)
    with pytest.raises(FrozenInstanceError):
        report.robot = True
    with pytest.raises(FrozenInstanceError):
        CERTIFICATE.chain_trusted = False
    with pytest.raises(FrozenInstanceError):
        RULES[0].title = "changed"


@pytest.fixture
def dns(monkeypatch):
    addresses = ["93.184.215.14"]
    calls = []

    def getaddrinfo(host, port, *, type):
        assert type == socket.SOCK_STREAM
        calls.append((host, port))
        return [(socket.AF_INET, type, socket.IPPROTO_TCP, "", (ip, port)) for ip in addresses]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", lambda *a: pytest.fail("Real TCP attempted"))
    return addresses, calls


@pytest.mark.parametrize("url", ["https://example.test/path", "http://example.test:80/"])
def test_scanner_resolves_through_guard_and_uses_only_port_443(dns, url):
    probe = Mock()
    probe.scan.return_value = CLEAN
    assert TlsScanner(probe, RULES).run(Target(url)) == []
    assert dns[1] == [("example.test", 443)]
    probe.scan.assert_called_once_with("example.test", "93.184.215.14")


@pytest.mark.parametrize("ips", [["10.0.0.1"], ["93.184.215.14", "10.0.0.1"]])
def test_private_ip_blocks_before_probe(dns, ips):
    dns[0][:] = ips
    probe = Mock()
    with pytest.raises(SsrfBlockedError):
        TlsScanner(probe, RULES).run(Target("https://example.test/"))
    probe.scan.assert_not_called()


def test_exact_demo_host_can_use_private_ip(dns):
    dns[0][:] = ["172.20.0.3"]
    probe = Mock()
    probe.scan.return_value = CLEAN
    scanner = TlsScanner(probe, RULES, allowed_hosts={"demo.scanner.test"})
    assert scanner.run(Target("https://demo.scanner.test/")) == []
    probe.scan.assert_called_once_with("demo.scanner.test", "172.20.0.3")
    with pytest.raises(SsrfBlockedError):
        scanner.run(Target("https://other.test/"))
    assert probe.scan.call_count == 1


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "https://user@example.test/", "https://example.test:8443/", "https://"],
)
def test_invalid_target_fails_before_dns_and_probe(dns, url):
    probe = Mock()
    with pytest.raises(SsrfBlockedError):
        TlsScanner(probe, RULES).run(Target(url))
    assert dns[1] == []
    probe.scan.assert_not_called()


def test_demo_origin_port_is_accepted_but_tls_is_still_probed_on_443(dns):
    dns[0][:] = ["10.10.10.30"]
    probe = Mock()
    probe.scan.return_value = CLEAN
    scanner = TlsScanner(
        probe,
        RULES,
        allowed_hosts={"juiceshop.lab"},
        extra_ports={("juiceshop.lab", 3000)},
    )
    assert scanner.run(Target("http://juiceshop.lab:3000/")) == []
    assert dns[1] == [("juiceshop.lab", 443)]
    with pytest.raises(SsrfBlockedError):
        scanner.run(Target("http://juiceshop.lab:3001/"))
