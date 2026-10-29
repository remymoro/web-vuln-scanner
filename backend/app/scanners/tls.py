"""Données indépendantes de sslyze et analyse pure des contrôles TLS."""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from app.domain.finding import Finding, Severity
from app.domain.target import Target
from app.security.ssrf import SsrfBlockedError, resolve_and_check


class TlsProtocol(StrEnum):
    SSL_2_0 = "SSL 2.0"
    SSL_3_0 = "SSL 3.0"
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"


class TlsCheck(StrEnum):
    SSL_2_0 = "ssl_2_0"
    SSL_3_0 = "ssl_3_0"
    TLS_1_0 = "tls_1_0"
    TLS_1_1 = "tls_1_1"
    TLS_1_3_MISSING = "tls_1_3_missing"
    WEAK_CIPHERS = "weak_ciphers"
    CERTIFICATE_EXPIRED = "certificate_expired"
    CERTIFICATE_HOSTNAME = "certificate_hostname"
    CERTIFICATE_UNTRUSTED = "certificate_untrusted"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    HEARTBLEED = "heartbleed"
    ROBOT = "robot"
    OPENSSL_CCS = "openssl_ccs"


@dataclass(frozen=True)
class TlsRule:
    id: str
    check: TlsCheck
    severity: Severity
    title: str
    description: str
    recommendation: str
    days: int | None = None

    def __post_init__(self) -> None:
        if self.check == TlsCheck.CERTIFICATE_EXPIRING:
            if type(self.days) is not int or self.days <= 0:
                raise ValueError("days must be a positive integer for certificate_expiring")
        elif self.days is not None:
            raise ValueError("days is only supported for certificate_expiring")


@dataclass(frozen=True)
class TlsWeakCipher:
    protocol: TlsProtocol
    name: str


@dataclass(frozen=True)
class TlsCertificate:
    expires_at: datetime
    hostname_matches: bool
    chain_trusted: bool


@dataclass(frozen=True)
class TlsReport:
    observed_at: datetime
    accepted_protocols: frozenset[TlsProtocol] = frozenset()
    weak_cipher_suites: tuple[TlsWeakCipher, ...] = ()
    certificates: tuple[TlsCertificate, ...] = ()
    heartbleed: bool = False
    robot: bool = False
    openssl_ccs: bool = False
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "accepted_protocols", frozenset(self.accepted_protocols))
        for field in ("weak_cipher_suites", "certificates", "errors"):
            object.__setattr__(self, field, tuple(getattr(self, field)))


class TlsProbeError(Exception):
    """Les contrôles TLS n'ont pas tous pu être évalués."""


class TlsProbe(Protocol):
    def scan(self, host: str, ip: str) -> TlsReport: ...


_OLD_PROTOCOLS = {
    TlsCheck.SSL_2_0: TlsProtocol.SSL_2_0,
    TlsCheck.SSL_3_0: TlsProtocol.SSL_3_0,
    TlsCheck.TLS_1_0: TlsProtocol.TLS_1_0,
    TlsCheck.TLS_1_1: TlsProtocol.TLS_1_1,
}


def analyze_tls(report: TlsReport, rules: Sequence[TlsRule]) -> list[Finding]:
    if report.errors:
        raise TlsProbeError("TLS probe incomplete")
    findings = []
    for rule in rules:
        evidence = ""
        if rule.check in _OLD_PROTOCOLS:
            protocol = _OLD_PROTOCOLS[rule.check]
            if protocol in report.accepted_protocols:
                evidence = f"Protocole {protocol} accepté"
        elif rule.check == TlsCheck.TLS_1_3_MISSING:
            if TlsProtocol.TLS_1_3 not in report.accepted_protocols:
                evidence = "Protocole TLS 1.3 non accepté"
        elif rule.check == TlsCheck.WEAK_CIPHERS:
            if report.weak_cipher_suites:
                suites = sorted(
                    {f"{c.protocol} : {c.name[:160]}" for c in report.weak_cipher_suites}
                )
                evidence = f"Suites faibles acceptées ({len(suites)}) : " + "; ".join(suites)
        elif rule.check in (TlsCheck.HEARTBLEED, TlsCheck.ROBOT, TlsCheck.OPENSSL_CCS):
            if getattr(report, rule.check.value):
                evidence = f"Vulnérabilité {rule.check.value} détectée"
        else:
            for index, certificate in enumerate(report.certificates, 1):
                match rule.check:
                    case TlsCheck.CERTIFICATE_EXPIRED:
                        bad = certificate.expires_at <= report.observed_at
                        detail = f"expiré depuis le {certificate.expires_at.isoformat()}"
                    case TlsCheck.CERTIFICATE_EXPIRING:
                        bad = (
                            report.observed_at
                            < certificate.expires_at
                            < report.observed_at + timedelta(days=rule.days)
                        )
                        detail = f"expire le {certificate.expires_at.isoformat()}"
                    case TlsCheck.CERTIFICATE_HOSTNAME:
                        bad = not certificate.hostname_matches
                        detail = "ne correspond pas au nom de la cible"
                    case TlsCheck.CERTIFICATE_UNTRUSTED:
                        bad = not certificate.chain_trusted
                        detail = "chaîne non validée par les magasins de confiance"
                if bad:
                    evidence = f"Certificat {index} : {detail}"
                    break
        if evidence:
            findings.append(
                Finding(
                    id=rule.id,
                    scanner="tls",
                    category="TLS",
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=evidence[:997] + "..." if len(evidence) > 1000 else evidence,
                    recommendation=rule.recommendation,
                )
            )
    return findings


class TlsScanner:
    name = "tls"
    category = "TLS"

    def __init__(
        self,
        probe: TlsProbe,
        rules: Sequence[TlsRule],
        *,
        allowed_hosts: Iterable[str] = (),
        extra_ports: Iterable[tuple[str, int]] = (),
    ) -> None:
        self._probe = probe
        self._rules = tuple(rules)
        self._allowed_hosts = frozenset(allowed_hosts)
        self._extra_ports = frozenset(extra_ports)

    def run(self, target: Target) -> list[Finding]:
        try:
            url = urlsplit(target.url)
            if (
                url.scheme not in {"http", "https"}
                or not url.hostname
                or "@" in url.netloc
                or (
                    url.port not in {None, 80, 443}
                    and (url.hostname, url.port) not in self._extra_ports
                )
            ):
                raise ValueError("Invalid TLS target URL")
            host = url.hostname.encode("idna").decode("ascii")
        except ValueError as exc:
            raise SsrfBlockedError("Invalid TLS target URL") from exc
        ips = resolve_and_check(host, 443, allowed_hosts=self._allowed_hosts)
        return analyze_tls(self._probe.scan(host, ips[0]), self._rules)
