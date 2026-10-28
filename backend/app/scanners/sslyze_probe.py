"""Adaptateur sslyze : ne reçoit qu'une IP déjà validée par la garde anti-SSRF."""

from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

import sslyze
from cryptography import x509

from app.scanners.tls import TlsCertificate, TlsProtocol, TlsReport, TlsWeakCipher

_PROTOCOL_COMMANDS = {
    TlsProtocol.SSL_2_0: sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
    TlsProtocol.SSL_3_0: sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
    TlsProtocol.TLS_1_0: sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
    TlsProtocol.TLS_1_1: sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
    TlsProtocol.TLS_1_2: sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
    TlsProtocol.TLS_1_3: sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
}
_COMMANDS = set(_PROTOCOL_COMMANDS.values()) | {
    sslyze.ScanCommand.CERTIFICATE_INFO,
    sslyze.ScanCommand.HEARTBLEED,
    sslyze.ScanCommand.ROBOT,
    sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
}


def _hostname_matches(certificate: x509.Certificate, host: str) -> bool:
    # SAN uniquement ; joker complet limité à une étiquette (pas de repli sur CN).
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        address = ip_address(host)
    except ValueError:
        labels = host.lower().split(".")
        for name in names.get_values_for_type(x509.DNSName):
            pattern = name.lower().split(".")
            if pattern == labels or (
                len(pattern) == len(labels)
                and pattern[0] == "*"
                and len(pattern) > 1
                and pattern[1:] == labels[1:]
                and "*" not in ".".join(pattern[1:])
                and labels[0]
            ):
                return True
        return False
    return address in names.get_values_for_type(x509.IPAddress)


def _weak_cipher(cipher: sslyze.CipherSuite) -> bool:
    name = cipher.name.upper()
    return (
        cipher.is_anonymous
        or cipher.key_size < 128
        or any(marker in name for marker in ("RC4", "3DES", "EDE3", "NULL", "EXPORT", "ANON"))
    )


def _translate(result: sslyze.ServerScanResult, host: str) -> TlsReport:
    now = datetime.now(UTC)
    if (
        result.connectivity_status != sslyze.ServerConnectivityStatusEnum.COMPLETED
        or result.scan_status != sslyze.ServerScanStatusEnum.COMPLETED
        or result.scan_result is None
    ):
        return TlsReport(now, errors=("connectivity",))

    values = {}
    errors = []
    for command in sorted(_COMMANDS, key=lambda command: command.value):
        attempt = getattr(result.scan_result, command.value)
        if (
            attempt.status != sslyze.ScanCommandAttemptStatusEnum.COMPLETED
            or attempt.result is None
        ):
            errors.append(command.value)
        else:
            values[command] = attempt.result

    protocols = set()
    weak_ciphers = []
    for protocol, command in _PROTOCOL_COMMANDS.items():
        if command not in values:
            continue
        for accepted in values[command].accepted_cipher_suites:
            protocols.add(protocol)
            if _weak_cipher(accepted.cipher_suite):
                weak_ciphers.append(TlsWeakCipher(protocol, accepted.cipher_suite.name))

    certificates = []
    cert_info = values.get(sslyze.ScanCommand.CERTIFICATE_INFO)
    if cert_info is not None:
        for deployment in cert_info.certificate_deployments:
            if not deployment.received_certificate_chain:
                errors.append("missing_certificate_chain")
                continue
            leaf = deployment.received_certificate_chain[0]
            certificates.append(
                TlsCertificate(
                    expires_at=leaf.not_valid_after_utc,
                    hostname_matches=_hostname_matches(leaf, host),
                    chain_trusted=any(
                        path.was_validation_successful
                        for path in deployment.path_validation_results
                    ),
                )
            )
        if not certificates:
            errors.append("missing_certificate")

    robot_result = values.get(sslyze.ScanCommand.ROBOT)
    robot = False
    if robot_result is not None:
        if robot_result.robot_result == sslyze.RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
            errors.append("robot_inconclusive")
        robot = robot_result.robot_result in {
            sslyze.RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
            sslyze.RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
        }
    heartbleed = values.get(sslyze.ScanCommand.HEARTBLEED)
    ccs = values.get(sslyze.ScanCommand.OPENSSL_CCS_INJECTION)
    return TlsReport(
        observed_at=now,
        accepted_protocols=frozenset(protocols),
        weak_cipher_suites=tuple(weak_ciphers),
        certificates=tuple(certificates),
        heartbleed=heartbleed.is_vulnerable_to_heartbleed if heartbleed else False,
        robot=robot,
        openssl_ccs=ccs.is_vulnerable_to_ccs_injection if ccs else False,
        errors=tuple(errors),
    )


class SslyzeProbe:
    def __init__(
        self,
        *,
        network_timeout: int = 3,
        network_max_retries: int = 0,
        extra_ca_file: Path | None = None,
    ) -> None:
        self._network_timeout = network_timeout
        self._network_max_retries = network_max_retries
        self._extra_ca_file = extra_ca_file

    def scan(self, host: str, ip: str) -> TlsReport:
        request = sslyze.ServerScanRequest(
            server_location=sslyze.ServerNetworkLocation(host, 443, ip_address=ip),
            network_configuration=sslyze.ServerNetworkConfiguration(
                tls_server_name_indication=host,
                network_timeout=self._network_timeout,
                network_max_retries=self._network_max_retries,
            ),
            scan_commands=set(_COMMANDS),
            scan_commands_extra_arguments=sslyze.ScanCommandsExtraArguments(
                certificate_info=(
                    sslyze.CertificateInfoExtraArgument(custom_ca_file=self._extra_ca_file)
                    if self._extra_ca_file is not None
                    else None
                )
            ),
        )
        scanner = sslyze.Scanner(concurrent_server_scans_limit=1)
        scanner.queue_scans([request])
        # Épuiser le générateur permet à sslyze de joindre ses threads de travail.
        results = list(scanner.get_results())
        if len(results) != 1:
            return TlsReport(datetime.now(UTC), errors=("missing_scan_result",))
        return _translate(results[0], host)
