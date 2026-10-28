import socket
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.domain.target import Target
from app.scanners import sslyze_probe as adapter
from app.scanners.tls import TlsProtocol, TlsScanner


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unexpected DNS or network connection")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.fixture
def make_certificate():
    key = ec.generate_private_key(ec.SECP256R1())

    def build(names=("example.test",), expires_at=None):
        now = datetime.now(UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(expires_at or now + timedelta(days=90))
        )
        if names is not None:
            general_names = []
            for name in names:
                try:
                    general_names.append(x509.IPAddress(ip_address(name)))
                except ValueError:
                    general_names.append(x509.DNSName(name))
            builder = builder.add_extension(
                x509.SubjectAlternativeName(general_names), critical=False
            )
        return builder.sign(key, hashes.SHA256())

    return build


def completed(result):
    return adapter.sslyze.ScanCommandAttempt(
        status=adapter.sslyze.ScanCommandAttemptStatusEnum.COMPLETED,
        error_reason=None,
        error_trace=None,
        result=result,
    )


@pytest.fixture
def scan_result(make_certificate):
    attempts = {
        command.value: completed(SimpleNamespace(accepted_cipher_suites=[]))
        for command in adapter._PROTOCOL_COMMANDS.values()
    }
    cipher = adapter.sslyze.CipherSuite(
        "TLS_AES_128_GCM_SHA256", False, 128, "TLS_AES_128_GCM_SHA256"
    )
    attempts["tls_1_3_cipher_suites"] = completed(
        SimpleNamespace(accepted_cipher_suites=[SimpleNamespace(cipher_suite=cipher)])
    )
    deployment = SimpleNamespace(
        received_certificate_chain=[make_certificate()],
        path_validation_results=[
            SimpleNamespace(was_validation_successful=False),
            SimpleNamespace(was_validation_successful=True),
        ],
    )
    attempts["certificate_info"] = completed(SimpleNamespace(certificate_deployments=[deployment]))
    attempts["heartbleed"] = completed(SimpleNamespace(is_vulnerable_to_heartbleed=False))
    attempts["openssl_ccs_injection"] = completed(
        SimpleNamespace(is_vulnerable_to_ccs_injection=False)
    )
    attempts["robot"] = completed(
        SimpleNamespace(robot_result=adapter.sslyze.RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)
    )
    return SimpleNamespace(
        connectivity_status=adapter.sslyze.ServerConnectivityStatusEnum.COMPLETED,
        scan_status=adapter.sslyze.ServerScanStatusEnum.COMPLETED,
        scan_result=SimpleNamespace(**attempts),
    )


@pytest.mark.parametrize("with_ca", [False, True])
def test_pins_guarded_ip_preserves_name_and_configures_only_requested_commands(
    monkeypatch, tmp_path, scan_result, with_ca
):
    ca = tmp_path / "ca.crt"
    ca.write_text("CA file checked for existence by the sslyze argument")
    backend = Mock()
    exhausted = []

    def results():
        yield scan_result
        exhausted.append(True)

    backend.get_results.side_effect = results
    factory = Mock(return_value=backend)
    monkeypatch.setattr(adapter.sslyze, "Scanner", factory)
    dns = Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))])
    monkeypatch.setattr(socket, "getaddrinfo", dns)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    probe = adapter.SslyzeProbe(
        network_timeout=2, network_max_retries=1, extra_ca_file=ca if with_ca else None
    )
    assert TlsScanner(probe, []).run(Target("https://example.test/")) == []
    dns.assert_called_once_with("example.test", 443, type=socket.SOCK_STREAM)
    (requests,) = backend.queue_scans.call_args.args
    (request,) = requests
    assert request.server_location.hostname == "example.test"
    assert request.server_location.port == 443
    assert request.server_location.ip_address == "93.184.215.14"
    assert request.server_location.http_proxy_settings is None
    assert request.network_configuration.tls_server_name_indication == "example.test"
    assert request.network_configuration.network_timeout == 2
    assert request.network_configuration.network_max_retries == 1
    assert {command.value for command in request.scan_commands} == {
        "ssl_2_0_cipher_suites",
        "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites",
        "tls_1_2_cipher_suites",
        "tls_1_3_cipher_suites",
        "certificate_info",
        "heartbleed",
        "robot",
        "openssl_ccs_injection",
    }
    argument = request.scan_commands_extra_arguments.certificate_info
    if with_ca:
        assert argument.custom_ca_file == ca
    else:
        assert argument is None
    assert exhausted == [True]


def test_translation_uses_our_frozen_data(scan_result):
    report = adapter._translate(scan_result, "example.test")
    assert report.accepted_protocols == frozenset({TlsProtocol.TLS_1_3})
    assert report.weak_cipher_suites == ()
    assert report.errors == ()
    (certificate,) = report.certificates
    assert certificate.hostname_matches
    assert certificate.chain_trusted
    leaf = scan_result.scan_result.certificate_info.result.certificate_deployments[0]
    assert certificate.expires_at == leaf.received_certificate_chain[0].not_valid_after_utc
    assert not report.heartbleed and not report.robot and not report.openssl_ccs


@pytest.mark.parametrize(
    ("name", "bits", "anonymous", "weak"),
    [
        ("TLS_RSA_WITH_RC4_128_SHA", 128, False, True),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 168, False, True),
        ("SSL_CK_DES_192_EDE3_CBC_WITH_MD5", 192, False, True),
        ("TLS_RSA_WITH_NULL_SHA", 0, False, True),
        ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 40, False, True),
        ("TLS_DH_anon_WITH_AES_128_CBC_SHA", 128, False, True),
        ("unknown-anonymous", 256, True, True),
        ("unknown-short-key", 127, False, True),
        ("TLS_AES_128_GCM_SHA256", 128, False, False),
        ("TLS_AES_256_GCM_SHA384", 256, False, False),
    ],
)
def test_weak_suite_translation(scan_result, name, bits, anonymous, weak):
    cipher = adapter.sslyze.CipherSuite(name, anonymous, bits, name)
    scan_result.scan_result.tls_1_2_cipher_suites = completed(
        SimpleNamespace(accepted_cipher_suites=[SimpleNamespace(cipher_suite=cipher)])
    )
    report = adapter._translate(scan_result, "example.test")
    assert TlsProtocol.TLS_1_2 in report.accepted_protocols
    assert bool(report.weak_cipher_suites) is weak
    if weak:
        assert report.weak_cipher_suites[0].name == name
        assert report.weak_cipher_suites[0].protocol is TlsProtocol.TLS_1_2


@pytest.mark.parametrize(
    ("names", "host", "matches"),
    [
        (("example.test",), "example.test", True),
        (("EXAMPLE.TEST",), "example.test", True),
        (("other.test", "example.test"), "example.test", True),
        (("*.example.test",), "www.example.test", True),
        (("*.example.test",), "a.b.example.test", False),
        (("*.example.test",), "example.test", False),
        (("w*.example.test",), "www.example.test", False),
        (("other.test",), "example.test", False),
        (None, "example.test", False),
        (("93.184.215.14",), "93.184.215.14", True),
        (("93.184.215.14",), "1.1.1.1", False),
        (("xn--bcher-kva.test",), "xn--bcher-kva.test", True),
    ],
)
def test_hostname_matching_uses_san(make_certificate, names, host, matches):
    assert adapter._hostname_matches(make_certificate(names), host) is matches


def test_multiple_deployments_and_untrusted_chain(scan_result, make_certificate):
    deployments = scan_result.scan_result.certificate_info.result.certificate_deployments
    expired = datetime.now(UTC) - timedelta(days=1)
    deployments.append(
        SimpleNamespace(
            received_certificate_chain=[make_certificate(("wrong.test",), expires_at=expired)],
            path_validation_results=[SimpleNamespace(was_validation_successful=False)],
        )
    )
    report = adapter._translate(scan_result, "example.test")
    assert len(report.certificates) == 2
    assert report.certificates[0].chain_trusted
    assert not report.certificates[1].chain_trusted
    assert not report.certificates[1].hostname_matches
    assert report.certificates[1].expires_at == expired.replace(microsecond=0)


@pytest.mark.parametrize("robot_result", list(adapter.sslyze.RobotScanResultEnum))
def test_vulnerabilities_and_robot_states(scan_result, robot_result):
    scan_result.scan_result.robot = completed(SimpleNamespace(robot_result=robot_result))
    scan_result.scan_result.heartbleed = completed(
        SimpleNamespace(is_vulnerable_to_heartbleed=True)
    )
    scan_result.scan_result.openssl_ccs_injection = completed(
        SimpleNamespace(is_vulnerable_to_ccs_injection=True)
    )
    report = adapter._translate(scan_result, "example.test")
    assert report.heartbleed and report.openssl_ccs
    assert report.robot is robot_result.name.startswith("VULNERABLE_")
    assert bool(report.errors) is (robot_result.name == "UNKNOWN_INCONSISTENT_RESULTS")


@pytest.mark.parametrize("status", ["ERROR", "NOT_SCHEDULED", "COMPLETED"])
def test_failed_or_missing_command_is_not_a_negative_result(scan_result, status):
    scan_result.scan_result.tls_1_3_cipher_suites = SimpleNamespace(
        status=adapter.sslyze.ScanCommandAttemptStatusEnum(status),
        result=None,
    )
    report = adapter._translate(scan_result, "example.test")
    assert report.errors == ("tls_1_3_cipher_suites",)


def test_connection_error_is_translated_without_internal_trace(scan_result):
    scan_result.connectivity_status = adapter.sslyze.ServerConnectivityStatusEnum.ERROR
    scan_result.scan_status = adapter.sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY
    scan_result.scan_result = None
    report = adapter._translate(scan_result, "example.test")
    assert report.errors == ("connectivity",)


@pytest.mark.parametrize("empty_chain", [False, True])
def test_missing_certificate_is_an_error(scan_result, empty_chain):
    deployments = scan_result.scan_result.certificate_info.result.certificate_deployments
    if empty_chain:
        deployments[0].received_certificate_chain.clear()
    else:
        deployments.clear()
    assert "missing_certificate" in adapter._translate(scan_result, "example.test").errors


def test_missing_scan_result_is_an_error(monkeypatch):
    scanner = Mock()
    scanner.get_results.return_value = iter(())
    monkeypatch.setattr(adapter.sslyze, "Scanner", lambda **kwargs: scanner)
    report = adapter.SslyzeProbe().scan("example.test", "93.184.215.14")
    assert report.errors == ("missing_scan_result",)
