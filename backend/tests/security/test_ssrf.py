import ipaddress
import socket
import ssl

import httpcore
import httpx
import pytest

from app.security.ssrf import (
    GuardedNetworkBackend,
    SsrfBlockedError,
    _create_safe_client,
    check_url,
    create_safe_client,
    is_ip_allowed,
    resolve_and_check,
    safe_get,
)


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    table = {"example.test": ["93.184.215.14"], "other.test": ["1.1.1.1"]}
    calls = []

    def getaddrinfo(host, port, *, type):
        assert type == socket.SOCK_STREAM
        calls.append((host, port))
        addresses = table.get(host)
        if addresses is None:
            try:
                ipaddress.ip_address(host.split("%")[0])
            except ValueError:
                raise socket.gaierror("simulated DNS failure") from None
            addresses = [host]
        if callable(addresses):
            addresses = addresses()
        return [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, port),
            )
            for address in addresses
        ]

    def forbidden_network(*args, **kwargs):
        pytest.fail("Real TCP connection attempted")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", forbidden_network)
    monkeypatch.setattr(socket.socket, "connect", forbidden_network)
    return table, calls


class MemoryStream(httpcore.NetworkStream):
    def __init__(self):
        self.data = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
        self.written = b""
        self.closed = False
        self.tls = None

    def read(self, max_bytes, timeout=None):
        data, self.data = self.data[:max_bytes], self.data[max_bytes:]
        return data

    def write(self, buffer, timeout=None):
        self.written += buffer

    def close(self):
        self.closed = True

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.tls = (ssl_context, server_hostname)
        return self


class FakeBackend(httpcore.NetworkBackend):
    def __init__(self, failures=()):
        self.calls = []
        self.streams = []
        self.failures = dict(failures)
        self.sleeps = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        # The wrapped backend must never receive a DNS name.
        ipaddress.ip_address(host)
        self.calls.append((host, port, timeout, local_address, socket_options))
        if host in self.failures:
            raise self.failures[host]
        stream = MemoryStream()
        self.streams.append(stream)
        return stream

    def sleep(self, seconds):
        self.sleeps.append(seconds)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fec0::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "2002:7f00:0001::1",
        "64:ff9b::7f00:1",
        # Teredo: private server, then private client (inverted last 32 bits).
        "2001:0:a00:1:0:0:fefe:fefe",
        "2001:0:101:101:0:0:80ff:fffe",
        "2002:0a00:0001::1",
        "64:ff9b::a00:1",
        "ff0e::1",
    ],
)
def test_forbidden_ip(address):
    assert not is_ip_allowed(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ip(address):
    assert is_ip_allowed(ipaddress.ip_address(address))


@pytest.mark.parametrize("addresses", [["10.0.0.1"], ["1.1.1.1", "127.0.0.1"]])
def test_dns_blocks_any_forbidden_address(dns, addresses):
    dns[0]["example.test"] = addresses
    with pytest.raises(SsrfBlockedError, match=addresses[-1].replace(".", r"\.")):
        resolve_and_check("example.test", 80)


@pytest.mark.parametrize("host", ["missing.test", "empty.test"])
def test_dns_failure(dns, host):
    dns[0]["empty.test"] = []
    with pytest.raises(SsrfBlockedError, match="[Rr]esol"):
        resolve_and_check(host, 80)


def test_dns_deduplicates_and_strips_scope(dns):
    dns[0]["example.test"] = ["2606:4700:4700::1111%eth0", "1.1.1.1", "1.1.1.1"]
    assert resolve_and_check("example.test", 443) == ["2606:4700:4700::1111", "1.1.1.1"]
    assert dns[1] == [("example.test", 443)]


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("file:///etc/passwd", "[Ss]cheme"),
        ("gopher://example.test/", "[Ss]cheme"),
        ("ftp://example.test/", "[Ss]cheme"),
        ("http://example.test:8080/", "[Pp]ort"),
        ("http://user:pass@example.test/", "[Uu]serinfo"),
        ("http://user@example.test/", "[Uu]serinfo"),
        ("http://@example.test/", "[Uu]serinfo"),
        ("http://127.0.0.1/", "127"),
        ("http://[::1]/", "::1"),
        ("http:///", "[Hh]ost"),
        ("http://example.test:bad/", "[Uu][Rr][Ll]|[Pp]ort"),
    ],
)
def test_invalid_url(url, message):
    with pytest.raises(SsrfBlockedError, match=message):
        check_url(url)


@pytest.mark.parametrize("url", ["http://example.test/", "https://example.test:443/"])
def test_valid_url(url):
    check_url(url)
    check_url(httpx.URL(url))


def test_backend_connects_to_ip_and_delegates_options():
    wrapped = FakeBackend()
    backend = GuardedNetworkBackend(wrapped)
    options = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
    backend.connect_tcp("example.test", 80, 2.0, "0.0.0.0", options)
    assert wrapped.calls == [("93.184.215.14", 80, 2.0, "0.0.0.0", tuple(options))]
    backend.sleep(0.1)
    assert wrapped.sleeps == [0.1]


@pytest.mark.parametrize("port", [80, 8080])
def test_backend_blocks_before_connect(dns, port):
    dns[0]["example.test"] = ["10.0.0.1"]
    wrapped = FakeBackend()
    with pytest.raises(SsrfBlockedError):
        GuardedNetworkBackend(wrapped).connect_tcp("example.test", port)
    assert wrapped.calls == []


def test_unix_socket_blocked():
    with pytest.raises(SsrfBlockedError, match="[Uu][Nn][Ii][Xx]"):
        GuardedNetworkBackend(FakeBackend()).connect_unix_socket("/tmp/service.sock")


def test_backend_fallback_and_last_error(dns):
    dns[0]["example.test"] = ["1.1.1.1", "93.184.215.14"]
    first = httpcore.ConnectTimeout("first")
    last = httpcore.ConnectError("last")
    wrapped = FakeBackend({"1.1.1.1": first})
    backend = GuardedNetworkBackend(wrapped)
    backend.connect_tcp("example.test", 80)
    assert [call[0] for call in wrapped.calls] == ["1.1.1.1", "93.184.215.14"]
    wrapped.failures["93.184.215.14"] = last
    with pytest.raises(httpcore.ConnectError) as caught:
        backend.connect_tcp("example.test", 80)
    assert caught.value is last


def test_rebinding_each_connection_is_checked(dns):
    answers = iter([["93.184.215.14"], ["127.0.0.1"]])
    dns[0]["example.test"] = lambda: next(answers)
    wrapped = FakeBackend()
    backend = GuardedNetworkBackend(wrapped)
    backend.connect_tcp("example.test", 80)
    with pytest.raises(SsrfBlockedError, match="127.0.0.1"):
        backend.connect_tcp("example.test", 80)
    assert [call[:2] for call in wrapped.calls] == [("93.184.215.14", 80)]
    assert dns[1] == [("example.test", 80), ("example.test", 80)]


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_client_end_to_end_and_original_tls_name(dns, monkeypatch, scheme):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8080")
    wrapped = FakeBackend()
    with _create_safe_client(network_backend=wrapped) as client:
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert client.get(f"{scheme}://example.test/").text == "OK"
    assert wrapped.calls[0][:2] == ("93.184.215.14", 443 if scheme == "https" else 80)
    assert b"Host: example.test\r\n" in wrapped.streams[0].written
    if scheme == "https":
        context, hostname = wrapped.streams[0].tls
        assert hostname == "example.test"
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED


def test_public_factory_configuration():
    with create_safe_client(timeout=3.0) as client:
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert client.timeout.connect == 3.0


def test_exception_propagates_unchanged_through_httpx(monkeypatch):
    error = SsrfBlockedError("blocked at connection")

    def blocked(*args, **kwargs):
        raise error

    monkeypatch.setattr(GuardedNetworkBackend, "connect_tcp", blocked)
    with _create_safe_client(network_backend=FakeBackend()) as client:
        with pytest.raises(SsrfBlockedError) as caught:
            client.get("http://example.test/")
    assert caught.value is error


def test_client_blocks_private_dns(dns):
    dns[0]["example.test"] = ["10.0.0.1"]
    wrapped = FakeBackend()
    with _create_safe_client(network_backend=wrapped) as client:
        with pytest.raises(SsrfBlockedError, match="10.0.0.1"):
            client.get("http://example.test/")
    assert wrapped.calls == []


def test_safe_get_checks_again_at_connection(dns):
    answers = iter([["1.1.1.1"], ["127.0.0.1"]])
    dns[0]["example.test"] = lambda: next(answers)
    wrapped = FakeBackend()
    with _create_safe_client(network_backend=wrapped) as client:
        with pytest.raises(SsrfBlockedError, match="127.0.0.1"):
            safe_get(client, "http://example.test/")
    assert wrapped.calls == []


def test_redirect_to_metadata_blocked_before_connection():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SsrfBlockedError, match="169.254.169.254"):
            safe_get(client, "http://example.test/")
    assert calls == ["http://example.test/"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", ["/next", "https://other.test/next"])
def test_redirect_followed_and_intermediate_closed(status, location):
    responses = []
    calls = []

    def handler(request):
        calls.append(str(request.url))
        response = (
            httpx.Response(status, headers={"Location": location})
            if len(calls) == 1
            else httpx.Response(200)
        )
        responses.append(response)
        return response

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = safe_get(client, "http://example.test/", max_redirects=1)
    assert result.status_code == 200
    assert calls == [
        "http://example.test/",
        "http://example.test/next" if location == "/next" else location,
    ]
    assert responses[0].is_closed


@pytest.mark.parametrize("max_redirects", [0, 2, 5])
def test_redirect_limit(max_redirects):
    responses = []

    def handler(request):
        response = httpx.Response(302, headers={"Location": "/"})
        responses.append(response)
        return response

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SsrfBlockedError, match="[Rr]edirect"):
            safe_get(client, "http://example.test/", max_redirects=max_redirects)
    assert len(responses) == max_redirects + 1
    assert all(response.is_closed for response in responses)


@pytest.mark.parametrize("status", [200, 302, 304])
def test_response_without_redirect_location_is_returned(status):
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status))
    ) as client:
        assert safe_get(client, "http://example.test/", max_redirects=0).status_code == status


def test_rebinding_through_httpcore_never_connects_to_hostname(dns):
    answers = iter([["93.184.215.14"], ["127.0.0.1"]])
    dns[0]["example.test"] = lambda: next(answers)
    wrapped = FakeBackend()
    with _create_safe_client(network_backend=wrapped) as client:
        assert client.get("http://example.test/").text == "OK"
        with pytest.raises(SsrfBlockedError, match="127.0.0.1"):
            client.get("http://example.test/")
    assert [call[:2] for call in wrapped.calls] == [("93.184.215.14", 80)]
    assert dns[1] == [("example.test", 80), ("example.test", 80)]


@pytest.mark.parametrize("url", ["http://example.test:8080/", "http://user:pass@example.test/"])
def test_direct_client_enforces_url_policy(url):
    wrapped = FakeBackend()
    with _create_safe_client(network_backend=wrapped) as client:
        with pytest.raises(SsrfBlockedError):
            client.get(url)
    assert wrapped.calls == []


def test_private_scoped_ipv6_is_blocked(dns):
    dns[0]["example.test"] = ["fe80::1%eth0"]
    with pytest.raises(SsrfBlockedError, match="fe80::1"):
        resolve_and_check("example.test", 80)


def test_invalid_dns_address_is_blocked(dns):
    dns[0]["example.test"] = ["not-an-ip"]
    with pytest.raises(SsrfBlockedError, match="invalid IP"):
        resolve_and_check("example.test", 80)


def test_negative_redirect_limit_makes_no_request(dns):
    def handler(request):
        pytest.fail("No request expected for a negative redirect limit")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SsrfBlockedError, match="[Rr]edirect"):
            safe_get(client, "http://example.test/", max_redirects=-1)
    assert dns[1] == []
