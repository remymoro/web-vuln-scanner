"""Garde synchrone : contrôle des URL et épinglage des IP à la connexion TCP."""

import ipaddress
import socket
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

import httpcore
import httpx

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
_SOCKET_OPTION = tuple[int, int, int | bytes | bytearray] | tuple[int, int, None, int]


class SsrfBlockedError(Exception):
    """La destination ne respecte pas la politique anti-SSRF."""


def is_ip_allowed(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool = False
) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = []
        if ip.ipv4_mapped is not None:
            embedded.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            embedded.append(ip.sixtofour)
        if ip.teredo is not None:
            embedded.extend(ip.teredo)
        if ip in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if any(not is_ip_allowed(inner) for inner in embedded):
            return False

    if allow_private and any(ip in network for network in _PRIVATE_NETWORKS):
        return True

    return ip.is_global and not (
        ip.is_multicast
        or ip.is_unspecified
        or ip.is_loopback
        or ip.is_link_local
        or (isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local)
        or ip.is_private
        or ip.is_reserved
    )


def resolve_and_check(host: str, port: int, *, allowed_hosts: Iterable[str] = ()) -> list[str]:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SsrfBlockedError(f"Resolution impossible for host {host!r}: {exc}") from exc
    if not addresses:
        raise SsrfBlockedError(f"Resolution returned no address for host {host!r}")

    ips = []
    for address in addresses:
        raw_ip = address[4][0].split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise SsrfBlockedError(f"Resolution returned an invalid IP: {raw_ip!r}") from exc
        if not is_ip_allowed(ip, allow_private=host in allowed_hosts):
            raise SsrfBlockedError(f"Forbidden IP {ip} for host {host!r}")
        normalized = str(ip)
        if normalized not in ips:
            ips.append(normalized)
    return ips


def _port_allowed(host: str, port: int, extra_ports: frozenset[tuple[str, int]]) -> bool:
    return port in ALLOWED_PORTS or (host, port) in extra_ports


def _check_extra_ports(
    extra_ports: Iterable[tuple[str, int]], allowed_hosts: frozenset[str]
) -> frozenset[tuple[str, int]]:
    # Exception de démo : un port hors 80/443 n'est accepté que pour un nom déjà autorisé.
    extra_ports = frozenset(extra_ports)
    if any(host not in allowed_hosts or not 1 <= port <= 65535 for host, port in extra_ports):
        raise ValueError("Extra ports require an allowed host and a valid port")
    return extra_ports


def _check_url_parts(
    url: str | httpx.URL, extra_ports: frozenset[tuple[str, int]] = frozenset()
) -> tuple[str, int]:
    try:
        has_userinfo = isinstance(url, str) and "@" in urlsplit(url).netloc
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError) as exc:
        raise SsrfBlockedError(f"Invalid URL: {exc}") from exc
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SsrfBlockedError(f"Scheme {parsed.scheme!r} is forbidden; use http or https")
    if not parsed.host:
        raise SsrfBlockedError("Host must not be empty")
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if not _port_allowed(parsed.host, port, extra_ports):
        raise SsrfBlockedError(f"Port {port} is forbidden; use 80 or 443")
    if has_userinfo or parsed.userinfo:
        raise SsrfBlockedError("Userinfo is forbidden in target URLs")
    return parsed.host, port


def check_url(
    url: str | httpx.URL,
    *,
    allowed_hosts: Iterable[str] = (),
    extra_ports: Iterable[tuple[str, int]] = (),
) -> None:
    allowed_hosts = frozenset(allowed_hosts)
    host, port = _check_url_parts(url, _check_extra_ports(extra_ports, allowed_hosts))
    resolve_and_check(host, port, allowed_hosts=allowed_hosts)


class GuardedNetworkBackend(httpcore.NetworkBackend):
    """Décore le backend : seul un littéral IP validé atteint la connexion TCP."""

    def __init__(
        self,
        backend: httpcore.NetworkBackend | None = None,
        *,
        allowed_hosts: Iterable[str] = (),
        extra_ports: Iterable[tuple[str, int]] = (),
    ) -> None:
        self._backend = backend if backend is not None else httpcore.SyncBackend()
        self._allowed_hosts = frozenset(allowed_hosts)
        self._extra_ports = _check_extra_ports(extra_ports, self._allowed_hosts)

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[_SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        if not _port_allowed(host, port, self._extra_ports):
            raise SsrfBlockedError(f"Port {port} is forbidden; use 80 or 443")
        ips = resolve_and_check(host, port, allowed_hosts=self._allowed_hosts)
        # Réutilisable même si l'appelant fournit un générateur d'options.
        options = None if socket_options is None else tuple(socket_options)
        for index, ip in enumerate(ips):
            try:
                return self._backend.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError):
                if index == len(ips) - 1:
                    raise
        raise AssertionError("resolve_and_check must return at least one IP")

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[_SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        raise SsrfBlockedError("Unix socket connections are forbidden")

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class _GuardedTransport(httpx.HTTPTransport):
    def __init__(
        self,
        network_backend: httpcore.NetworkBackend | None = None,
        *,
        allowed_hosts: Iterable[str] = (),
        extra_ports: Iterable[tuple[str, int]] = (),
        extra_ca_file: str | Path | None = None,
    ) -> None:
        self._extra_ports = _check_extra_ports(extra_ports, frozenset(allowed_hosts))
        limits = httpx.Limits()
        super().__init__(verify=True, trust_env=False, limits=limits, retries=0)
        original_pool = self._pool
        if extra_ca_file is not None:
            original_pool._ssl_context.load_verify_locations(cafile=extra_ca_file)
        # HTTPTransport ne permet pas d'injecter un backend. Conserver son contexte
        # vérifié et ses limites ; cet accès privé est couvert par les tests TLS.
        self._pool = httpcore.ConnectionPool(
            ssl_context=original_pool._ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=GuardedNetworkBackend(
                network_backend, allowed_hosts=allowed_hosts, extra_ports=self._extra_ports
            ),
        )
        original_pool.close()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Appliquer aussi la politique d'URL aux appels directs du client, même
        # lorsqu'une connexion existante peut être réutilisée par le pool.
        _check_url_parts(request.url, self._extra_ports)
        return super().handle_request(request)


class _SafeClient(httpx.Client):
    def __init__(
        self,
        timeout: float,
        *,
        network_backend: httpcore.NetworkBackend | None,
        allowed_hosts: Iterable[str],
        extra_ports: Iterable[tuple[str, int]],
        extra_ca_file: str | Path | None,
    ) -> None:
        self.allowed_hosts = frozenset(allowed_hosts)
        self.extra_ports = _check_extra_ports(extra_ports, self.allowed_hosts)
        super().__init__(
            transport=_GuardedTransport(
                network_backend,
                allowed_hosts=self.allowed_hosts,
                extra_ports=self.extra_ports,
                extra_ca_file=extra_ca_file,
            ),
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )


def _create_safe_client(
    timeout: float = 10.0,
    *,
    network_backend: httpcore.NetworkBackend | None = None,
    allowed_hosts: Iterable[str] = (),
    extra_ports: Iterable[tuple[str, int]] = (),
    extra_ca_file: str | Path | None = None,
) -> httpx.Client:
    return _SafeClient(
        timeout,
        network_backend=network_backend,
        allowed_hosts=allowed_hosts,
        extra_ports=extra_ports,
        extra_ca_file=extra_ca_file,
    )


def create_safe_client(
    timeout: float = 10.0,
    *,
    allowed_hosts: Iterable[str] = (),
    extra_ports: Iterable[tuple[str, int]] = (),
    extra_ca_file: str | Path | None = None,
) -> httpx.Client:
    """Seule fabrique de clients HTTP autorisée pour contacter une cible."""
    return _create_safe_client(
        timeout, allowed_hosts=allowed_hosts, extra_ports=extra_ports, extra_ca_file=extra_ca_file
    )


def safe_get(client: httpx.Client, url: str, max_redirects: int = 5) -> httpx.Response:
    if max_redirects < 0:
        raise SsrfBlockedError("Redirect limit must not be negative")
    redirects = 0
    while True:
        safe = isinstance(client, _SafeClient)
        check_url(
            url,
            allowed_hosts=client.allowed_hosts if safe else (),
            extra_ports=client.extra_ports if safe else (),
        )
        response = client.get(url, follow_redirects=False)
        location = response.headers.get("location")
        if response.status_code not in {301, 302, 303, 307, 308} or location is None:
            return response
        try:
            if redirects >= max_redirects:
                raise SsrfBlockedError(f"Redirect limit exceeded ({max_redirects})")
            try:
                url = str(response.url.join(location))
            except httpx.InvalidURL as exc:
                raise SsrfBlockedError(f"Invalid redirect URL: {exc}") from exc
        finally:
            response.close()
        redirects += 1
