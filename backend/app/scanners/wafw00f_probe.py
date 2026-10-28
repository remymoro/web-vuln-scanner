"""Seul import de wafw00f : son réseau est remplacé par le client anti-SSRF."""

from dataclasses import dataclass
from inspect import signature
from time import monotonic, sleep

import httpx
from wafw00f import __version__
from wafw00f.main import WAFW00F

from app.domain.target import Target
from app.scanners.waf import WafProbeError, WafReport

MAX_RESPONSE_SIZE = 100 * 1024
MAX_REQUESTS = 7
_REQUEST_SIGNATURE = "(self, headers=None, path=None, params={}, delay=0)"


def validate_network_timeout(network_timeout: int) -> None:
    if type(network_timeout) is not int or not 1 <= network_timeout <= 10:
        raise ValueError("waf network_timeout must be an integer between 1 and 10 seconds")


def validate_wafw00f_contract() -> None:
    # Refuser une évolution non auditée avant la première requête (y compris
    # celle du constructeur parent). Aucun patch global de requests.
    if __version__ != "2.4.2" or str(signature(WAFW00F.Request)) != _REQUEST_SIGNATURE:
        raise ValueError("Unsupported wafw00f version or Request signature; audit required")


@dataclass(frozen=True)
class _Response:
    status_code: int
    reason: str
    headers: httpx.Headers
    content: bytes
    text: str
    url: str


class _SafeWAFW00F(WAFW00F):
    def __init__(self, client: httpx.Client, target: Target, network_timeout: int) -> None:
        validate_wafw00f_contract()
        self._client = client
        self._target_url = target.url
        super().__init__(target.url, followredirect=False, proxies=None, timeout=network_timeout)

    def Request(self, headers=None, path=None, params=None, delay=0):
        # Le parent 2.4.2 ignore path : garder exactement l'URL cible, sans join.
        # Remonter toute erreur : None pourrait devenir un faux WAF générique
        # via RequestBlocked, ou une fausse absence dans identwaf.
        if self.requestnumber >= MAX_REQUESTS:
            raise WafProbeError("WAF request budget exhausted")
        if delay:
            sleep(delay)
        timeout = httpx.Timeout(
            **{
                phase: self.timeout if value is None else min(value, self.timeout)
                for phase, value in self._client.timeout.as_dict().items()
            }
        )
        requested_headers = httpx.Headers(headers or self.headers)
        url = httpx.URL(self._target_url)
        if params:
            query = str(httpx.QueryParams(params)).encode("ascii")
            url = url.copy_with(query=url.query + b"&" + query if url.query else query)
        request = self._client.build_request(
            "GET",
            url,
            headers=requested_headers,
            timeout=timeout,
        )
        # HTTPX fusionne les en-têtes du client : retirer les ajouts, notamment
        # User-Agent, dont l'absence est testée par genericdetect. Garder Host.
        for name in tuple(request.headers):
            if name not in requested_headers and name != "host":
                del request.headers[name]
        self.requestnumber += 1
        deadline = monotonic() + self.timeout
        response = self._client.send(request, stream=True, follow_redirects=False)
        try:
            content = bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if monotonic() >= deadline:
                    raise httpx.ReadTimeout("WAF response body deadline exceeded", request=request)
                content.extend(chunk[: MAX_RESPONSE_SIZE - len(content)])
                if len(content) >= MAX_RESPONSE_SIZE:
                    break
            body = bytes(content)
            # Décodage local seulement, aucune lecture supplémentaire. Les
            # cookies sont lus par matchCookie via Set-Cookie, pas via .cookies.
            decoded = httpx.Response(200, content=body)
            decoded.encoding = response.encoding
            return _Response(
                response.status_code,
                response.reason_phrase,
                httpx.Headers(response.headers),
                body,
                decoded.text,
                str(response.url),
            )
        finally:
            response.close()


class Wafw00fProbe:
    def __init__(self, client: httpx.Client, *, network_timeout: int = 3) -> None:
        validate_network_timeout(network_timeout)
        validate_wafw00f_contract()
        self._client = client
        self._network_timeout = network_timeout

    def scan(self, target: Target) -> WafReport:
        engine = _SafeWAFW00F(self._client, target, self._network_timeout)
        # Arrêt au premier nom : pas de requête supplémentaire par signature.
        names, _ = engine.identwaf(findall=False)
        generic = bool(engine.genericdetect()) if not names else False
        return WafReport(tuple(names), generic)
