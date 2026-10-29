"""Pilotage passif de l'API REST de ZAP et traduction pure des alertes."""

import logging
import re
import uuid
from collections.abc import Callable, Iterable, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from time import monotonic
from time import sleep as time_sleep
from types import TracebackType
from typing import Protocol, Self
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr
from redis import Redis
from redis.exceptions import RedisError

from app.domain.finding import Finding, Severity
from app.domain.target import Target
from app.security.ssrf import SsrfBlockedError, resolve_and_check

ZAP_LOCK_KEY = "scanner:zap:lock"
_ENV_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
_RELEASE_LOCK_SCRIPT = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)
_RISK_TO_SEVERITY: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}


@dataclass(frozen=True)
class ZapExcludedRule:
    plugin_id: str
    name: str
    covered_by: str


@dataclass(frozen=True)
class ZapAlert:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str = ""
    description: str = ""
    solution: str = ""


class ZapProbeError(Exception):
    """L'analyse passive ZAP n'a pas pu être menée à terme."""


class ZapBusyError(ZapProbeError):
    """Le démon ZAP est déjà occupé par un autre scan."""


class ZapLock(Protocol):
    def __enter__(self) -> object: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


class ZapProbe(Protocol):
    def scan(self, target: Target) -> Sequence[ZapAlert]: ...


class _RedactZapApiKeyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                arg.copy_remove_param("apikey")
                if isinstance(arg, httpx.URL) and "apikey" in arg.params
                else arg
                for arg in record.args
            )
        return True


def _install_httpx_log_filter() -> None:
    httpx_logger = logging.getLogger("httpx")
    if not any(isinstance(f, _RedactZapApiKeyFilter) for f in httpx_logger.filters):
        httpx_logger.addFilter(_RedactZapApiKeyFilter())


_install_httpx_log_filter()


def validate_zap_api_url(api_url: object) -> str:
    if not isinstance(api_url, str) or not api_url.strip() or api_url != api_url.strip():
        raise ValueError("zap api_url must be a non-empty URL string")
    try:
        parsed = urlsplit(api_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("zap api_url is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("zap api_url must be a base http or https URL without path or query")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("zap api_url port is out of range")
    return api_url.rstrip("/")


def validate_zap_api_key_env(api_key_env: object) -> str:
    if not isinstance(api_key_env, str) or _ENV_NAME_PATTERN.fullmatch(api_key_env) is None:
        raise ValueError("zap api_key_env must be a valid uppercase environment variable name")
    return api_key_env


def validate_zap_options(
    *,
    max_depth: int = 3,
    max_children: int = 50,
    spider_timeout: int = 60,
    passive_timeout: int = 60,
) -> None:
    if type(max_depth) is not int or not 1 <= max_depth <= 10:
        raise ValueError("zap max_depth must be an integer between 1 and 10")
    if type(max_children) is not int or not 1 <= max_children <= 200:
        raise ValueError("zap max_children must be an integer between 1 and 200")
    if type(spider_timeout) is not int or not 1 <= spider_timeout <= 120:
        raise ValueError("zap spider_timeout must be an integer between 1 and 120 seconds")
    if type(passive_timeout) is not int or not 1 <= passive_timeout <= 120:
        raise ValueError("zap passive_timeout must be an integer between 1 and 120 seconds")


class _ZapInternalClient(httpx.Client):
    """Client HTTP interne dédié exclusivement à l'API REST de ZAP."""

    def __init__(self, api_url: str, *, timeout: float = 10.0) -> None:
        normalized = validate_zap_api_url(api_url)
        parsed = httpx.URL(normalized)
        self.api_url = normalized
        self._allowed_origin = (parsed.scheme, parsed.host, parsed.port)
        super().__init__(
            base_url=normalized,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        auth: object = httpx.USE_CLIENT_DEFAULT,
        follow_redirects: object = httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        if (
            request.url.scheme,
            request.url.host,
            request.url.port,
        ) != self._allowed_origin or not request.url.path.startswith("/JSON/"):
            raise ZapProbeError("Internal ZAP client cannot contact non-ZAP URLs")
        return super().send(
            request,
            stream=stream,
            auth=auth,
            follow_redirects=False,
        )


def create_zap_internal_client(api_url: str, *, timeout: float = 10.0) -> httpx.Client:
    """Crée un client HTTP interne réservé au démon ZAP (jamais pour joindre une cible)."""
    return _ZapInternalClient(api_url, timeout=timeout)


class RedisZapLock:
    """Verrou distribué Redis garantissant un seul scan ZAP à la fois."""

    def __init__(
        self,
        redis: Redis,
        *,
        key: str = ZAP_LOCK_KEY,
        ttl: int = 180,
        wait_timeout: float = 5.0,
        poll_interval: float = 0.2,
        clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], None] = time_sleep,
    ) -> None:
        if type(ttl) is not int or ttl <= 0:
            raise ValueError("zap lock ttl must be a positive integer")
        if (
            isinstance(wait_timeout, bool)
            or not isinstance(wait_timeout, (int, float))
            or wait_timeout < 0
        ):
            raise ValueError("zap lock wait_timeout must be a non-negative number")
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or poll_interval <= 0
        ):
            raise ValueError("zap lock poll_interval must be a positive number")
        self._redis = redis
        self._key = key
        self._ttl = ttl
        self._wait_timeout = float(wait_timeout)
        self._poll_interval = float(poll_interval)
        self._clock = clock
        self._sleep = sleep
        self._tokens: list[str] = []

    def __enter__(self) -> Self:
        token = uuid.uuid4().hex
        deadline = self._clock() + self._wait_timeout
        while True:
            try:
                acquired = bool(self._redis.set(self._key, token, nx=True, ex=self._ttl))
            except RedisError as exc:
                raise ZapProbeError("Cannot acquire ZAP Redis lock") from exc
            if acquired:
                self._tokens.append(token)
                return self
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise ZapBusyError("ZAP is already busy with another scan")
            self._sleep(min(self._poll_interval, remaining))

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if not self._tokens:
            return
        token = self._tokens.pop()
        try:
            self._redis.eval(_RELEASE_LOCK_SCRIPT, 1, self._key, token)
        except RedisError as exc:
            if exc_type is None:
                raise ZapProbeError("Cannot release ZAP Redis lock") from exc


def _parse_int(value: object, field: str) -> int:
    if type(value) is int:
        return value
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        return int(value.strip())
    raise ZapProbeError(f"Invalid integer for ZAP {field}")


def _parse_alert(item: object) -> ZapAlert:
    if not isinstance(item, dict):
        raise ZapProbeError("Each ZAP alert must be a JSON object")
    plugin_id = item.get("pluginId")
    name = item.get("name") or item.get("alert")
    risk = item.get("risk")
    confidence = item.get("confidence")
    url = item.get("url", "")
    description = item.get("description", "")
    solution = item.get("solution", "")
    if (
        not isinstance(plugin_id, str)
        or not plugin_id.strip()
        or not plugin_id.strip().isascii()
        or not plugin_id.strip().isdecimal()
        or not isinstance(name, str)
        or not name.strip()
        or not isinstance(risk, str)
        or not risk.strip()
        or not isinstance(confidence, str)
        or not confidence.strip()
        or not isinstance(url, str)
        or not isinstance(description, str)
        or not isinstance(solution, str)
    ):
        raise ZapProbeError("Invalid ZAP alert fields")
    return ZapAlert(
        plugin_id=plugin_id.strip(),
        name=name.strip(),
        risk=risk.strip(),
        confidence=confidence.strip(),
        url=url.strip(),
        description=description.strip(),
        solution=solution.strip(),
    )


class ZapHttpProbe:
    """Pilote ZAP via son API REST en exploration bornée et analyse passive uniquement."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        client: httpx.Client | None = None,
        max_depth: int = 3,
        max_children: int = 50,
        spider_timeout: int = 60,
        passive_timeout: int = 60,
        network_timeout: float = 10.0,
        poll_interval: float = 1.0,
        clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], None] = time_sleep,
        context_name_factory: Callable[[], str] | None = None,
    ) -> None:
        self._api_url = validate_zap_api_url(api_url)
        if not isinstance(api_key, str) or not api_key.strip() or api_key != api_key.strip():
            raise ValueError("zap api_key must be a non-empty string without surrounding spaces")
        validate_zap_options(
            max_depth=max_depth,
            max_children=max_children,
            spider_timeout=spider_timeout,
            passive_timeout=passive_timeout,
        )
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or poll_interval <= 0
        ):
            raise ValueError("zap poll_interval must be a positive number")
        self._api_key = SecretStr(api_key)
        self._client = client
        self._max_depth = max_depth
        self._max_children = max_children
        self._spider_timeout = spider_timeout
        self._passive_timeout = passive_timeout
        self._network_timeout = network_timeout
        self._poll_interval = float(poll_interval)
        self._clock = clock
        self._sleep = sleep
        self._context_name_factory = (
            context_name_factory
            if context_name_factory is not None
            else lambda: f"scan-{uuid.uuid4().hex}"
        )

    def __repr__(self) -> str:
        return f"ZapHttpProbe(api_url={self._api_url!r}, api_key='***')"

    def _get_json(self, client: httpx.Client, path: str, **params: str) -> dict[str, object]:
        if not path.startswith("/JSON/"):
            raise ZapProbeError("ZAP API path must start with /JSON/")
        secret = self._api_key.get_secret_value()
        try:
            response = client.get(
                f"{self._api_url}{path}",
                params={"apikey": secret, **params},
                headers={"X-ZAP-API-Key": secret},
                follow_redirects=False,
            )
        except httpx.HTTPError:
            # Ne jamais chaîner l'exception httpx brute dont le message peut contenir apikey.
            raise ZapProbeError(f"ZAP API request failed on {path}") from None
        if response.status_code != 200:
            raise ZapProbeError(f"ZAP API returned HTTP {response.status_code} on {path}")
        try:
            data = response.json()
        except ValueError:
            raise ZapProbeError(f"Invalid JSON from ZAP API on {path}") from None
        if not isinstance(data, dict):
            raise ZapProbeError(f"Unexpected JSON structure from ZAP API on {path}")
        return data

    def _scan_with_client(self, client: httpx.Client, target: Target) -> tuple[ZapAlert, ...]:
        parsed = urlsplit(target.url)
        if not parsed.hostname or parsed.scheme not in {"http", "https"}:
            raise ZapProbeError("Invalid target URL for ZAP probe")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        default_port = 443 if parsed.scheme == "https" else 80
        port_suffix = f":{parsed.port}" if parsed.port not in (None, default_port) else ""
        origin = f"{parsed.scheme.lower()}://{host}{port_suffix}"
        regex = f"^{re.escape(origin)}/.*"
        context_name = self._context_name_factory()

        created = self._get_json(
            client, "/JSON/context/action/newContext/", contextName=context_name
        )
        if not (
            (isinstance(created.get("contextId"), str) and created["contextId"].strip())
            or created.get("Result") == "OK"
        ):
            raise ZapProbeError("ZAP newContext did not return a contextId")

        error_occurred = False
        try:
            included = self._get_json(
                client,
                "/JSON/context/action/includeInContext/",
                contextName=context_name,
                regex=regex,
            )
            if included.get("Result") != "OK":
                raise ZapProbeError("ZAP includeInContext failed")

            depth_res = self._get_json(
                client,
                "/JSON/spider/action/setOptionMaxDepth/",
                Integer=str(self._max_depth),
            )
            if depth_res.get("Result") != "OK":
                raise ZapProbeError("ZAP setOptionMaxDepth failed")

            scan_res = self._get_json(
                client,
                "/JSON/spider/action/scan/",
                url=target.url,
                maxChildren=str(self._max_children),
                recurse="true",
                contextName=context_name,
                subtreeOnly="true",
            )
            scan_id = scan_res.get("scan")
            if not isinstance(scan_id, str) or not scan_id.strip():
                raise ZapProbeError("ZAP spider scan did not return a scan id")

            spider_started = self._clock()
            while True:
                status_res = self._get_json(
                    client,
                    "/JSON/spider/view/status/",
                    scanId=scan_id.strip(),
                )
                status = _parse_int(status_res.get("status"), "spider status")
                if not 0 <= status <= 100:
                    raise ZapProbeError("ZAP spider status out of range")
                if status == 100:
                    break
                if self._clock() - spider_started >= self._spider_timeout:
                    raise ZapProbeError("ZAP spider timeout exceeded")
                self._sleep(self._poll_interval)

            passive_started = self._clock()
            while True:
                pscan_res = self._get_json(
                    client,
                    "/JSON/pscan/view/recordsToScan/",
                )
                records = _parse_int(pscan_res.get("recordsToScan"), "recordsToScan")
                if records < 0:
                    raise ZapProbeError("ZAP recordsToScan cannot be negative")
                if records == 0:
                    break
                if self._clock() - passive_started >= self._passive_timeout:
                    raise ZapProbeError("ZAP passive scan timeout exceeded")
                self._sleep(self._poll_interval)

            alerts_res = self._get_json(
                client,
                "/JSON/alert/view/alerts/",
                baseurl=origin,
            )
            raw_alerts = alerts_res.get("alerts")
            if not isinstance(raw_alerts, list):
                raise ZapProbeError("ZAP alerts response must contain an alerts list")
            return tuple(_parse_alert(item) for item in raw_alerts)
        except BaseException:
            error_occurred = True
            raise
        finally:
            try:
                removed = self._get_json(
                    client,
                    "/JSON/context/action/removeContext/",
                    contextName=context_name,
                )
                if not error_occurred and removed.get("Result") != "OK":
                    raise ZapProbeError("ZAP removeContext failed")
            except ZapProbeError:
                if not error_occurred:
                    raise

    def scan(self, target: Target) -> tuple[ZapAlert, ...]:
        if self._client is not None:
            return self._scan_with_client(self._client, target)
        with create_zap_internal_client(self._api_url, timeout=self._network_timeout) as client:
            return self._scan_with_client(client, target)


def analyze_zap(alerts: Sequence[ZapAlert], rules: Sequence[ZapExcludedRule] = ()) -> list[Finding]:
    excluded_ids = {rule.plugin_id for rule in rules}
    grouped: dict[str, list[ZapAlert]] = {}
    for alert in alerts:
        plugin_id = alert.plugin_id.strip()
        if not plugin_id or not plugin_id.isascii() or not plugin_id.isdecimal():
            raise ZapProbeError(f"Invalid ZAP pluginId: {alert.plugin_id!r}")
        if alert.confidence.strip().casefold() == "false positive":
            continue
        if alert.risk not in _RISK_TO_SEVERITY:
            raise ZapProbeError(f"Unknown ZAP risk: {alert.risk!r}")
        if plugin_id in excluded_ids:
            continue
        grouped.setdefault(plugin_id, []).append(alert)

    findings = []
    for plugin_id, group in grouped.items():
        first = group[0]
        severity = _RISK_TO_SEVERITY[first.risk]
        urls = list(dict.fromkeys(a.url.strip() for a in group if a.url.strip()))
        pages_count = len(urls) if urls else len(group)
        examples = urls[:3]
        noun = "page touchée" if pages_count == 1 else "pages touchées"
        evidence = (
            f"{pages_count} {noun} : {', '.join(examples)}" if examples else f"{pages_count} {noun}"
        )
        if len(evidence) > 200:
            evidence = evidence[:197] + "..."
        title = first.name.strip() or f"Alerte ZAP {plugin_id}"
        description = first.description.strip() or title
        recommendation = (
            first.solution.strip() or "Consulter la documentation de la règle ZAP correspondante."
        )
        findings.append(
            Finding(
                id=f"zap.{plugin_id}",
                scanner="zap",
                category="Analyse passive (ZAP)",
                severity=severity,
                title=title,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
            )
        )
    return findings


class ZapPassiveScanner:
    name = "zap"
    category = "Analyse passive (ZAP)"

    def __init__(
        self,
        probe: ZapProbe,
        rules: Sequence[ZapExcludedRule] = (),
        *,
        allowed_hosts: Iterable[str] = (),
        extra_ports: Iterable[tuple[str, int]] = (),
        lock: ZapLock | None = None,
    ) -> None:
        self._probe = probe
        self._rules = tuple(rules)
        self._allowed_hosts = frozenset(allowed_hosts)
        self._extra_ports = frozenset(extra_ports)
        self._lock: ZapLock = lock if lock is not None else nullcontext()

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
                raise ValueError("Invalid ZAP target URL")
            host = url.hostname.encode("idna").decode("ascii")
        except ValueError as exc:
            raise SsrfBlockedError("Invalid ZAP target URL") from exc
        resolve_and_check(host, 443, allowed_hosts=self._allowed_hosts)
        with self._lock:
            alerts = self._probe.scan(target)
        return analyze_zap(alerts, self._rules)
