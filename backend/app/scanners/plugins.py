from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import entry_points
from inspect import signature
from pathlib import Path
from types import MappingProxyType

import httpx

from app.domain.ports import Scanner
from app.infra.header_rules_config import load_header_rules
from app.infra.ratelimit_rules_config import load_ratelimit_rules
from app.infra.scanners_config import ScannerConfig
from app.infra.tls_rules_config import load_tls_rules
from app.scanners.headers import HeadersScanner
from app.scanners.ratelimit import RateLimitScanner, validate_burst_options
from app.scanners.registry import ScannerRegistry
from app.scanners.tls import TlsScanner

ENTRY_POINT_GROUP = "web_vuln_scanner.scanners"


@dataclass(frozen=True)
class ScannerContext:
    client: httpx.Client
    config_dir: Path
    options: Mapping[str, object]
    allowed_hosts: frozenset[str] = frozenset()
    extra_ca_file: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", MappingProxyType(dict(self.options)))
        object.__setattr__(self, "allowed_hosts", frozenset(self.allowed_hosts))


def _headers(context: ScannerContext) -> Scanner:
    if context.options.keys() - {"rules"}:
        raise ValueError("Unknown headers option; expected rules")
    rules = context.options.get("rules", "header_rules.yaml")
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("headers rules must be a non-empty path")
    return HeadersScanner(context.client, load_header_rules(context.config_dir / rules))


def _tls(context: ScannerContext) -> Scanner:
    from app.scanners.sslyze_probe import SslyzeProbe

    if context.options.keys() - {"rules", "network_timeout", "network_max_retries"}:
        raise ValueError("Unknown tls option; expected rules, network_timeout, network_max_retries")
    rules = context.options.get("rules", "tls_rules.yaml")
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("tls rules must be a non-empty path")
    timeout = context.options.get("network_timeout", 3)
    retries = context.options.get("network_max_retries", 0)
    if type(timeout) is not int or not 1 <= timeout <= 10:
        raise ValueError("tls network_timeout must be an integer between 1 and 10 seconds")
    if type(retries) is not int or not 0 <= retries <= 2:
        raise ValueError("tls network_max_retries must be an integer between 0 and 2")
    return TlsScanner(
        SslyzeProbe(
            network_timeout=timeout,
            network_max_retries=retries,
            extra_ca_file=context.extra_ca_file,
        ),
        load_tls_rules(context.config_dir / rules),
        allowed_hosts=context.allowed_hosts,
    )


def _ratelimit(context: ScannerContext) -> Scanner:
    if context.options.keys() - {"rules", "max_requests", "max_duration"}:
        raise ValueError("Unknown ratelimit option; expected rules, max_requests, max_duration")
    rules = context.options.get("rules", "ratelimit_rules.yaml")
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("ratelimit rules must be a non-empty path")
    max_requests = context.options.get("max_requests", 30)
    max_duration = context.options.get("max_duration", 3)
    validate_burst_options(max_requests, max_duration)
    return RateLimitScanner(
        context.client,
        load_ratelimit_rules(context.config_dir / rules),
        max_requests=max_requests,
        max_duration=max_duration,
    )


BUILTIN_FACTORIES: dict[str, Callable[[ScannerContext], Scanner]] = {
    "headers": _headers,
    "tls": _tls,
    "ratelimit": _ratelimit,
}


def load_scanners(
    configs: Sequence[ScannerConfig],
    client: httpx.Client,
    config_dir: Path,
    *,
    allowed_hosts: Iterable[str] = (),
    extra_ca_file: Path | None = None,
) -> tuple[Scanner, ...]:
    allowed_hosts = frozenset(allowed_hosts)
    plugins = {}
    for entry_point in entry_points(group=ENTRY_POINT_GROUP):
        if entry_point.name in BUILTIN_FACTORIES or entry_point.name in plugins:
            raise ValueError(f"Scanner name conflict: {entry_point.name!r}")
        plugins[entry_point.name] = entry_point

    registry = ScannerRegistry()
    for config in configs:
        factory = BUILTIN_FACTORIES.get(config.name)
        if factory is None:
            entry_point = plugins.get(config.name)
            if entry_point is None:
                raise ValueError(f"Unknown scanner: {config.name!r}")
            try:
                factory = entry_point.load()
            except Exception as exc:
                raise ValueError(f"Cannot load scanner factory: {config.name!r}") from exc
        if not callable(factory):
            raise ValueError(f"Scanner factory must be callable: {config.name!r}")
        scanner = factory(
            ScannerContext(client, config_dir, config.options, allowed_hosts, extra_ca_file)
        )
        if (
            not isinstance(getattr(scanner, "name", None), str)
            or scanner.name != config.name
            or not isinstance(getattr(scanner, "category", None), str)
            or not scanner.category.strip()
            or not callable(getattr(scanner, "run", None))
        ):
            raise ValueError(f"Invalid Scanner contract (name, category, run): {config.name!r}")
        try:
            signature(scanner.run).bind(object())
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid Scanner run signature: {config.name!r}") from exc
        registry.register(scanner)
    return registry.all()
