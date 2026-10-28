from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import entry_points
from inspect import signature
from pathlib import Path
from types import MappingProxyType

import httpx

from app.domain.ports import Scanner
from app.infra.header_rules_config import load_header_rules
from app.infra.scanners_config import ScannerConfig
from app.scanners.headers import HeadersScanner
from app.scanners.registry import ScannerRegistry

ENTRY_POINT_GROUP = "web_vuln_scanner.scanners"


@dataclass(frozen=True)
class ScannerContext:
    client: httpx.Client
    config_dir: Path
    options: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", MappingProxyType(dict(self.options)))


def _headers(context: ScannerContext) -> Scanner:
    if context.options.keys() - {"rules"}:
        raise ValueError("Unknown headers option; expected rules")
    rules = context.options.get("rules", "header_rules.yaml")
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("headers rules must be a non-empty path")
    return HeadersScanner(context.client, load_header_rules(context.config_dir / rules))


BUILTIN_FACTORIES: dict[str, Callable[[ScannerContext], Scanner]] = {"headers": _headers}


def load_scanners(
    configs: Sequence[ScannerConfig], client: httpx.Client, config_dir: Path
) -> tuple[Scanner, ...]:
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
        scanner = factory(ScannerContext(client, config_dir, config.options))
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
