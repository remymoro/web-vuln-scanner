from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import yaml


@dataclass(frozen=True)
class ScannerConfig:
    name: str
    options: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", MappingProxyType(dict(self.options)))


def load_scanners_config(path: Path) -> tuple[ScannerConfig, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read scanners YAML at {path}: {exc}") from exc
    if not isinstance(data, dict) or data.keys() != {"scanners"}:
        raise ValueError("Scanners configuration requires only the scanners key")
    items = data["scanners"]
    if not isinstance(items, list) or not items:
        raise ValueError("scanners must be a non-empty list")
    configs = []
    names = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each scanner must be a mapping")
        if item.keys() - {"name", "options"}:
            raise ValueError("Unknown scanner configuration key")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise ValueError("Scanner name must be a non-empty string without surrounding spaces")
        if name in names:
            raise ValueError(f"Duplicate scanner name: {name!r}")
        options = item.get("options", {})
        if not isinstance(options, dict) or any(not isinstance(key, str) for key in options):
            raise ValueError(f"Scanner options must be a mapping with string keys: {name!r}")
        names.add(name)
        configs.append(ScannerConfig(name, options))
    return tuple(configs)
