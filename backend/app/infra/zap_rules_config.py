from pathlib import Path

import yaml

from app.scanners.zap import ZapExcludedRule


def load_zap_rules(path: Path) -> tuple[ZapExcludedRule, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read zap rules YAML at {path}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise ValueError("zap rules configuration must be a non-empty list")

    required = {"plugin_id", "name", "covered_by"}
    rules = []
    plugin_ids = set()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each zap rule must be a mapping")
        if item.keys() - required:
            raise ValueError("Unknown zap rule key")
        if required - item.keys():
            raise ValueError(f"Each zap rule requires {', '.join(sorted(required))}")
        for key in required:
            if not isinstance(item[key], str) or not item[key].strip():
                raise ValueError(f"zap rule {key} must be a non-empty string")
        plugin_id = item["plugin_id"]
        if plugin_id != plugin_id.strip() or not plugin_id.isascii() or not plugin_id.isdecimal():
            raise ValueError("zap rule plugin_id must be ASCII digits without surrounding spaces")
        covered_by = item["covered_by"]
        if not covered_by.startswith("headers.") or covered_by != covered_by.strip():
            raise ValueError("zap rule covered_by must start with headers.")
        if plugin_id in plugin_ids:
            raise ValueError(f"Duplicate zap rule plugin_id: {plugin_id!r}")
        plugin_ids.add(plugin_id)
        rules.append(ZapExcludedRule(**item))
    return tuple(rules)
