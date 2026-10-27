from pathlib import Path

import yaml

from app.domain.finding import Severity
from app.scanners.headers import CheckType, HeaderRule


def load_header_rules(path: Path) -> tuple[HeaderRule, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read header rules YAML at {path}: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError("Header rules configuration must be a list")

    required = {"id", "header", "check", "severity", "title", "description", "recommendation"}
    rules = []
    ids = set()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each header rule must be a mapping")
        if item.keys() - (required | {"value"}):
            raise ValueError("Unknown header rule key")
        if required - item.keys():
            raise ValueError(f"Each header rule requires {', '.join(sorted(required))}")
        for key in required - {"check", "severity"}:
            if not isinstance(item[key], str):
                raise ValueError(f"Header rule {key} must be a string")
        try:
            check = CheckType(item["check"])
        except ValueError as exc:
            raise ValueError(f"Unknown check: {item['check']!r}") from exc
        try:
            severity = Severity(item["severity"])
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {item['severity']!r}") from exc
        if item["id"] in ids:
            raise ValueError(f"Duplicate header rule id: {item['id']!r}")
        ids.add(item["id"])
        rules.append(HeaderRule(**{**item, "check": check, "severity": severity}))
    return tuple(rules)
