from pathlib import Path

import yaml

from app.domain.finding import Severity
from app.scanners.ratelimit import RateLimitRule


def load_ratelimit_rules(path: Path) -> tuple[RateLimitRule, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read ratelimit rules YAML at {path}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise ValueError("ratelimit rules configuration must be a non-empty list")

    required = {"id", "severity", "title", "description", "recommendation"}
    rules = []
    ids = set()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each ratelimit rule must be a mapping")
        if item.keys() - required:
            raise ValueError("Unknown ratelimit rule key")
        if required - item.keys():
            raise ValueError(f"Each ratelimit rule requires {', '.join(sorted(required))}")
        for key in required:
            if not isinstance(item[key], str) or not item[key].strip():
                raise ValueError(f"ratelimit rule {key} must be a non-empty string")
        if item["id"] != "ratelimit.absent":
            raise ValueError("Unknown ratelimit rule id; expected ratelimit.absent")
        try:
            severity = Severity(item["severity"])
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {item['severity']!r}") from exc
        if item["id"] in ids:
            raise ValueError(f"Duplicate ratelimit rule id: {item['id']!r}")
        ids.add(item["id"])
        rules.append(RateLimitRule(**{**item, "severity": severity}))
    return tuple(rules)
