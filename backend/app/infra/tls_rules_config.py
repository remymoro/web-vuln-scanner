from pathlib import Path

import yaml

from app.domain.finding import Severity
from app.scanners.tls import TlsCheck, TlsRule


def load_tls_rules(path: Path) -> tuple[TlsRule, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read TLS rules YAML at {path}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise ValueError("TLS rules configuration must be a non-empty list")

    required = {"id", "check", "severity", "title", "description", "recommendation"}
    rules = []
    ids = set()
    checks = set()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each TLS rule must be a mapping")
        if item.keys() - (required | {"days"}):
            raise ValueError("Unknown TLS rule key")
        if required - item.keys():
            raise ValueError(f"Each TLS rule requires {', '.join(sorted(required))}")
        for key in required:
            if not isinstance(item[key], str) or not item[key].strip():
                raise ValueError(f"TLS rule {key} must be a non-empty string")
        if not item["id"].startswith("tls.") or item["id"] != item["id"].strip():
            raise ValueError("TLS rule id must start with tls. without surrounding spaces")
        try:
            check = TlsCheck(item["check"])
        except ValueError as exc:
            raise ValueError(f"Unknown TLS check: {item['check']!r}") from exc
        try:
            severity = Severity(item["severity"])
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {item['severity']!r}") from exc
        if item["id"] in ids or check in checks:
            raise ValueError(f"Duplicate TLS rule id or check: {item['id']!r}")
        ids.add(item["id"])
        checks.add(check)
        rules.append(TlsRule(**{**item, "check": check, "severity": severity}))
    return tuple(rules)
