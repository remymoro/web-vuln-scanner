from pathlib import Path

import yaml

from app.domain.finding import Severity
from app.scanners.waf import WafRule


def load_waf_rules(path: Path) -> tuple[WafRule, ...]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read waf rules YAML at {path}: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise ValueError("waf rules configuration must be a non-empty list")

    required = {"id", "severity", "title", "description", "recommendation"}
    severities = {"waf.detected": Severity.INFO, "waf.absent": Severity.LOW}
    rules = []
    ids = set()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each waf rule must be a mapping")
        if item.keys() - required:
            raise ValueError("Unknown waf rule key")
        if required - item.keys():
            raise ValueError(f"Each waf rule requires {', '.join(sorted(required))}")
        for key in required:
            if not isinstance(item[key], str) or not item[key].strip():
                raise ValueError(f"waf rule {key} must be a non-empty string")
        if item["id"] not in severities:
            raise ValueError("Unknown waf rule id; expected waf.detected or waf.absent")
        if item["severity"] != severities[item["id"]]:
            raise ValueError("waf severity must be info for detected and low for absent")
        if item["id"] in ids:
            raise ValueError(f"Duplicate waf rule id: {item['id']!r}")
        ids.add(item["id"])
        rules.append(WafRule(**{**item, "severity": Severity(item["severity"])}))
    if ids != severities.keys():
        raise ValueError("waf rules require both waf.detected and waf.absent")
    return tuple(rules)
