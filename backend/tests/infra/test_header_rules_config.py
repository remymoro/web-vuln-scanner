from pathlib import Path

import pytest

from app.domain.finding import Severity
from app.infra.header_rules_config import load_header_rules
from app.scanners.headers import CheckType

VALID_YAML = """
- id: headers.test
  header: X-Test
  check: equals
  severity: low
  title: En-tête incorrect
  description: Description
  recommendation: Correction
  value: nosniff
"""


def test_shipped_config():
    rules = load_header_rules(Path(__file__).resolve().parents[2] / "config/header_rules.yaml")
    assert isinstance(rules, tuple)
    assert len(rules) == len({rule.id for rule in rules}) == 6


def test_valid_file(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    (rule,) = load_header_rules(path)
    assert rule.check is CheckType.EQUALS
    assert rule.severity is Severity.LOW
    assert rule.value == "nosniff"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (VALID_YAML.replace("check: equals", "check: unknown"), "Unknown check"),
        (VALID_YAML.replace("severity: low", "severity: critical"), "Unknown severity"),
        (VALID_YAML + VALID_YAML, "Duplicate.*id"),
        (VALID_YAML.replace("  header: X-Test\n", ""), "requires"),
        (VALID_YAML + "  unexpected: true\n", "Unknown.*key"),
        ("{}", "list"),
        ("", "list"),
        ("- string", "mapping"),
        ("[", "YAML"),
        (VALID_YAML.replace("value: nosniff", "value: 10"), "value"),
        (VALID_YAML.replace("id: headers.test", "id: 10"), "string"),
        (VALID_YAML.replace("title: En-tête incorrect", "title: []"), "string"),
    ],
)
def test_invalid_file(tmp_path, content, message):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_header_rules(path)


def test_unreadable_file(tmp_path):
    with pytest.raises(ValueError, match="Cannot read.*YAML"):
        load_header_rules(tmp_path / "missing.yaml")
