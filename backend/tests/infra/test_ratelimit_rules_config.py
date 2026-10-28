from pathlib import Path

import pytest

from app.domain.finding import Severity
from app.infra.ratelimit_rules_config import load_ratelimit_rules

VALID_YAML = """
- id: ratelimit.absent
  severity: low
  title: Aucune limitation de débit détectée
  description: Description
  recommendation: Correction
"""


def test_shipped_rules():
    rules = load_ratelimit_rules(
        Path(__file__).resolve().parents[2] / "config/ratelimit_rules.yaml"
    )
    assert isinstance(rules, tuple)
    (rule,) = rules
    assert rule.id == "ratelimit.absent"
    assert rule.severity is Severity.LOW


def test_valid_rule(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    (rule,) = load_ratelimit_rules(path)
    assert rule.id == "ratelimit.absent"
    assert rule.severity is Severity.LOW
    assert rule.recommendation == "Correction"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[", "YAML"),
        ("", "non-empty list"),
        ("{}", "non-empty list"),
        ("[]", "non-empty list"),
        ("- string", "mapping"),
        (VALID_YAML.replace("  recommendation: Correction\n", ""), "requires"),
        (VALID_YAML + "  unknown: true\n", "Unknown.*key"),
        (VALID_YAML.replace("ratelimit.absent", "ratelimit.other"), "Unknown.*id"),
        (VALID_YAML.replace("ratelimit.absent", "headers.test"), "Unknown.*id"),
        (VALID_YAML.replace("ratelimit.absent", "5"), "string"),
        (VALID_YAML.replace("severity: low", "severity: critical"), "Unknown severity"),
        (VALID_YAML.replace("severity: low", "severity: true"), "string"),
        (VALID_YAML.replace("description: Description", "description: []"), "string"),
        (VALID_YAML.replace("recommendation: Correction", "recommendation: ' '"), "string"),
        (VALID_YAML + VALID_YAML, "Duplicate"),
    ],
)
def test_invalid_rules(tmp_path, content, message):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_ratelimit_rules(path)


def test_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Cannot read ratelimit rules YAML"):
        load_ratelimit_rules(tmp_path / "missing.yaml")
