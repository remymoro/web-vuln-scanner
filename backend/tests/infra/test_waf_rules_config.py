from pathlib import Path

import pytest

from app.domain.finding import Severity
from app.infra.waf_rules_config import load_waf_rules

VALID_YAML = """
- id: waf.detected
  severity: info
  title: Détecté
  description: Description
  recommendation: Correction
- id: waf.absent
  severity: low
  title: Absent
  description: Description
  recommendation: Correction
"""


def test_shipped_rules():
    rules = load_waf_rules(Path(__file__).resolve().parents[2] / "config/waf_rules.yaml")
    assert isinstance(rules, tuple)
    assert [(rule.id, rule.severity) for rule in rules] == [
        ("waf.detected", Severity.INFO),
        ("waf.absent", Severity.LOW),
    ]


def test_valid_rules(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    detected, absent = load_waf_rules(path)
    assert detected.title == "Détecté"
    assert absent.title == "Absent"


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
        (VALID_YAML.replace("waf.absent", "waf.other"), "Unknown.*id"),
        (VALID_YAML.replace("waf.absent", "headers.test"), "Unknown.*id"),
        (VALID_YAML.replace("waf.absent", "5"), "string"),
        (VALID_YAML.replace("severity: low", "severity: critical"), "severity"),
        (VALID_YAML.replace("severity: low", "severity: info"), "severity"),
        (VALID_YAML.replace("severity: info", "severity: low"), "severity"),
        (VALID_YAML.replace("severity: low", "severity: true"), "string"),
        (VALID_YAML.replace("description: Description", "description: []"), "string"),
        (VALID_YAML.replace("recommendation: Correction", "recommendation: ' '"), "string"),
        (VALID_YAML + VALID_YAML, "Duplicate"),
        (VALID_YAML.split("- id: waf.absent")[0], "require both"),
    ],
)
def test_invalid_rules(tmp_path, content, message):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_waf_rules(path)


def test_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Cannot read waf rules YAML"):
        load_waf_rules(tmp_path / "missing.yaml")
