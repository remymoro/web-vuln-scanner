from pathlib import Path

import pytest

from app.domain.finding import Severity
from app.infra.tls_rules_config import load_tls_rules
from app.scanners.tls import TlsCheck

VALID_YAML = """
- id: tls.test
  check: certificate_expiring
  severity: medium
  title: Expiration prochaine
  description: Description
  recommendation: Correction
  days: 30
"""


def test_shipped_rules_cover_all_checks():
    rules = load_tls_rules(Path(__file__).resolve().parents[2] / "config/tls_rules.yaml")
    assert isinstance(rules, tuple)
    assert {rule.check for rule in rules} == set(TlsCheck)
    assert len(rules) == len({rule.id for rule in rules}) == 13


def test_valid_rule(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(VALID_YAML)
    (rule,) = load_tls_rules(path)
    assert rule.check is TlsCheck.CERTIFICATE_EXPIRING
    assert rule.severity is Severity.MEDIUM
    assert rule.days == 30


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[", "YAML"),
        ("", "non-empty list"),
        ("{}", "non-empty list"),
        ("[]", "non-empty list"),
        ("- string", "mapping"),
        (VALID_YAML.replace("  title: Expiration prochaine\n", ""), "requires"),
        (VALID_YAML + "  unexpected: true\n", "Unknown.*key"),
        (VALID_YAML.replace("id: tls.test", "id: headers.test"), "start with tls"),
        (VALID_YAML.replace("id: tls.test", "id: 5"), "string"),
        (VALID_YAML.replace("title: Expiration prochaine", "title: ''"), "string"),
        (VALID_YAML.replace("severity: medium", "severity: critical"), "Unknown severity"),
        (VALID_YAML.replace("check: certificate_expiring", "check: unknown"), "Unknown TLS check"),
        (VALID_YAML + VALID_YAML, "Duplicate"),
        (VALID_YAML + VALID_YAML.replace("id: tls.test", "id: tls.other"), "Duplicate"),
        (VALID_YAML.replace("days: 30", "days: true"), "days"),
        (VALID_YAML.replace("days: 30", "days: -1"), "days"),
        (VALID_YAML.replace("days: 30", "days: 0"), "days"),
        (VALID_YAML.replace("days: 30", "days: '30'"), "days"),
        (VALID_YAML.replace("  days: 30\n", ""), "days"),
        (VALID_YAML.replace("check: certificate_expiring", "check: heartbleed"), "days"),
    ],
)
def test_invalid_rules(tmp_path, content, message):
    path = tmp_path / "rules.yaml"
    path.write_text(content)
    with pytest.raises(ValueError, match=message):
        load_tls_rules(path)


def test_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Cannot read TLS rules YAML"):
        load_tls_rules(tmp_path / "missing.yaml")
