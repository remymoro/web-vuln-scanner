from pathlib import Path

import pytest

from app.domain.finding import Severity
from app.domain.scoring import DEFAULT_POLICY, Grade
from app.infra.scoring_config import load_scoring_policy

VALID_YAML = """
penalties: {high: 25, medium: 10, low: 3, info: 0}
thresholds:
  - {grade: A, min: 90}
  - {grade: B, min: 75}
  - {grade: C, min: 60}
  - {grade: D, min: 40}
  - {grade: E, min: 0}
"""


def test_shipped_config_matches_default_policy():
    path = Path(__file__).resolve().parents[2] / "config" / "scoring.yaml"
    assert load_scoring_policy(path) == DEFAULT_POLICY


def test_valid_file(tmp_path):
    path = tmp_path / "scoring.yaml"
    path.write_text(VALID_YAML.replace("high: 25", "high: 30"), encoding="utf-8")
    policy = load_scoring_policy(path)
    assert policy.penalties[Severity.HIGH] == 30
    assert policy.grade_for(90) is Grade.A


@pytest.mark.parametrize(
    "content",
    [VALID_YAML + "unexpected: 1\n", VALID_YAML.replace("grade: A,", "grade: A, extra: 1,")],
)
def test_unknown_configuration_key(tmp_path, content):
    path = tmp_path / "scoring.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown.*key"):
        load_scoring_policy(path)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (VALID_YAML.replace("high:", "critical:"), "severity"),
        ("- not\n- a mapping", "mapping"),
        ("", "mapping"),
        ("penalties: [", "YAML"),
        ("penalties: {}", "thresholds"),
        (VALID_YAML.replace("grade: A", "grade: Z"), "grade"),
        (VALID_YAML.replace("min: 90", "min: nope"), "integer"),
        (VALID_YAML.replace("high: 25", "high: nope"), "integer"),
        (VALID_YAML.replace("high: 25", "high: -1"), "negative"),
        (VALID_YAML.replace("min: 0", "min: 1"), "last minimum"),
        ("penalties: []\nthresholds: []", "mapping"),
        ("penalties: {}\nthresholds: {}", "list"),
        ("penalties: {}\nthresholds: [A]", "mapping"),
        ("penalties: {}\nthresholds: [{grade: A}]", "min"),
    ],
)
def test_invalid_file(tmp_path, content, message):
    path = tmp_path / "scoring.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_scoring_policy(path)
