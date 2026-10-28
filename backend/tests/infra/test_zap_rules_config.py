from pathlib import Path

import pytest

from app.infra.zap_rules_config import load_zap_rules

VALID_YAML = """
- plugin_id: "10010"
  name: Cookie No HttpOnly Flag
  covered_by: headers.cookie.httponly
- plugin_id: "10035"
  name: Strict-Transport-Security Header Not Set
  covered_by: headers.hsts
"""


def test_shipped_rules():
    rules = load_zap_rules(Path(__file__).resolve().parents[2] / "config/zap_rules.yaml")
    assert isinstance(rules, tuple)
    assert [(rule.plugin_id, rule.covered_by) for rule in rules] == [
        ("10010", "headers.cookie.httponly"),
        ("10011", "headers.cookie.secure"),
        ("10021", "headers.x_content_type_options"),
        ("10035", "headers.hsts"),
        ("10038", "headers.csp"),
        ("10054", "headers.cookie.samesite"),
        ("10055", "headers.csp"),
        ("10063", "headers.permissions_policy"),
    ]


def test_valid_rules(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(VALID_YAML, encoding="utf-8")
    first, second = load_zap_rules(path)
    assert first.plugin_id == "10010"
    assert first.name == "Cookie No HttpOnly Flag"
    assert second.covered_by == "headers.hsts"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[", "YAML"),
        ("", "non-empty list"),
        ("{}", "non-empty list"),
        ("[]", "non-empty list"),
        ("- string", "mapping"),
        (VALID_YAML.replace("  covered_by: headers.hsts\n", ""), "requires"),
        (VALID_YAML + "  unknown: true\n", "Unknown.*key"),
        (VALID_YAML.replace('"10010"', "10010"), "string"),
        (VALID_YAML.replace('"10010"', '""'), "non-empty string"),
        (VALID_YAML.replace('"10010"', '" 10010"'), "ASCII digits"),
        (VALID_YAML.replace('"10010"', '"10010a"'), "ASCII digits"),
        (VALID_YAML.replace("Cookie No HttpOnly Flag", " "), "non-empty string"),
        (VALID_YAML.replace("headers.hsts", "tls.hsts"), "start with headers\\."),
        (VALID_YAML.replace("headers.hsts", '"headers.hsts "'), "start with headers\\."),
        (VALID_YAML + VALID_YAML, "Duplicate"),
    ],
)
def test_invalid_rules(tmp_path, content, message):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_zap_rules(path)


def test_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Cannot read zap rules YAML"):
        load_zap_rules(tmp_path / "missing.yaml")
