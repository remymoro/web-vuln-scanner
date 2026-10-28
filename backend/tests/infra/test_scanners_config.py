from pathlib import Path

import pytest

from app.infra.scanners_config import load_scanners_config


def test_shipped_config():
    configs = load_scanners_config(Path(__file__).resolve().parents[2] / "config/scanners.yaml")
    assert [(config.name, dict(config.options)) for config in configs] == [
        ("headers", {"rules": "header_rules.yaml"}),
        ("tls", {"rules": "tls_rules.yaml", "network_timeout": 3, "network_max_retries": 0}),
        ("ratelimit", {"max_requests": 30, "max_duration": 3, "rules": "ratelimit_rules.yaml"}),
        ("waf", {"network_timeout": 3, "rules": "waf_rules.yaml"}),
        (
            "zap",
            {
                "api_url": "http://zap:8080",
                "api_key_env": "ZAP_API_KEY",
                "max_depth": 3,
                "max_children": 50,
                "spider_timeout": 60,
                "passive_timeout": 60,
                "rules": "zap_rules.yaml",
            },
        ),
    ]


def test_order_and_default_options(tmp_path):
    path = tmp_path / "scanners.yaml"
    path.write_text("scanners: [{name: second}, {name: first, options: {limit: 5}}]")
    configs = load_scanners_config(path)
    assert [config.name for config in configs] == ["second", "first"]
    assert configs[0].options == {}
    assert configs[1].options == {"limit": 5}


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "scanners key"),
        ("[]", "scanners key"),
        ("scanners: []\nextra: true", "scanners key"),
        ("scanners: []", "non-empty list"),
        ("scanners: {}", "non-empty list"),
        ("scanners: [headers]", "mapping"),
        ("scanners: [{name: headers, extra: true}]", "Unknown.*key"),
        ("scanners: [{}]", "name"),
        ("scanners: [{name: 5}]", "name"),
        ("scanners: [{name: ''}]", "name"),
        ("scanners: [{name: ' headers'}]", "name"),
        ("scanners: [{name: headers}, {name: headers}]", "Duplicate"),
        ("scanners: [{name: headers, options: []}]", "options"),
        ("scanners: [{name: headers, options: {5: true}}]", "options"),
        ("[", "YAML"),
    ],
)
def test_invalid_configuration(tmp_path, content, message):
    path = tmp_path / "scanners.yaml"
    path.write_text(content)
    with pytest.raises(ValueError, match=message):
        load_scanners_config(path)


def test_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Cannot read scanners YAML"):
        load_scanners_config(tmp_path / "missing.yaml")
