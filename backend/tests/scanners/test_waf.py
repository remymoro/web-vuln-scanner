from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.domain.finding import Severity
from app.domain.scoring import DEFAULT_POLICY, score
from app.domain.target import Target
from app.infra.waf_rules_config import load_waf_rules
from app.scanners.waf import WafReport, WafScanner, analyze_waf

RULES = load_waf_rules(Path(__file__).resolve().parents[2] / "config/waf_rules.yaml")


@pytest.mark.parametrize(
    ("report", "rule_id", "evidence", "severity", "points"),
    [
        (WafReport(), "waf.absent", "Aucun WAF détecté", Severity.LOW, 3),
        (
            WafReport(("Cloudflare (Cloudflare Inc.)", "Autre")),
            "waf.detected",
            "WAF détecté : Cloudflare (Cloudflare Inc.), Autre",
            Severity.INFO,
            0,
        ),
        (WafReport(generic=True), "waf.detected", "WAF détecté : non identifié", Severity.INFO, 0),
    ],
)
def test_analysis_uses_rules_and_expected_penalty(report, rule_id, evidence, severity, points):
    (finding,) = analyze_waf(report, RULES)
    rule = next(rule for rule in RULES if rule.id == rule_id)
    assert finding.id == rule_id
    assert finding.severity is severity
    assert (finding.scanner, finding.category) == ("waf", "Pare-feu applicatif")
    assert finding.evidence.startswith(evidence)
    assert (finding.title, finding.description, finding.recommendation) == (
        rule.title,
        rule.description,
        rule.recommendation,
    )
    assert "chaînes de type attaque" in finding.description
    assert "alertes de sécurité" in finding.description
    assert score([finding], DEFAULT_POLICY).score == 100 - points


def test_absence_description_is_honest():
    (finding,) = analyze_waf(WafReport(), RULES)
    assert "son absence n'est pas une faille en soi" in finding.description
    assert "détection n'est jamais certaine" in finding.description


def test_evidence_is_bounded():
    (finding,) = analyze_waf(WafReport(("x" * 2000,)), RULES)
    assert len(finding.evidence) == 1000
    assert finding.evidence.endswith("...")


def test_report_and_rules_are_frozen_and_names_copied():
    names = ["Cloudflare"]
    report = WafReport(names)
    names.clear()
    assert report.names == ("Cloudflare",)
    with pytest.raises(FrozenInstanceError):
        report.generic = True
    with pytest.raises(FrozenInstanceError):
        RULES[0].title = "changed"


def test_scanner_calls_probe_with_target_and_analyzes_result():
    probe = Mock()
    probe.scan.return_value = WafReport(generic=True)
    target = Target("https://example.test/")
    scanner = WafScanner(probe, RULES)
    assert (scanner.name, scanner.category) == ("waf", "Pare-feu applicatif")
    assert scanner.run(target) == analyze_waf(probe.scan.return_value, RULES)
    probe.scan.assert_called_once_with(target)
