"""Contrat de sonde WAF et analyse pure de la détection."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.domain.finding import Finding, Severity
from app.domain.target import Target


@dataclass(frozen=True)
class WafRule:
    id: str
    severity: Severity
    title: str
    description: str
    recommendation: str


@dataclass(frozen=True)
class WafReport:
    names: tuple[str, ...] = ()
    generic: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "names", tuple(self.names))


class WafProbeError(Exception):
    """La détection WAF n'a pas pu être évaluée complètement."""


class WafProbe(Protocol):
    def scan(self, target: Target) -> WafReport: ...


def analyze_waf(report: WafReport, rules: Sequence[WafRule]) -> list[Finding]:
    detected = bool(report.names) or report.generic
    rule_id = "waf.detected" if detected else "waf.absent"
    evidence = (
        "WAF détecté : " + ", ".join(report.names or ("non identifié",))
        if detected
        else "Aucun WAF détecté par les signatures ni la détection générique"
    )
    return [
        Finding(
            id=rule.id,
            scanner="waf",
            category="Pare-feu applicatif",
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            evidence=evidence[:997] + "..." if len(evidence) > 1000 else evidence,
            recommendation=rule.recommendation,
        )
        for rule in rules
        if rule.id == rule_id
    ]


class WafScanner:
    name = "waf"
    category = "Pare-feu applicatif"

    def __init__(self, probe: WafProbe, rules: Sequence[WafRule]) -> None:
        self._probe = probe
        self._rules = tuple(rules)

    def run(self, target: Target) -> list[Finding]:
        return analyze_waf(self._probe.scan(target), self._rules)
