from dataclasses import FrozenInstanceError

import pytest

from app.domain.finding import Finding, Severity


def make_finding() -> Finding:
    return Finding(
        id="headers.hsts.missing",
        scanner="headers",
        category="en-têtes HTTP",
        severity=Severity.MEDIUM,
        title="En-tête HSTS absent",
        description="Le navigateur peut être forcé en HTTP",
        evidence="Aucun en-tête Strict-Transport-Security dans la réponse",
        recommendation="Ajouter HSTS avec un max-age d'au moins un an",
    )


def test_finding_creation():
    finding = make_finding()

    assert finding.id == "headers.hsts.missing"
    assert finding.scanner == "headers"
    assert finding.category == "en-têtes HTTP"
    assert finding.severity is Severity.MEDIUM
    assert finding.title == "En-tête HSTS absent"
    assert finding.description == "Le navigateur peut être forcé en HTTP"
    assert finding.evidence == "Aucun en-tête Strict-Transport-Security dans la réponse"
    assert finding.recommendation == "Ajouter HSTS avec un max-age d'au moins un an"


def test_finding_is_immutable():
    finding = make_finding()

    with pytest.raises(FrozenInstanceError):
        finding.title = "Autre titre"


def test_findings_are_equal_by_value_and_hashable():
    first = make_finding()
    second = make_finding()

    assert first is not second
    assert first == second
    assert len({first, second}) == 1


def test_severity_values():
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"


def test_severity_from_value():
    assert Severity("medium") is Severity.MEDIUM


def test_severity_rejects_unknown_value():
    with pytest.raises(ValueError):
        Severity("unknown")
