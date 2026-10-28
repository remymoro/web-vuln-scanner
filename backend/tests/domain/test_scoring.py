from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from app.domain.finding import Finding, Severity
from app.domain.scanner_run import ScannerRun, is_partial
from app.domain.scoring import DEFAULT_POLICY, Deduction, Grade, ScoringPolicy, score


def make_finding(
    finding_id: str = "headers.hsts.missing",
    category: str = "headers",
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        id=finding_id,
        scanner="test",
        category=category,
        severity=severity,
        title="Test finding",
        description="Description",
        evidence="Evidence",
        recommendation="Recommendation",
    )


@pytest.mark.parametrize("value", range(101))
def test_every_score_has_a_grade(value):
    assert isinstance(DEFAULT_POLICY.grade_for(value), Grade)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (100, Grade.A),
        (90, Grade.A),
        (89, Grade.B),
        (75, Grade.B),
        (74, Grade.C),
        (60, Grade.C),
        (59, Grade.D),
        (40, Grade.D),
        (39, Grade.E),
        (0, Grade.E),
    ],
)
def test_grade_boundaries(value, expected):
    assert DEFAULT_POLICY.grade_for(value) is expected


def test_no_findings():
    report = score([], DEFAULT_POLICY)
    assert (report.score, report.grade) == (100, Grade.A)
    assert report.categories == ()
    assert report.deductions == ()


def test_clean_evaluated_category_has_a_score():
    now = datetime.now(UTC)
    report = score([], DEFAULT_POLICY, [ScannerRun("test", "headers", "ok", None, 0, now, now)])
    assert (report.score, report.grade) == (100, Grade.A)
    assert [(item.category, item.score, item.grade) for item in report.categories] == [
        ("headers", 100, Grade.A)
    ]


def test_failed_scanner_has_no_penalty_and_is_not_evaluated():
    now = datetime.now(UTC)
    runs = [
        ScannerRun("test", "headers", "ok", None, 1, now, now),
        ScannerRun("tls", "tls", "error", "ValueError", 0, now, now),
    ]
    report = score([make_finding()], DEFAULT_POLICY, runs)
    assert (report.score, report.grade) == (90, Grade.A)
    assert is_partial(runs)
    assert [(item.category, item.score, item.grade) for item in report.categories] == [
        ("headers", 90, Grade.A),
        ("tls", None, None),
    ]
    assert report.categories[1].deductions == ()


def test_findings_from_failed_scanner_do_not_affect_scoring():
    now = datetime.now(UTC)
    runs = [ScannerRun("test", "headers", "error", "ValueError", 0, now, now)]
    report = score([make_finding()], DEFAULT_POLICY, runs)
    assert report.score == 100
    assert report.deductions == ()
    assert report.categories[0].score is None


def test_shared_category_is_evaluated_when_one_scanner_succeeds():
    now = datetime.now(UTC)
    runs = [
        ScannerRun("test", "headers", "ok", None, 0, now, now),
        ScannerRun("other", "headers", "error", "ValueError", 0, now, now),
    ]
    report = score([], DEFAULT_POLICY, runs)
    assert [(item.category, item.score, item.grade) for item in report.categories] == [
        ("headers", 100, Grade.A)
    ]
    assert is_partial(runs)


def test_one_medium_finding():
    report = score([make_finding()], DEFAULT_POLICY)
    assert (report.score, report.grade) == (90, Grade.A)
    assert (report.categories[0].score, report.categories[0].grade) == (90, Grade.A)


def test_scores_have_a_floor_of_zero_without_losing_deductions():
    report = score((make_finding(str(i), severity=Severity.HIGH) for i in range(5)), DEFAULT_POLICY)
    assert (report.score, report.grade) == (0, Grade.E)
    assert report.categories[0].score == 0
    assert sum(item.points for item in report.deductions) == 125


def test_categories_are_sorted_and_global_score_uses_every_penalty():
    findings = [
        make_finding("tls.high", "tls", Severity.HIGH),
        make_finding("headers.medium", "headers"),
        make_finding("tls.low", "tls", Severity.LOW),
        make_finding("headers.info", "headers", Severity.INFO),
    ]
    report = score(iter(findings), DEFAULT_POLICY)
    assert (report.score, report.grade) == (62, Grade.C)
    assert [(item.category, item.score, item.grade) for item in report.categories] == [
        ("headers", 90, Grade.A),
        ("tls", 72, Grade.C),
    ]
    expected = tuple(
        Deduction(f.id, f.category, f.severity, DEFAULT_POLICY.penalties[f.severity])
        for f in findings
    )
    assert report.deductions == expected
    assert report.categories[0].deductions == (expected[1], expected[3])
    assert report.categories[1].deductions == (expected[0], expected[2])
    with pytest.raises(FrozenInstanceError):
        report.score = 100


def test_custom_policy_is_used():
    policy = ScoringPolicy({severity: 20 for severity in Severity}, DEFAULT_POLICY.thresholds)
    report = score([make_finding()], policy)
    assert (report.score, report.grade) == (80, Grade.B)
    assert report.deductions[0].points == 20


@pytest.mark.parametrize(
    ("penalties", "message"),
    [
        ({Severity.HIGH: 25}, "severity"),
        ({**DEFAULT_POLICY.penalties, Severity.LOW: -1}, "negative"),
    ],
)
def test_invalid_penalties(penalties, message):
    with pytest.raises(ValueError, match=message):
        ScoringPolicy(penalties, DEFAULT_POLICY.thresholds)


@pytest.mark.parametrize(
    ("thresholds", "message"),
    [
        (((Grade.A, 90),) * 5, "exactly once"),
        (DEFAULT_POLICY.thresholds[:-1], "exactly once"),
        (((Grade.A, 75), (Grade.B, 90), *DEFAULT_POLICY.thresholds[2:]), "decreasing"),
        (((Grade.A, 90), (Grade.B, 90), *DEFAULT_POLICY.thresholds[2:]), "decreasing"),
        ((*DEFAULT_POLICY.thresholds[:-1], (Grade.E, 1)), "last minimum"),
        (((Grade.A, 101), *DEFAULT_POLICY.thresholds[1:]), "0.*100"),
        ((*DEFAULT_POLICY.thresholds[:-1], (Grade.E, -1)), "0.*100"),
    ],
)
def test_invalid_thresholds(thresholds, message):
    with pytest.raises(ValueError, match=message):
        ScoringPolicy(DEFAULT_POLICY.penalties, thresholds)


def test_policy_is_immutable_and_hashable():
    penalties = dict(DEFAULT_POLICY.penalties)
    policy = ScoringPolicy(penalties, DEFAULT_POLICY.thresholds)
    penalties[Severity.HIGH] = 99
    assert policy.penalties[Severity.HIGH] == 25
    with pytest.raises(TypeError):
        policy.penalties[Severity.HIGH] = 99
    with pytest.raises(FrozenInstanceError):
        policy.thresholds = ()
    assert policy == DEFAULT_POLICY
    assert len({policy, DEFAULT_POLICY}) == 1
