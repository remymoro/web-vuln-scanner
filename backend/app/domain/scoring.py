from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from types import MappingProxyType

from app.domain.finding import Finding, Severity
from app.domain.scanner_run import ScannerRun


class Grade(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"


@dataclass(frozen=True)
class ScoringPolicy:
    penalties: Mapping[Severity, int]
    thresholds: tuple[tuple[Grade, int], ...]

    def __post_init__(self) -> None:
        penalties = dict(self.penalties)
        thresholds = tuple((grade, minimum) for grade, minimum in self.thresholds)
        if set(penalties) != set(Severity):
            raise ValueError("penalties must contain every severity and no unknown severity")
        if any(type(points) is not int for points in penalties.values()):
            raise ValueError("penalties must be integers")
        if any(points < 0 for points in penalties.values()):
            raise ValueError("penalties must not be negative")
        grades = [grade for grade, _ in thresholds]
        if len(grades) != len(Grade) or set(grades) != set(Grade):
            raise ValueError("thresholds must contain each grade exactly once")
        minima = [minimum for _, minimum in thresholds]
        if any(type(minimum) is not int or not 0 <= minimum <= 100 for minimum in minima):
            raise ValueError("threshold minima must be integers between 0 and 100")
        if any(first <= second for first, second in pairwise(minima)):
            raise ValueError("threshold minima must be strictly decreasing")
        if minima[-1] != 0:
            raise ValueError("the last minimum must be 0")
        object.__setattr__(self, "penalties", MappingProxyType(penalties))
        object.__setattr__(self, "thresholds", thresholds)

    def __hash__(self) -> int:
        # MappingProxyType is immutable but unhashable on Python 3.12.
        return hash((frozenset(self.penalties.items()), self.thresholds))

    def grade_for(self, score: int) -> Grade:
        if not 0 <= score <= 100:
            raise ValueError("score must be between 0 and 100")
        return next(grade for grade, minimum in self.thresholds if minimum <= score)


DEFAULT_POLICY = ScoringPolicy(
    penalties={Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 3, Severity.INFO: 0},
    thresholds=((Grade.A, 90), (Grade.B, 75), (Grade.C, 60), (Grade.D, 40), (Grade.E, 0)),
)


@dataclass(frozen=True)
class Deduction:
    finding_id: str
    category: str
    severity: Severity
    points: int


@dataclass(frozen=True)
class CategoryScore:
    category: str
    score: int | None
    grade: Grade | None
    deductions: tuple[Deduction, ...]


@dataclass(frozen=True)
class ScoreReport:
    score: int
    grade: Grade
    categories: tuple[CategoryScore, ...]
    deductions: tuple[Deduction, ...]


def score(
    findings: Iterable[Finding],
    policy: ScoringPolicy,
    scanner_runs: Iterable[ScannerRun] | None = None,
) -> ScoreReport:
    runs = None if scanner_runs is None else tuple(scanner_runs)
    evaluated = None if runs is None else {run.scanner for run in runs if run.status == "ok"}
    deductions = tuple(
        Deduction(
            finding.id, finding.category, finding.severity, policy.penalties[finding.severity]
        )
        for finding in findings
        if evaluated is None or finding.scanner in evaluated
    )
    by_category: dict[str, list[Deduction]] = {}
    evaluated_categories = (
        set() if runs is None else {run.category for run in runs if run.status == "ok"}
    )
    if runs is not None:
        for run in runs:
            by_category.setdefault(run.category, [])
    for deduction in deductions:
        by_category.setdefault(deduction.category, []).append(deduction)

    categories = []
    for category, items in sorted(by_category.items()):
        if runs is not None and category not in evaluated_categories:
            categories.append(CategoryScore(category, None, None, ()))
            continue
        category_score = max(0, 100 - sum(item.points for item in items))
        categories.append(
            CategoryScore(category, category_score, policy.grade_for(category_score), tuple(items))
        )

    total = max(0, 100 - sum(item.points for item in deductions))
    return ScoreReport(total, policy.grade_for(total), tuple(categories), deductions)
