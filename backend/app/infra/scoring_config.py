from pathlib import Path

import yaml

from app.domain.finding import Severity
from app.domain.scoring import Grade, ScoringPolicy


def load_scoring_policy(path: Path) -> ScoringPolicy:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read scoring YAML at {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Scoring configuration must be a mapping")
    if data.keys() - {"penalties", "thresholds"}:
        raise ValueError("Unknown scoring configuration key; expected penalties and thresholds")
    if "penalties" not in data or "thresholds" not in data:
        raise ValueError("Scoring configuration requires penalties and thresholds")
    if not isinstance(data["penalties"], dict):
        raise ValueError("penalties must be a mapping")
    if not isinstance(data["thresholds"], list):
        raise ValueError("thresholds must be a list")

    penalties = {}
    for key, points in data["penalties"].items():
        try:
            severity = Severity(key)
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {key!r}") from exc
        if type(points) is not int:
            raise ValueError(f"Penalty for {key!r} must be an integer")
        penalties[severity] = points

    thresholds = []
    for threshold in data["thresholds"]:
        if not isinstance(threshold, dict):
            raise ValueError("Each threshold must be a mapping")
        if threshold.keys() - {"grade", "min"}:
            raise ValueError("Unknown threshold key; expected grade and min")
        if "grade" not in threshold or "min" not in threshold:
            raise ValueError("Each threshold requires grade and min")
        try:
            grade = Grade(threshold["grade"])
        except ValueError as exc:
            raise ValueError(f"Unknown grade: {threshold['grade']!r}") from exc
        minimum = threshold["min"]
        if type(minimum) is not int:
            raise ValueError(f"Minimum for grade {grade} must be an integer")
        thresholds.append((grade, minimum))

    return ScoringPolicy(penalties, tuple(thresholds))
