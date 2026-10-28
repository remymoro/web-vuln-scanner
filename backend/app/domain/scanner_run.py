from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True)
class ScannerRun:
    scanner: str
    category: str
    status: Literal["ok", "error"]
    error: str | None
    findings_count: int
    started_at: datetime
    finished_at: datetime

    def __post_init__(self) -> None:
        if self.status not in ("ok", "error"):
            raise ValueError("scanner status must be ok or error")
        if self.findings_count < 0:
            raise ValueError("findings_count must not be negative")
        if (self.status == "ok") != (self.error is None):
            raise ValueError("only failed scanners must have an error")
        if any(at.utcoffset() is None for at in (self.started_at, self.finished_at)):
            raise ValueError("scanner dates must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("scanner finished_at must not precede started_at")


def is_partial(runs: Iterable[ScannerRun]) -> bool:
    return {run.status for run in runs} == {"ok", "error"}
