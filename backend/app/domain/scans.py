"""Cycle de vie des scans et orchestration indépendante des outils."""

from __future__ import annotations

import math
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from app.domain.finding import Finding
from app.domain.scanner_run import ScannerRun
from app.domain.scoring import Grade, ScoreReport, ScoringPolicy, score
from app.domain.targets import TargetNotFoundError, TargetNotVerifiedError

if TYPE_CHECKING:
    from app.domain.ports import Scanner, ScanRepository, TargetRepository


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class ScanNotFoundError(Exception):
    """Le scan demandé est absent."""


class ScanAlreadyActiveError(Exception):
    """Un scan est déjà actif sur cette cible."""


class InvalidScanTransitionError(Exception):
    """La transition demandée est interdite."""


class QueueUnavailableError(Exception):
    """La file de scans est injoignable."""


class ScanTooSoonError(Exception):
    """Un scan récent de la même cible impose d'attendre."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(f"Retry after {retry_after_seconds} seconds")
        self.retry_after_seconds = retry_after_seconds


# Échecs dus à notre infrastructure : ils ne déclenchent pas le délai entre deux scans.
INFRASTRUCTURE_FAILURES = frozenset({"queue unavailable", "abandoned", "worker error"})


@dataclass(frozen=True)
class Scan:
    id: uuid.UUID
    target_id: uuid.UUID
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    score: int | None = None
    grade: Grade | None = None
    error: str | None = None
    attempts: int = 0

    def __post_init__(self) -> None:
        for at in (self.created_at, self.started_at, self.finished_at):
            if at is not None and at.utcoffset() is None:
                raise ValueError("scan dates must be timezone-aware")

    @classmethod
    def create(cls, target_id: uuid.UUID) -> Scan:
        return cls(uuid.uuid4(), target_id, ScanStatus.PENDING, datetime.now(UTC))

    def start(self, at: datetime) -> Scan:
        if self.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
            raise InvalidScanTransitionError
        return replace(self, status=ScanStatus.RUNNING, started_at=at, attempts=self.attempts + 1)

    def complete(self, report: ScoreReport, at: datetime) -> Scan:
        if self.status != ScanStatus.RUNNING:
            raise InvalidScanTransitionError
        return replace(
            self, status=ScanStatus.DONE, finished_at=at, score=report.score, grade=report.grade
        )

    def fail(self, reason: str, at: datetime) -> Scan:
        if self.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
            raise InvalidScanTransitionError
        return replace(self, status=ScanStatus.FAILED, finished_at=at, error=reason)


def request_scan(
    targets: TargetRepository,
    scans: ScanRepository,
    user_id: uuid.UUID,
    target_id: uuid.UUID,
    now: datetime,
    timeout: int,
    *,
    pending_timeout: int,
    cooldown: int,
) -> Scan:
    target = targets.get(target_id)
    if target is None or target.user_id != user_id:
        raise TargetNotFoundError
    target.scan_target()
    active = scans.get_active_for_target(target_id)
    if active is not None:
        if _is_abandoned(active, now, timeout, pending_timeout):
            scans.save(active.fail("abandoned", now))
        else:
            raise ScanAlreadyActiveError
    cooldown_delta = timedelta(seconds=cooldown)
    recent = [
        scan
        for scan in scans.list_for_target_since(target_id, now - cooldown_delta)
        if scan.error not in INFRASTRUCTURE_FAILURES and now - scan.created_at < cooldown_delta
    ]
    if recent:
        last = max(scan.created_at for scan in recent)
        wait = cooldown - (now - last).total_seconds()
        raise ScanTooSoonError(max(1, math.ceil(wait)))
    scan = replace(Scan.create(target_id), created_at=now)
    scans.add(scan)
    return scan


def _is_abandoned(scan: Scan, now: datetime, timeout: int, pending_timeout: int) -> bool:
    if scan.status == ScanStatus.RUNNING and scan.started_at is not None:
        return now - scan.started_at > timedelta(seconds=timeout + 60)
    # Un pending sans job (crash entre commit et mise en file, job perdu) bloquerait la cible.
    return scan.status == ScanStatus.PENDING and now - scan.created_at > timedelta(
        seconds=pending_timeout
    )


def execute_scan(
    scans: ScanRepository,
    targets: TargetRepository,
    scanners: Iterable[Scanner],
    policy: ScoringPolicy,
    scan_id: uuid.UUID,
    clock: Callable[[], datetime],
    commit: Callable[[], None],
) -> Scan:
    scan = scans.get(scan_id)
    if scan is None:
        raise ScanNotFoundError
    if scan.status in (ScanStatus.DONE, ScanStatus.FAILED):
        return scan
    scan = scan.start(clock())
    scans.save(scan)
    scans.replace_findings(scan.id, [])
    scans.replace_scanner_runs(scan.id, [])
    commit()
    target = targets.get(scan.target_id)
    if target is None:
        scan = scan.fail("target not found", clock())
    else:
        try:
            scan_target = target.scan_target()
        except TargetNotVerifiedError:
            scan = scan.fail("target not verified", clock())
        else:
            findings = []
            runs = []
            for scanner in scanners:
                started_at = clock()
                try:
                    scanner_findings = list(scanner.run(scan_target))
                    if any(not isinstance(finding, Finding) for finding in scanner_findings):
                        raise TypeError("scanner must return findings")
                except Exception as exc:
                    run = ScannerRun(
                        scanner.name,
                        scanner.category,
                        "error",
                        type(exc).__name__[:100],
                        0,
                        started_at,
                        clock(),
                    )
                else:
                    findings.extend(scanner_findings)
                    run = ScannerRun(
                        scanner.name,
                        scanner.category,
                        "ok",
                        None,
                        len(scanner_findings),
                        started_at,
                        clock(),
                    )
                runs.append(run)
            scans.replace_findings(scan.id, findings)
            scans.replace_scanner_runs(scan.id, runs)
            if any(run.status == "ok" for run in runs):
                report = score(findings, policy, runs)
                scan = scan.complete(report, clock())
            else:
                scan = scan.fail(
                    "all scanners failed" if runs else "no scanners configured", clock()
                )
    scans.save(scan)
    commit()
    return scan
