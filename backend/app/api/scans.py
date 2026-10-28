import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from app.api.auth import CurrentUserDep
from app.api.deps import SessionDep
from app.domain.finding import Finding
from app.domain.scanner_run import ScannerRun, is_partial
from app.domain.scans import (
    QueueUnavailableError,
    Scan,
    ScanAlreadyActiveError,
    ScanStatus,
    ScanTooSoonError,
    request_scan,
)
from app.domain.scoring import CategoryScore, Deduction, Grade, score
from app.domain.targets import TargetNotFoundError, TargetNotVerifiedError
from app.infra.scan_repository import SqlAlchemyScanRepository
from app.infra.target_repository import SqlAlchemyTargetRepository

router = APIRouter(prefix="/scans", tags=["scans"])


class RequestScanBody(BaseModel):
    target_id: uuid.UUID


class RequestedScanResponse(BaseModel):
    id: uuid.UUID
    status: ScanStatus


class ScannerResponse(BaseModel):
    name: str
    category: str
    status: Literal["ok", "error"]
    error: str | None
    findings_count: int


def _scanner_responses(runs: list[ScannerRun]) -> list[ScannerResponse]:
    return [
        ScannerResponse(
            name=run.scanner,
            category=run.category,
            status=run.status,
            error=run.error,
            findings_count=run.findings_count,
        )
        for run in runs
    ]


class ScanResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    score: int | None
    grade: Grade | None
    error: str | None
    partial: bool
    scanners: list[ScannerResponse]


def scan_response(scan: Scan, scans: SqlAlchemyScanRepository) -> ScanResponse:
    runs = scans.get_scanner_runs(scan.id)
    return ScanResponse(**asdict(scan), partial=is_partial(runs), scanners=_scanner_responses(runs))


class ScanReportResponse(BaseModel):
    score: int
    grade: Grade
    categories: tuple[CategoryScore, ...]
    deductions: tuple[Deduction, ...]
    findings: list[Finding]
    partial: bool
    scanners: list[ScannerResponse]


def _owned_scan(session: SessionDep, user: CurrentUserDep, scan_id: uuid.UUID) -> Scan:
    scan = SqlAlchemyScanRepository(session).get(scan_id)
    target = None if scan is None else SqlAlchemyTargetRepository(session).get(scan.target_id)
    if scan is None or target is None or target.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def request_new_scan(
    body: RequestScanBody, request: Request, session: SessionDep, user: CurrentUserDep
) -> RequestedScanResponse:
    scans = SqlAlchemyScanRepository(session)
    try:
        scan = request_scan(
            SqlAlchemyTargetRepository(session),
            scans,
            user.id,
            body.target_id,
            datetime.now(UTC),
            request.app.state.settings.scan_timeout_seconds,
            pending_timeout=request.app.state.settings.scan_pending_timeout_seconds,
            cooldown=request.app.state.settings.scan_cooldown_seconds,
        )
    except TargetNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found") from None
    except TargetNotVerifiedError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Target not verified") from None
    except ScanAlreadyActiveError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan already active") from None
    except ScanTooSoonError as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Scan requested too soon",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from None
    # Double écriture : commit avant Redis, puis compensation si l'envoi échoue.
    # Une transactional outbox fiabiliserait l'envoi après commit.
    session.commit()
    try:
        request.app.state.scan_queue.enqueue(scan.id)
    except QueueUnavailableError:
        scans.save(scan.fail("queue unavailable", datetime.now(UTC)))
        session.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Queue unavailable") from None
    return RequestedScanResponse(id=scan.id, status=scan.status)


@router.get("/{scan_id}")
def get_scan(scan_id: uuid.UUID, session: SessionDep, user: CurrentUserDep) -> ScanResponse:
    return scan_response(_owned_scan(session, user, scan_id), SqlAlchemyScanRepository(session))


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: uuid.UUID, request: Request, session: SessionDep, user: CurrentUserDep
) -> ScanReportResponse:
    scan = _owned_scan(session, user, scan_id)
    if scan.status != ScanStatus.DONE:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not done")
    scans = SqlAlchemyScanRepository(session)
    findings = scans.get_findings(scan.id)
    runs = scans.get_scanner_runs(scan.id)
    report = score(findings, request.app.state.scoring_policy, runs or None)
    # Note globale figée à la fin du scan ; le détail est recalculé avec le barème actuel.
    return ScanReportResponse(
        score=scan.score,
        grade=scan.grade,
        categories=report.categories,
        deductions=report.deductions,
        findings=findings,
        partial=is_partial(runs),
        scanners=_scanner_responses(runs),
    )
