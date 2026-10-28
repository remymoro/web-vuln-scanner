"""Adaptateur PostgreSQL du port ScanRepository."""

import uuid
from collections.abc import Iterable
from dataclasses import asdict
from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.domain.finding import Finding, Severity
from app.domain.scanner_run import ScannerRun
from app.domain.scans import Scan, ScanAlreadyActiveError, ScanStatus
from app.domain.scoring import Grade
from app.infra.models import FindingModel, ScanModel, ScannerRunModel


def _to_domain(model: ScanModel) -> Scan:
    return Scan(
        model.id,
        model.target_id,
        ScanStatus(model.status),
        model.created_at,
        model.started_at,
        model.finished_at,
        model.score,
        None if model.grade is None else Grade(model.grade),
        model.error,
        model.attempts,
    )


class SqlAlchemyScanRepository:
    """Ne valide jamais la transaction : c'est l'appelant qui décide du commit."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, scan: Scan) -> None:
        try:
            with self._session.begin_nested():
                self._session.add(ScanModel(**asdict(scan)))
        except IntegrityError as exc:
            if getattr(exc.orig.diag, "constraint_name", None) == "uq_scans_active_target":
                raise ScanAlreadyActiveError from exc
            raise

    def get(self, scan_id: uuid.UUID) -> Scan | None:
        model = self._session.get(ScanModel, scan_id)
        return None if model is None else _to_domain(model)

    def get_active_for_target(self, target_id: uuid.UUID) -> Scan | None:
        model = self._session.scalar(
            select(ScanModel).where(
                ScanModel.target_id == target_id,
                ScanModel.status.in_((ScanStatus.PENDING, ScanStatus.RUNNING)),
            )
        )
        return None if model is None else _to_domain(model)

    def list_for_target(self, target_id: uuid.UUID) -> list[Scan]:
        models = self._session.scalars(
            select(ScanModel)
            .where(ScanModel.target_id == target_id)
            .order_by(ScanModel.created_at.desc(), ScanModel.id.desc())
            .limit(20)
        )
        return [_to_domain(model) for model in models]

    def list_for_target_since(self, target_id: uuid.UUID, since: datetime) -> list[Scan]:
        models = self._session.scalars(
            select(ScanModel)
            .where(ScanModel.target_id == target_id, ScanModel.created_at >= since)
            .order_by(ScanModel.created_at, ScanModel.id)
        )
        return [_to_domain(model) for model in models]

    def save(self, scan: Scan) -> None:
        values = asdict(scan)
        del values["id"]
        try:
            with self._session.begin_nested():
                self._session.execute(
                    update(ScanModel).where(ScanModel.id == scan.id).values(**values)
                )
        except IntegrityError as exc:
            if getattr(exc.orig.diag, "constraint_name", None) == "uq_scans_active_target":
                raise ScanAlreadyActiveError from exc
            raise

    def replace_findings(self, scan_id: uuid.UUID, findings: Iterable[Finding]) -> None:
        self._session.execute(delete(FindingModel).where(FindingModel.scan_id == scan_id))
        for finding in findings:
            values = asdict(finding)
            values["rule_id"] = values.pop("id")
            self._session.add(FindingModel(scan_id=scan_id, **values))
        self._session.flush()

    def get_findings(self, scan_id: uuid.UUID) -> list[Finding]:
        models = self._session.scalars(
            select(FindingModel)
            .where(FindingModel.scan_id == scan_id)
            .order_by(FindingModel.rule_id, FindingModel.id)
        )
        return [
            Finding(
                model.rule_id,
                model.scanner,
                model.category,
                Severity(model.severity),
                model.title,
                model.description,
                model.evidence,
                model.recommendation,
            )
            for model in models
        ]

    def replace_scanner_runs(self, scan_id: uuid.UUID, runs: Iterable[ScannerRun]) -> None:
        self._session.execute(delete(ScannerRunModel).where(ScannerRunModel.scan_id == scan_id))
        for run in runs:
            self._session.add(ScannerRunModel(scan_id=scan_id, **asdict(run)))
        self._session.flush()

    def get_scanner_runs(self, scan_id: uuid.UUID) -> list[ScannerRun]:
        models = self._session.scalars(
            select(ScannerRunModel)
            .where(ScannerRunModel.scan_id == scan_id)
            .order_by(ScannerRunModel.started_at, ScannerRunModel.scanner)
        )
        return [
            ScannerRun(
                model.scanner,
                model.category,
                model.status,
                model.error,
                model.findings_count,
                model.started_at,
                model.finished_at,
            )
            for model in models
        ]
