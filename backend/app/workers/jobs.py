"""Composition et points d'entrée des jobs RQ."""

import atexit
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import httpx
from redis import Redis
from rq.job import Job
from rq.timeouts import JobTimeoutException
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.domain.ports import Scanner
from app.domain.scans import ScanStatus, execute_scan
from app.domain.scoring import ScoringPolicy
from app.infra.db import create_db_engine, create_session_factory
from app.infra.header_rules_config import load_header_rules
from app.infra.scan_repository import SqlAlchemyScanRepository
from app.infra.scoring_config import load_scoring_policy
from app.infra.target_repository import SqlAlchemyTargetRepository
from app.scanners.headers import HeadersScanner
from app.scanners.registry import ScannerRegistry
from app.security.ssrf import SsrfBlockedError, create_safe_client

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


@dataclass(frozen=True)
class WorkerRuntime:
    sessions: Callable[[], Session]
    scanners: tuple[Scanner, ...]
    policy: ScoringPolicy


@lru_cache
def _session_factory(process_id: int) -> sessionmaker[Session]:
    engine = create_db_engine(get_settings().database_url)
    atexit.register(engine.dispose)
    return create_session_factory(engine)


def get_worker_sessions() -> sessionmaker[Session]:
    return _session_factory(os.getpid())


def build_worker_runtime() -> WorkerRuntime:
    settings = get_settings()
    sessions = get_worker_sessions()
    policy = load_scoring_policy(CONFIG_DIR / "scoring.yaml")
    rules = load_header_rules(CONFIG_DIR / "header_rules.yaml")
    client = create_safe_client(
        allowed_hosts=(
            settings.dev_ssrf_allowed_hosts if settings.app_env == "development" else ()
        ),
        extra_ca_file=(settings.dev_extra_ca_file if settings.app_env == "development" else None),
    )
    atexit.register(client.close)
    registry = ScannerRegistry()
    registry.register(HeadersScanner(client, rules))
    return WorkerRuntime(sessions, registry.all(), policy)


@lru_cache
def _runtime(process_id: int) -> WorkerRuntime:
    return build_worker_runtime()


def get_worker_runtime() -> WorkerRuntime:
    return _runtime(os.getpid())


def _mark_failed(scan_id: uuid.UUID, reason: str) -> None:
    with get_worker_sessions()() as session:
        scans = SqlAlchemyScanRepository(session)
        scan = scans.get(scan_id)
        if scan is not None and scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
            scans.save(scan.fail(reason, datetime.now(UTC)))
            session.commit()


def run_scan(scan_id: str) -> None:
    identifier = uuid.UUID(scan_id)
    try:
        runtime = get_worker_runtime()
        with runtime.sessions() as session:
            execute_scan(
                SqlAlchemyScanRepository(session),
                SqlAlchemyTargetRepository(session),
                runtime.scanners,
                runtime.policy,
                identifier,
                lambda: datetime.now(UTC),
                (httpx.HTTPError, SsrfBlockedError),
                session.commit,
            )
    except JobTimeoutException:
        _mark_failed(identifier, "timeout")
        raise


def on_scan_failure(
    job: Job,
    connection: Redis,
    exc_type: type[BaseException],
    exc_value: BaseException,
    traceback: object,
) -> None:
    if issubclass(exc_type, JobTimeoutException):
        # RQ appelle ce callback avant de décider d'une relance.
        job.retries_left = 0
        job.save()
        _mark_failed(uuid.UUID(job.args[0]), "timeout")
    elif not job.should_retry:
        _mark_failed(uuid.UUID(job.args[0]), "worker error")
