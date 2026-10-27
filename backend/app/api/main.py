"""Fabrique de l'application : rien n'est créé à l'import, chaque test construit la sienne."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from redis import Redis

from app.api import auth, health, scans, targets
from app.config import Settings, get_settings
from app.domain.auth import PasswordHasher
from app.domain.ports import ScanQueue, TxtRecordResolver
from app.domain.scoring import ScoringPolicy
from app.infra.db import create_db_engine, create_session_factory
from app.infra.passwords import Argon2PasswordHasher
from app.infra.scan_queue import RqScanQueue
from app.infra.scoring_config import load_scoring_policy
from app.security.dns_verification import DnspythonTxtResolver


def create_app(
    settings: Settings | None = None,
    password_hasher: PasswordHasher | None = None,
    txt_resolver: TxtRecordResolver | None = None,
    scan_queue: ScanQueue | None = None,
    scoring_policy: ScoringPolicy | None = None,
) -> FastAPI:
    settings = settings if settings is not None else get_settings()
    connection = None if scan_queue is not None else Redis.from_url(settings.redis_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        engine = create_db_engine(settings.database_url)
        app.state.session_factory = create_session_factory(engine)
        try:
            yield
        finally:
            engine.dispose()
            if connection is not None:
                connection.close()

    app = FastAPI(title="web-vuln-scanner", lifespan=lifespan)
    app.state.settings = settings
    app.state.password_hasher = password_hasher or Argon2PasswordHasher()
    app.state.txt_resolver = (
        txt_resolver
        if txt_resolver is not None
        else DnspythonTxtResolver(
            nameservers=(
                [str(ip) for ip in settings.dns_nameservers]
                if settings.dns_nameservers is not None
                else None
            )
        )
    )
    app.state.scan_queue = (
        scan_queue
        if scan_queue is not None
        else RqScanQueue(connection, settings.scan_timeout_seconds)
    )
    app.state.scoring_policy = (
        scoring_policy
        if scoring_policy is not None
        else load_scoring_policy(Path(__file__).resolve().parents[2] / "config/scoring.yaml")
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(targets.router)
    app.include_router(scans.router)
    return app
