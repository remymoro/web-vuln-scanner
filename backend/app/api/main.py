"""Fabrique de l'application : rien n'est créé à l'import, chaque test construit la sienne."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import auth, health, targets
from app.config import Settings, get_settings
from app.domain.auth import PasswordHasher
from app.domain.ports import TxtRecordResolver
from app.infra.db import create_db_engine, create_session_factory
from app.infra.passwords import Argon2PasswordHasher
from app.security.dns_verification import DnspythonTxtResolver


def create_app(
    settings: Settings | None = None,
    password_hasher: PasswordHasher | None = None,
    txt_resolver: TxtRecordResolver | None = None,
) -> FastAPI:
    settings = settings if settings is not None else get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        engine = create_db_engine(settings.database_url)
        app.state.session_factory = create_session_factory(engine)
        try:
            yield
        finally:
            engine.dispose()

    app = FastAPI(title="web-vuln-scanner", lifespan=lifespan)
    app.state.settings = settings
    app.state.password_hasher = password_hasher or Argon2PasswordHasher()
    app.state.txt_resolver = txt_resolver if txt_resolver is not None else DnspythonTxtResolver()
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(targets.router)
    return app
