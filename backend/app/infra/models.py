"""Modèles SQLAlchemy : la forme des tables. Le domaine ne les importe jamais."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.infra.db import Base


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TargetModel(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("user_id", "domain"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    domain: Mapped[str] = mapped_column(String(253))
    verification_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanModel(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index(
            "uq_scans_active_target",
            "target_id",
            unique=True,
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    score: Mapped[int | None]
    grade: Mapped[str | None] = mapped_column(String(1))
    error: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(server_default=text("0"))


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(Text)
    scanner: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)


class ScannerRunModel(Base):
    __tablename__ = "scanner_runs"
    __table_args__ = (UniqueConstraint("scan_id", "scanner"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    scanner: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(Text)
    findings_count: Mapped[int]
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
