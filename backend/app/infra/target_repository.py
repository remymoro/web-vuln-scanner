"""Adaptateur PostgreSQL du port TargetRepository."""

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.domain.targets import RegisteredTarget, TargetAlreadyRegisteredError
from app.infra.models import TargetModel


def _to_domain(model: TargetModel) -> RegisteredTarget:
    return RegisteredTarget(
        model.id,
        model.user_id,
        model.domain,
        model.verification_token,
        model.created_at,
        model.verified_at,
    )


class SqlAlchemyTargetRepository:
    """Ne valide jamais la transaction : c'est l'appelant qui décide du commit."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, target: RegisteredTarget) -> None:
        model = TargetModel(
            id=target.id,
            user_id=target.user_id,
            domain=target.domain,
            verification_token=target.verification_token,
            created_at=target.created_at,
            verified_at=target.verified_at,
        )
        try:
            with self._session.begin_nested():
                self._session.add(model)
        except IntegrityError as exc:
            if getattr(exc.orig.diag, "constraint_name", None) == "uq_targets_user_id_domain":
                raise TargetAlreadyRegisteredError(target.domain) from exc
            raise

    def get(self, target_id: uuid.UUID) -> RegisteredTarget | None:
        model = self._session.get(TargetModel, target_id)
        return None if model is None else _to_domain(model)

    def list_for_user(self, user_id: uuid.UUID) -> list[RegisteredTarget]:
        models = self._session.scalars(
            select(TargetModel)
            .where(TargetModel.user_id == user_id)
            .order_by(TargetModel.created_at, TargetModel.id)
        )
        return [_to_domain(model) for model in models]

    def mark_verified(self, target_id: uuid.UUID, at: datetime) -> None:
        self._session.execute(
            update(TargetModel).where(TargetModel.id == target_id).values(verified_at=at)
        )
