"""Adaptateur PostgreSQL du port UserRepository."""

import uuid

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.domain.user import EmailAlreadyUsedError, User, normalize_email
from app.infra.models import UserModel


def _to_domain(model: UserModel) -> User:
    return User(model.id, model.email, model.password_hash, model.created_at)


class SqlAlchemyUserRepository:
    """Ne valide jamais la transaction : c'est l'appelant qui décide du commit."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, user: User) -> None:
        model = UserModel(
            id=user.id,
            email=user.email,
            password_hash=user.password_hash,
            created_at=user.created_at,
        )
        try:
            # Point de sauvegarde : un doublon n'annule pas le reste de la transaction.
            with self._session.begin_nested():
                self._session.add(model)
        except IntegrityError as exc:
            if getattr(exc.orig.diag, "constraint_name", None) == "uq_users_email":
                raise EmailAlreadyUsedError(user.email) from exc
            raise

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        model = self._session.get(UserModel, user_id)
        return None if model is None else _to_domain(model)

    def get_by_email(self, email: str) -> User | None:
        try:
            normalized = normalize_email(email)
        except ValueError:
            return None
        model = self._session.scalar(select(UserModel).where(UserModel.email == normalized))
        return None if model is None else _to_domain(model)

    def update_password_hash(self, user_id: uuid.UUID, password_hash: str) -> None:
        if not password_hash:
            raise ValueError("password_hash must not be empty")
        self._session.execute(
            update(UserModel).where(UserModel.id == user_id).values(password_hash=password_hash)
        )
