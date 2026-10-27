"""Dépendances FastAPI partagées par les routes."""

from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session


def get_session(request: Request) -> Generator[Session]:
    # Une requête = une transaction : validée si la route réussit, annulée sinon.
    session = request.app.state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# scope="function" : le commit a lieu avant l'envoi de la réponse. Avec le scope par
# défaut, un commit qui échoue après la route laisserait partir un 200 trompeur.
SessionDep = Annotated[Session, Depends(get_session, scope="function")]
