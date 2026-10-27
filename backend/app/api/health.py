from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.api.deps import SessionDep

router = APIRouter()


@router.get("/health")
def health(session: SessionDep) -> dict[str, str]:
    try:
        session.execute(text("SELECT 1"))
    except OperationalError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Database unavailable") from exc
    return {"status": "ok"}
