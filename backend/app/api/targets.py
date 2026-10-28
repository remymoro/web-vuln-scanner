import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.auth import CurrentUserDep
from app.api.deps import SessionDep
from app.api.scans import ScanResponse, scan_response
from app.domain.ports import TxtRecordResolver
from app.domain.targets import (
    DnsLookupError,
    OwnershipNotProvenError,
    RegisteredTarget,
    TargetAlreadyRegisteredError,
    TargetNotFoundError,
    normalize_domain,
    register_target,
    verify_target,
)
from app.infra.scan_repository import SqlAlchemyScanRepository
from app.infra.target_repository import SqlAlchemyTargetRepository

router = APIRouter(prefix="/targets", tags=["targets"])


class RegisterTargetRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def valid_url(cls, url: str) -> str:
        return normalize_domain(url)


class DnsRecordResponse(BaseModel):
    type: Literal["TXT"] = "TXT"
    name: str
    value: str


class TargetResponse(BaseModel):
    id: uuid.UUID
    domain: str
    verified: bool
    verified_at: datetime | None
    dns_record: DnsRecordResponse


def _to_response(target: RegisteredTarget) -> TargetResponse:
    return TargetResponse(
        id=target.id,
        domain=target.domain,
        verified=target.is_verified,
        verified_at=target.verified_at,
        dns_record=DnsRecordResponse(name=target.dns_record_name, value=target.dns_record_value),
    )


def get_txt_resolver(request: Request) -> TxtRecordResolver:
    return request.app.state.txt_resolver


ResolverDep = Annotated[TxtRecordResolver, Depends(get_txt_resolver)]


@router.post("", status_code=status.HTTP_201_CREATED)
def register(
    body: RegisterTargetRequest, session: SessionDep, user: CurrentUserDep
) -> TargetResponse:
    try:
        target = register_target(SqlAlchemyTargetRepository(session), user.id, body.url)
    except TargetAlreadyRegisteredError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Domain already registered") from None
    return _to_response(target)


@router.get("")
def list_targets(session: SessionDep, user: CurrentUserDep) -> list[TargetResponse]:
    targets = SqlAlchemyTargetRepository(session).list_for_user(user.id)
    return [_to_response(target) for target in targets]


@router.get("/{target_id}")
def get_target(target_id: uuid.UUID, session: SessionDep, user: CurrentUserDep) -> TargetResponse:
    target = SqlAlchemyTargetRepository(session).get(target_id)
    if target is None or target.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    return _to_response(target)


@router.get("/{target_id}/scans")
def list_target_scans(
    target_id: uuid.UUID, session: SessionDep, user: CurrentUserDep
) -> list[ScanResponse]:
    target = SqlAlchemyTargetRepository(session).get(target_id)
    if target is None or target.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    scans = SqlAlchemyScanRepository(session)
    return [scan_response(scan, scans) for scan in scans.list_for_target(target_id)]


@router.post("/{target_id}/verify")
def verify(
    target_id: uuid.UUID, session: SessionDep, user: CurrentUserDep, resolver: ResolverDep
) -> TargetResponse:
    try:
        target = verify_target(
            SqlAlchemyTargetRepository(session), resolver, user.id, target_id, datetime.now(UTC)
        )
    except TargetNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found") from None
    except OwnershipNotProvenError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except DnsLookupError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "DNS lookup unavailable") from None
    return _to_response(target)
