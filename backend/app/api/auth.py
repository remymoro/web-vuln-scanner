import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from app.api.deps import SessionDep
from app.api.tokens import InvalidTokenError, create_access_token, decode_access_token
from app.domain.auth import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    InvalidCredentialsError,
    PasswordHasher,
    authenticate_user,
    register_user,
)
from app.domain.user import EmailAlreadyUsedError, User, normalize_email
from app.infra.user_repository import SqlAlchemyUserRepository

router = APIRouter(prefix="/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)


class RegisterRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def valid_email(cls, email: str) -> str:
        return normalize_email(email)


class LoginRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def get_password_hasher(request: Request) -> PasswordHasher:
    return request.app.state.password_hasher


HasherDep = Annotated[PasswordHasher, Depends(get_password_hasher)]

UNAUTHORIZED = HTTPException(
    status.HTTP_401_UNAUTHORIZED,
    "Invalid or missing token",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    request: Request,
    session: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> User:
    if credentials is None:
        raise UNAUTHORIZED
    try:
        user_id = decode_access_token(credentials.credentials, request.app.state.settings)
    except InvalidTokenError:
        raise UNAUTHORIZED from None
    user = SqlAlchemyUserRepository(session).get_by_id(user_id)
    if user is None:
        raise UNAUTHORIZED
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, session: SessionDep, hasher: HasherDep) -> UserResponse:
    try:
        user = register_user(SqlAlchemyUserRepository(session), hasher, body.email, body.password)
    except EmailAlreadyUsedError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from None
    return UserResponse(id=user.id, email=user.email)


@router.post("/login")
def login(
    body: LoginRequest, request: Request, session: SessionDep, hasher: HasherDep
) -> TokenResponse:
    try:
        user = authenticate_user(
            SqlAlchemyUserRepository(session), hasher, body.email, body.password
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    return TokenResponse(access_token=create_access_token(user.id, request.app.state.settings))


@router.get("/me")
def me(user: CurrentUserDep) -> UserResponse:
    return UserResponse(id=user.id, email=user.email)
