"""Réglages lus depuis l'environnement (ou un fichier .env), jamais écrits en dur."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(pattern=r"^postgresql\+psycopg://")
    redis_url: str = Field(pattern=r"^rediss?://[^/\s]+")
    scan_timeout_seconds: int = Field(default=300, gt=0, le=3600)
    # Au-delà, un scan resté pending (job jamais enfilé ou perdu) est considéré abandonné.
    scan_pending_timeout_seconds: int = Field(default=3600, gt=0, le=86400)
    # Délai minimum entre deux scans d'une même cible.
    scan_cooldown_seconds: int = Field(default=600, ge=0, le=86400)
    jwt_secret: SecretStr = Field(min_length=32)
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_minutes: int = Field(default=30, gt=0, le=1440)


@lru_cache
def get_settings() -> Settings:
    return Settings()
