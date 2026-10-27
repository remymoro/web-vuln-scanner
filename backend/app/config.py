"""Réglages lus depuis l'environnement (ou un fichier .env), jamais écrits en dur."""

from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.domain.targets import normalize_domain


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["development", "test", "production"] = "production"
    dev_ssrf_allowed_hosts: list[str] = Field(default_factory=list)
    dev_extra_ca_file: Path | None = None
    dns_nameservers: list[IPv4Address | IPv6Address] | None = None
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

    @field_validator("dev_ssrf_allowed_hosts")
    @classmethod
    def exact_hosts(cls, hosts: list[str]) -> list[str]:
        if any(normalize_domain(host) != host for host in hosts):
            raise ValueError("Use exact lowercase ASCII hostnames without URLs or trailing dots")
        return hosts

    @field_validator("dns_nameservers")
    @classmethod
    def nonempty_nameservers(
        cls, nameservers: list[IPv4Address | IPv6Address] | None
    ) -> list[IPv4Address | IPv6Address] | None:
        if nameservers == []:
            raise ValueError("dns_nameservers must contain at least one IP or be unset")
        return nameservers

    @model_validator(mode="after")
    def development_exceptions(self) -> Self:
        if self.app_env != "development" and (
            self.dev_ssrf_allowed_hosts or self.dev_extra_ca_file is not None
        ):
            raise ValueError("Demo exceptions require app_env=development")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
