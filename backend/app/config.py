"""Réglages lus depuis l'environnement (ou un fichier .env), jamais écrits en dur."""

from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.domain.targets import normalize_domain


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["development", "test", "production"] = "production"
    dev_ssrf_allowed_hosts: list[str] = Field(default_factory=list)
    dev_extra_ca_file: Path | None = None
    # Démo : origine réellement scannée pour un nom vérifié, ex. http://juiceshop.lab:3000/.
    dev_target_origins: dict[str, str] = Field(default_factory=dict)
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

    @field_validator("dev_target_origins")
    @classmethod
    def exact_origins(cls, origins: dict[str, str]) -> dict[str, str]:
        for host, origin in origins.items():
            parsed = urlsplit(origin)
            if (
                normalize_domain(host) != host
                or parsed.scheme not in {"http", "https"}
                or parsed.hostname != host
                or parsed.netloc != f"{host}:{parsed.port}"
                or not 1 <= parsed.port <= 65535
                or parsed.path != "/"
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Use origins like http://host:port/ keyed by their exact host")
        return origins

    @property
    def dev_target_ports(self) -> frozenset[tuple[str, int]]:
        return frozenset((host, urlsplit(o).port) for host, o in self.dev_target_origins.items())

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
            self.dev_ssrf_allowed_hosts
            or self.dev_extra_ca_file is not None
            or self.dev_target_origins
        ):
            raise ValueError("Demo exceptions require app_env=development")
        if not self.dev_target_origins.keys() <= set(self.dev_ssrf_allowed_hosts):
            raise ValueError("DEV_TARGET_ORIGINS hosts must be in DEV_SSRF_ALLOWED_HOSTS")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
