"""Résolution DNS TXT pour la preuve de propriété."""

import dns.exception
import dns.resolver

from app.domain.targets import DnsLookupError


class DnspythonTxtResolver:
    def __init__(
        self,
        resolver: dns.resolver.Resolver | None = None,
        *,
        timeout: float = 3.0,
        lifetime: float = 5.0,
        nameservers: list[str] | None = None,
    ) -> None:
        self._resolver = (
            resolver
            if resolver is not None
            else dns.resolver.Resolver(configure=nameservers is None)
        )
        if nameservers is not None:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    def txt_records(self, name: str) -> list[str]:
        try:
            records = self._resolver.resolve(name + ".", "TXT", search=False)
            return [
                b"".join(record.strings).decode("utf-8", errors="replace") for record in records
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsLookupError(f"DNS lookup failed for {name}") from exc
