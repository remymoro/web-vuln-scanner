from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

import httpx

from app.domain.finding import Finding, Severity
from app.domain.target import Target


class CheckType(StrEnum):
    PRESENT = "present"
    EQUALS = "equals"
    MIN_MAX_AGE = "min_max_age"
    MUST_NOT_CONTAIN = "must_not_contain"
    COOKIE_FLAGS = "cookie_flags"


@dataclass(frozen=True)
class HeaderRule:
    id: str
    header: str
    check: CheckType
    severity: Severity
    title: str
    description: str
    recommendation: str
    value: str | int | None = None

    def __post_init__(self) -> None:
        if self.check in (CheckType.PRESENT, CheckType.COOKIE_FLAGS):
            if self.value is not None:
                raise ValueError(f"value must be None for {self.check}")
        elif self.check in (CheckType.EQUALS, CheckType.MUST_NOT_CONTAIN):
            if not isinstance(self.value, str):
                raise ValueError(f"value must be a string for {self.check}")
        elif self.check == CheckType.MIN_MAX_AGE:
            if type(self.value) is not int or self.value < 0:
                raise ValueError("value must be a non-negative integer for min_max_age")
        else:
            raise ValueError(f"Unknown check: {self.check!r}")


def _finding(rule: HeaderRule, evidence: str, suffix: str = "") -> Finding:
    return Finding(
        id=rule.id + suffix,
        scanner="headers",
        category="en-têtes HTTP",
        severity=rule.severity,
        title=rule.title,
        description=rule.description,
        evidence=evidence,
        recommendation=rule.recommendation,
    )


def _max_age_is_sufficient(observed: str, minimum: int) -> bool:
    for directive in observed.split(";"):
        name, separator, value = directive.partition("=")
        if name.strip().casefold() == "max-age":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            if not separator or not value.isascii() or not value.isdecimal():
                return False
            try:
                return int(value) >= minimum
            except ValueError:
                return False
    return False


def analyze_headers(headers: httpx.Headers, rules: Sequence[HeaderRule]) -> list[Finding]:
    findings = []
    for rule in rules:
        if rule.check == CheckType.COOKIE_FLAGS:
            for cookie in headers.get_list("set-cookie"):
                parts = cookie.split(";")
                cookie_name = parts[0].partition("=")[0].strip()
                attributes = {part.partition("=")[0].strip().casefold() for part in parts[1:]}
                for flag in ("Secure", "HttpOnly", "SameSite"):
                    if flag.casefold() not in attributes:
                        findings.append(
                            _finding(
                                rule,
                                f"Cookie {cookie_name[:200]} : attribut {flag} absent",
                                f".{flag.lower()}",
                            )
                        )
            continue

        observed = headers.get(rule.header)
        bad = observed is None
        if observed is not None:
            match rule.check:
                case CheckType.EQUALS:
                    bad = observed.strip().casefold() != rule.value.casefold()
                case CheckType.MIN_MAX_AGE:
                    bad = not _max_age_is_sufficient(observed, rule.value)
                case CheckType.MUST_NOT_CONTAIN:
                    bad = rule.value.casefold() in observed.casefold()
        if bad:
            evidence = (
                f"En-tête {rule.header} absent"
                if observed is None
                else f"{rule.header} : {observed[:200]}"
            )
            findings.append(_finding(rule, evidence))
    return findings


class HeadersScanner:
    """Utilise le client injecté, créé par create_safe_client() ; n'en crée jamais."""

    name = "headers"
    category = "en-têtes HTTP"

    def __init__(self, client: httpx.Client, rules: Sequence[HeaderRule]) -> None:
        self._client = client
        self._rules = tuple(rules)

    def run(self, target: Target) -> list[Finding]:
        response = self._client.get(target.url, follow_redirects=False)
        return analyze_headers(response.headers, self._rules)
