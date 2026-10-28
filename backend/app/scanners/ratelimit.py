"""Rafale HTTP bornée et analyse pure des signes de limitation de débit."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from time import monotonic

import httpx

from app.domain.finding import Finding, Severity
from app.domain.target import Target


@dataclass(frozen=True)
class RateLimitRule:
    id: str
    severity: Severity
    title: str
    description: str
    recommendation: str


@dataclass(frozen=True)
class BurstResult:
    requests_count: int
    duration: float
    signal: str | None = None


_LIMIT_HEADERS = (
    "RateLimit-Limit",
    "RateLimit-Policy",
    "RateLimit",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
)


def validate_burst_options(max_requests: int, max_duration: int) -> None:
    if type(max_requests) is not int or not 5 <= max_requests <= 100:
        raise ValueError("ratelimit max_requests must be an integer between 5 and 100")
    if type(max_duration) is not int or not 1 <= max_duration <= 10:
        raise ValueError("ratelimit max_duration must be an integer between 1 and 10 seconds")


def _limit_signal(response: httpx.Response) -> str | None:
    if response.status_code == 429:
        return "429"
    if response.status_code == 503 and "Retry-After" in response.headers:
        return "503 + Retry-After"
    return next((header for header in _LIMIT_HEADERS if header in response.headers), None)


def collect_burst(
    client: httpx.Client,
    target: Target,
    *,
    max_requests: int = 30,
    max_duration: int = 3,
    clock: Callable[[], float] = monotonic,
) -> BurstResult:
    validate_burst_options(max_requests, max_duration)
    started = clock()
    count = 0
    signal = None
    while count < max_requests:
        remaining = max_duration - (clock() - started)
        if remaining <= 0:
            break
        # Ne pas allonger les délais du client ; HTTPX les applique par opération,
        # pas comme une échéance absolue de la requête en cours.
        timeout = httpx.Timeout(
            **{
                phase: remaining if value is None else min(value, remaining)
                for phase, value in client.timeout.as_dict().items()
            }
        )
        # Seuls statut et en-têtes sont utiles ; fermer avant de lire le corps.
        with client.stream("GET", target.url, follow_redirects=False, timeout=timeout) as response:
            count += 1
            signal = _limit_signal(response)
        if signal is not None:
            break
    return BurstResult(count, clock() - started, signal)


def analyze_ratelimit(result: BurstResult, rules: Sequence[RateLimitRule]) -> list[Finding]:
    if result.signal is not None:
        return []
    duration = f"{result.duration:.1f}".replace(".", ",")
    return [
        Finding(
            id=rule.id,
            scanner="ratelimit",
            category="Limitation de débit",
            severity=rule.severity,
            title=rule.title,
            description=rule.description,
            evidence=(
                f"{result.requests_count} requêtes en {duration} s, "
                "aucune réponse 429 ni en-tête de limitation"
            )[:200],
            recommendation=rule.recommendation,
        )
        for rule in rules
    ]


class RateLimitScanner:
    """Réutilise le client anti-SSRF du contexte, sans le créer ni le fermer."""

    name = "ratelimit"
    category = "Limitation de débit"

    def __init__(
        self,
        client: httpx.Client,
        rules: Sequence[RateLimitRule],
        *,
        max_requests: int = 30,
        max_duration: int = 3,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        validate_burst_options(max_requests, max_duration)
        self._client = client
        self._rules = tuple(rules)
        self._max_requests = max_requests
        self._max_duration = max_duration
        self._clock = clock

    def run(self, target: Target) -> list[Finding]:
        result = collect_burst(
            self._client,
            target,
            max_requests=self._max_requests,
            max_duration=self._max_duration,
            clock=self._clock,
        )
        return analyze_ratelimit(result, self._rules)
