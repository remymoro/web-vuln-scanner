from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    id: str
    scanner: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
