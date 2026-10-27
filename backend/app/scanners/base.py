from typing import Protocol

from app.domain.finding import Finding
from app.domain.target import Target


class Scanner(Protocol):
    name: str

    def run(self, target: Target) -> list[Finding]: ...
