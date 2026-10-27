from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    url: str
