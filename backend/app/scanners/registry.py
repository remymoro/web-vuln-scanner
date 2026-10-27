from app.scanners.base import Scanner


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, Scanner] = {}

    def register(self, scanner: Scanner) -> None:
        if scanner.name in self._scanners:
            raise ValueError(f"Scanner already registered: {scanner.name!r}")
        self._scanners[scanner.name] = scanner

    def all(self) -> tuple[Scanner, ...]:
        return tuple(self._scanners.values())
