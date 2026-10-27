from dataclasses import FrozenInstanceError

import pytest

from app.domain.target import Target
from app.scanners.registry import ScannerRegistry


class StubScanner:
    def __init__(self, name):
        self.name = name

    def run(self, target):
        return []


def test_registry_order_and_snapshot():
    registry = ScannerRegistry()
    assert registry.all() == ()
    first, second = StubScanner("first"), StubScanner("second")
    registry.register(first)
    snapshot = registry.all()
    registry.register(second)
    assert snapshot == (first,)
    assert registry.all() == (first, second)
    assert ScannerRegistry().all() == ()


def test_duplicate_name_is_rejected():
    registry = ScannerRegistry()
    registry.register(StubScanner("headers"))
    with pytest.raises(ValueError, match="headers"):
        registry.register(StubScanner("headers"))
    assert len(registry.all()) == 1


def test_target_is_immutable():
    target = Target("https://example.test")
    assert target.url == "https://example.test"
    with pytest.raises(FrozenInstanceError):
        target.url = "https://other.test"
