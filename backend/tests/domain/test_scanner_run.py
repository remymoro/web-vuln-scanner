from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from app.domain.scanner_run import ScannerRun, is_partial

NOW = datetime.now(UTC)


def test_scanner_run_is_frozen():
    run = ScannerRun("headers", "en-têtes HTTP", "ok", None, 0, NOW, NOW)
    with pytest.raises(FrozenInstanceError):
        run.status = "error"
    assert not is_partial([])
    assert not is_partial([run])


@pytest.mark.parametrize(
    "values",
    [
        {"status": "unknown"},
        {"error": "ValueError"},
        {"status": "error"},
        {"findings_count": -1},
        {"started_at": datetime(2026, 1, 1)},
        {"finished_at": datetime(2026, 1, 1)},
        {"finished_at": NOW - timedelta(seconds=1)},
    ],
)
def test_invalid_scanner_run(values):
    with pytest.raises(ValueError):
        replace(ScannerRun("headers", "en-têtes HTTP", "ok", None, 0, NOW, NOW), **values)
