import uuid
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from app.domain.finding import Finding, Severity
from app.domain.scanner_run import ScannerRun, is_partial
from app.domain.scans import (
    InvalidScanTransitionError,
    Scan,
    ScanAlreadyActiveError,
    ScanNotFoundError,
    ScanStatus,
    ScanTooSoonError,
    execute_scan,
    request_scan,
)
from app.domain.scoring import DEFAULT_POLICY, Grade, score
from app.domain.targets import RegisteredTarget, TargetNotFoundError, TargetNotVerifiedError
from tests.domain.test_targets import InMemoryTargetRepository
from tests.fakes import FakeScanner

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)
FINDING = Finding("fake.rule", "fake", "headers", Severity.MEDIUM, "title", "why", "proof", "fix")


class InMemoryScanRepository:
    def __init__(self):
        self.scans = {}
        self.findings = {}
        self.runs = {}

    def add(self, scan):
        self.scans[scan.id] = scan

    def get(self, scan_id):
        return self.scans.get(scan_id)

    def get_active_for_target(self, target_id):
        return next(
            (
                scan
                for scan in self.scans.values()
                if scan.target_id == target_id
                and scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
            ),
            None,
        )

    def list_for_target_since(self, target_id, since):
        return sorted(
            (s for s in self.scans.values() if s.target_id == target_id and s.created_at >= since),
            key=lambda s: s.created_at,
        )

    def save(self, scan):
        self.scans[scan.id] = scan

    def replace_findings(self, scan_id, findings):
        self.findings[scan_id] = list(findings)

    def get_findings(self, scan_id):
        return self.findings.get(scan_id, [])

    def replace_scanner_runs(self, scan_id, runs):
        self.runs[scan_id] = list(runs)

    def get_scanner_runs(self, scan_id):
        return self.runs.get(scan_id, [])


@pytest.fixture
def scans():
    return InMemoryScanRepository()


@pytest.fixture
def targets():
    return InMemoryTargetRepository()


@pytest.fixture
def target(targets):
    target = RegisteredTarget.create(uuid.uuid4(), "example.com").mark_verified(NOW)
    targets.add(target)
    return target


@pytest.fixture
def pending(scans, target):
    scan = Scan.create(target.id)
    scans.add(scan)
    return scan


def test_create_is_frozen_and_pending():
    target_id = uuid.uuid4()
    scan = Scan.create(target_id)
    assert scan.target_id == target_id
    assert scan.id != Scan.create(target_id).id
    assert scan.status == ScanStatus.PENDING
    assert scan.created_at.utcoffset() == timedelta(0)
    assert (scan.started_at, scan.finished_at, scan.score, scan.grade, scan.error) == (None,) * 5
    assert scan.attempts == 0
    with pytest.raises(FrozenInstanceError):
        scan.status = ScanStatus.DONE


@pytest.mark.parametrize("field", ["created_at", "started_at", "finished_at"])
def test_dates_require_timezone(pending, field):
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(pending, **{field: datetime(2026, 1, 1)})


@pytest.mark.parametrize("operation", ["start", "complete", "fail"])
def test_transitions_require_timezone(pending, operation):
    naive = datetime(2026, 1, 1)
    with pytest.raises(ValueError, match="timezone-aware"):
        if operation == "start":
            pending.start(naive)
        elif operation == "complete":
            pending.start(NOW).complete(score([], DEFAULT_POLICY), naive)
        else:
            pending.fail("reason", naive)


def test_start_restart_and_complete(pending):
    first = pending.start(NOW)
    second = first.start(NOW + timedelta(seconds=10))
    report = score([FINDING], DEFAULT_POLICY)
    done = second.complete(report, NOW + timedelta(seconds=20))
    assert first.attempts == 1
    assert second.attempts == 2
    assert second.started_at == NOW + timedelta(seconds=10)
    assert done.status == ScanStatus.DONE
    assert done.finished_at == NOW + timedelta(seconds=20)
    assert (done.score, done.grade, done.error) == (90, Grade.A, None)
    assert pending.status == ScanStatus.PENDING


@pytest.mark.parametrize("status", [ScanStatus.PENDING, ScanStatus.RUNNING])
def test_fail_from_active_status(pending, status):
    scan = pending if status == ScanStatus.PENDING else pending.start(NOW)
    failed = scan.fail("reason", NOW)
    assert (failed.status, failed.finished_at, failed.error) == (ScanStatus.FAILED, NOW, "reason")


@pytest.mark.parametrize("status", list(ScanStatus))
@pytest.mark.parametrize("operation", ["start", "complete", "fail"])
def test_every_forbidden_transition(pending, status, operation):
    valid = {
        "start": {ScanStatus.PENDING, ScanStatus.RUNNING},
        "complete": {ScanStatus.RUNNING},
        "fail": {ScanStatus.PENDING, ScanStatus.RUNNING},
    }
    if status in valid[operation]:
        return
    scan = replace(pending, status=status)
    with pytest.raises(InvalidScanTransitionError):
        if operation == "start":
            scan.start(NOW)
        elif operation == "complete":
            scan.complete(score([], DEFAULT_POLICY), NOW)
        else:
            scan.fail("reason", NOW)


def request(targets, scans, target, **kwargs):
    return request_scan(
        targets,
        scans,
        target.user_id,
        target.id,
        NOW,
        **{"timeout": 300, "pending_timeout": 3600, "cooldown": 0, **kwargs},
    )


def test_request_adds_pending_with_supplied_date(targets, scans, target):
    scan = request(targets, scans, target)
    assert scan.status == ScanStatus.PENDING
    assert scans.get(scan.id) == scan
    assert scan.created_at == NOW


@pytest.mark.parametrize("missing", [False, True])
def test_request_hides_missing_and_other_users_target(targets, scans, target, missing):
    with pytest.raises(TargetNotFoundError):
        request_scan(
            targets,
            scans,
            uuid.uuid4(),
            uuid.uuid4() if missing else target.id,
            NOW,
            300,
            pending_timeout=3600,
            cooldown=0,
        )
    assert scans.scans == {}


def test_request_rejects_unverified_target(targets, scans, target):
    targets.targets[target.id] = replace(target, verified_at=None)
    with pytest.raises(TargetNotVerifiedError):
        request(targets, scans, target)
    assert scans.scans == {}


@pytest.mark.parametrize(
    ("status", "age"),
    [(ScanStatus.PENDING, 1000), (ScanStatus.RUNNING, 0), (ScanStatus.RUNNING, 360)],
)
def test_active_scan_conflicts(targets, scans, target, status, age):
    scan = replace(Scan.create(target.id), created_at=NOW - timedelta(seconds=age))
    if status == ScanStatus.RUNNING:
        scan = scan.start(NOW - timedelta(seconds=age))
    scans.add(scan)
    with pytest.raises(ScanAlreadyActiveError):
        request(targets, scans, target)
    assert scans.get(scan.id) == scan


def test_stale_pending_scan_is_abandoned_and_replaced(targets, scans, target):
    # Pending sans job (crash entre commit et mise en file) : la cible ne reste pas bloquée.
    stale = replace(Scan.create(target.id), created_at=NOW - timedelta(seconds=3601))
    scans.add(stale)
    fresh = request(targets, scans, target)
    assert scans.get(stale.id).status == ScanStatus.FAILED
    assert scans.get(stale.id).error == "abandoned"
    assert scans.get_active_for_target(target.id) == fresh


def test_scan_within_cooldown_is_refused_with_remaining_delay(targets, scans, target):
    previous = replace(Scan.create(target.id), created_at=NOW - timedelta(seconds=400))
    scans.add(previous.start(NOW).complete(score([], DEFAULT_POLICY), NOW))
    with pytest.raises(ScanTooSoonError) as caught:
        request(targets, scans, target, cooldown=600)
    assert caught.value.retry_after_seconds == 200


def test_scan_after_cooldown_is_allowed(targets, scans, target):
    previous = replace(Scan.create(target.id), created_at=NOW - timedelta(seconds=600))
    scans.add(previous.start(NOW).complete(score([], DEFAULT_POLICY), NOW))
    assert request(targets, scans, target, cooldown=600).status == ScanStatus.PENDING


@pytest.mark.parametrize("reason", ["queue unavailable", "abandoned", "worker error"])
def test_infrastructure_failures_do_not_start_the_cooldown(targets, scans, target, reason):
    previous = replace(Scan.create(target.id), created_at=NOW - timedelta(seconds=10))
    scans.add(previous.fail(reason, NOW))
    assert request(targets, scans, target, cooldown=600).status == ScanStatus.PENDING


def test_target_failures_start_the_cooldown(targets, scans, target):
    previous = replace(Scan.create(target.id), created_at=NOW - timedelta(seconds=10))
    scans.add(previous.start(NOW).fail("target error: ConnectError", NOW))
    with pytest.raises(ScanTooSoonError):
        request(targets, scans, target, cooldown=600)


def test_abandoned_running_scan_is_failed_and_replaced(targets, scans, target):
    abandoned = Scan.create(target.id).start(NOW - timedelta(seconds=361))
    scans.add(abandoned)
    fresh = request(targets, scans, target)
    assert fresh.id != abandoned.id
    assert scans.get_active_for_target(target.id) == fresh
    assert scans.get(abandoned.id) == abandoned.fail("abandoned", NOW)


def execute(scans, targets, scan_id, scanners=(), commit=lambda: None):
    return execute_scan(scans, targets, scanners, DEFAULT_POLICY, scan_id, lambda: NOW, commit)


def test_execution_saves_running_before_scanners_then_report(scans, targets, pending):
    snapshots = []
    scanner = FakeScanner([FINDING])
    done = execute(
        scans,
        targets,
        pending.id,
        [scanner],
        commit=lambda: snapshots.append(scans.get(pending.id)),
    )
    assert [scan.status for scan in snapshots] == [ScanStatus.RUNNING, ScanStatus.DONE]
    assert done == scans.get(pending.id)
    assert done.score == 90
    assert done.grade == Grade.A
    assert done.attempts == 1
    assert done.started_at == done.finished_at == NOW
    assert scans.get_findings(done.id) == [FINDING]
    assert scanner.targets[0].url == "https://example.com/"


@pytest.mark.parametrize("status", [ScanStatus.DONE, ScanStatus.FAILED])
def test_terminal_execution_is_idempotent(scans, targets, pending, status):
    terminal = replace(pending, status=status)
    scans.save(terminal)
    scanner = FakeScanner(error=AssertionError("must not run"))
    result = execute(scans, targets, terminal.id, [scanner], commit=lambda: pytest.fail("commit"))
    assert result == terminal
    assert scanner.targets == []


def test_retry_replaces_old_findings(scans, targets, pending):
    scans.save(pending.start(NOW))
    scans.replace_findings(pending.id, [FINDING, FINDING])
    scans.replace_scanner_runs(pending.id, [ScannerRun("old", "old", "ok", None, 2, NOW, NOW)])
    done = execute(scans, targets, pending.id, [FakeScanner([FINDING])])
    assert done.attempts == 2
    assert scans.get_findings(done.id) == [FINDING]
    assert [run.scanner for run in scans.get_scanner_runs(done.id)] == ["fake"]


def test_multiple_scanners_are_executed(scans, targets, pending):
    done = execute(
        scans,
        targets,
        pending.id,
        [FakeScanner([FINDING]), FakeScanner([replace(FINDING, scanner="other")], name="other")],
    )
    assert done.score == 80
    assert scans.get_findings(done.id) == [FINDING, replace(FINDING, scanner="other")]


@pytest.mark.parametrize("error", [ValueError("secret target"), RuntimeError("secret plugin bug")])
def test_scanner_error_is_isolated_without_exposing_details(scans, targets, pending, error):
    scanner = FakeScanner(error=error, name="broken", category="TLS")
    following = FakeScanner()
    done = execute(scans, targets, pending.id, [scanner, following])
    assert done.status == ScanStatus.DONE
    assert done.score == 100
    assert following.targets
    runs = scans.get_scanner_runs(pending.id)
    assert is_partial(runs)
    assert runs == [
        ScannerRun("broken", "TLS", "error", type(error).__name__, 0, NOW, NOW),
        ScannerRun("fake", "headers", "ok", None, 0, NOW, NOW),
    ]
    assert scans.get_findings(pending.id) == []


def test_all_failed_scanners_fail_the_scan(scans, targets, pending):
    failed = execute(scans, targets, pending.id, [FakeScanner(error=ValueError("secret"))])
    assert failed.status == ScanStatus.FAILED
    assert failed.error == "all scanners failed"
    assert failed.score is None
    assert scans.get_scanner_runs(pending.id)[0].error == "ValueError"
    assert not is_partial(scans.get_scanner_runs(pending.id))


def test_waf_network_failure_leaves_category_unevaluated(scans, targets, pending):
    import httpx
    import respx

    from app.infra.waf_rules_config import load_waf_rules
    from app.scanners.waf import WafScanner
    from app.scanners.wafw00f_probe import Wafw00fProbe
    from app.security.ssrf import create_safe_client
    from app.workers.jobs import CONFIG_DIR

    with respx.mock(assert_all_called=True) as router:
        router.get("https://example.com/").mock(side_effect=httpx.ConnectError("unreachable"))
        with create_safe_client() as client:
            waf = WafScanner(Wafw00fProbe(client), load_waf_rules(CONFIG_DIR / "waf_rules.yaml"))
            done = execute(scans, targets, pending.id, [waf, FakeScanner()])
    runs = scans.get_scanner_runs(done.id)
    assert done.status is ScanStatus.DONE
    assert done.score == 100
    assert is_partial(runs)
    assert runs[0].scanner == "waf"
    assert runs[0].status == "error"
    assert runs[0].error == "ConnectError"
    assert scans.get_findings(done.id) == []
    report = score([], DEFAULT_POLICY, runs)
    category = next(c for c in report.categories if c.category == "Pare-feu applicatif")
    assert category.score is None
    assert category.grade is None
    assert category.deductions == ()


def test_invalid_scanner_output_is_isolated(scans, targets, pending):
    done = execute(
        scans,
        targets,
        pending.id,
        [
            FakeScanner([None], name="broken"),
            FakeScanner(),
        ],
    )
    assert done.status == ScanStatus.DONE
    assert scans.get_scanner_runs(pending.id)[0].error == "TypeError"
    assert scans.get_findings(pending.id) == []


def test_no_scanners_fail_the_scan(scans, targets, pending):
    failed = execute(scans, targets, pending.id)
    assert failed.status == ScanStatus.FAILED
    assert failed.error == "no scanners configured"


def test_infrastructure_error_propagates_and_leaves_running(scans, targets, pending, monkeypatch):
    def broken_storage(*args):
        raise RuntimeError("database down")

    scanner = FakeScanner()
    original = scans.replace_scanner_runs

    def fail_on_results(scan_id, runs):
        if runs:
            broken_storage()
        original(scan_id, runs)

    monkeypatch.setattr(scans, "replace_scanner_runs", fail_on_results)
    with pytest.raises(RuntimeError, match="database down"):
        execute(scans, targets, pending.id, [scanner])
    assert scans.get(pending.id).status == ScanStatus.RUNNING


def test_execution_rechecks_target_verification(scans, targets, target, pending):
    targets.targets[target.id] = replace(target, verified_at=None)
    scanner = FakeScanner()
    failed = execute(scans, targets, pending.id, [scanner])
    assert failed.status == ScanStatus.FAILED
    assert failed.error == "target not verified"
    assert scanner.targets == []


def test_execution_without_target_fails(scans, targets, target, pending):
    del targets.targets[target.id]
    failed = execute(scans, targets, pending.id)
    assert failed.error == "target not found"


def test_unknown_scan_raises(scans, targets):
    with pytest.raises(ScanNotFoundError):
        execute(scans, targets, uuid.uuid4())
