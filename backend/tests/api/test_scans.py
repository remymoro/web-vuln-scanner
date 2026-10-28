import uuid
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from rq import Queue, SimpleWorker
from rq.job import JobStatus
from sqlalchemy import select

from app.api.main import create_app
from app.domain.scans import QueueUnavailableError, Scan, ScanStatus
from app.domain.scoring import DEFAULT_POLICY, ScoringPolicy
from app.infra.models import ScanModel
from app.infra.scan_queue import RqScanQueue
from app.infra.scan_repository import SqlAlchemyScanRepository
from app.security.ssrf import SsrfBlockedError
from app.workers import jobs
from app.workers.jobs import WorkerRuntime
from tests.api.test_targets import auth_headers, declare
from tests.domain.test_scans import FINDING
from tests.fakes import FakeScanner


@pytest.fixture
def headers(client):
    return auth_headers(client)


@pytest.fixture
def target(client, headers, txt_resolver):
    target = declare(client, headers).json()
    txt_resolver.records = [target["dns_record"]["value"]]
    assert client.post(f"/targets/{target['id']}/verify", headers=headers).status_code == 200
    return target


def request_scan(client, headers, target_id):
    return client.post("/scans", headers=headers, json={"target_id": target_id})


def read_scan(client, headers, scan_id):
    response = client.get(f"/scans/{scan_id}", headers=headers)
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def worker(app, client, redis_connection, monkeypatch, settings):
    def configure(scanners):
        runtime = WorkerRuntime(app.state.session_factory, tuple(scanners), DEFAULT_POLICY)
        monkeypatch.setattr(jobs, "get_worker_runtime", lambda: runtime)
        monkeypatch.setattr(jobs, "get_worker_sessions", lambda: runtime.sessions)
        app.state.scan_queue = RqScanQueue(redis_connection, settings.scan_timeout_seconds)
        queue = Queue("scans", connection=redis_connection)
        return queue

    return configure


def work(redis_connection):
    SimpleWorker(["scans"], connection=redis_connection).work(burst=True)


def test_request_returns_pending_and_conflicts_if_already_active(
    client, headers, target, scan_queue
):
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 202
    body = response.json()
    assert body == {"id": body["id"], "status": "pending"}
    assert scan_queue.scan_ids == [uuid.UUID(body["id"])]
    pending = read_scan(client, headers, body["id"])
    assert pending["target_id"] == target["id"]
    assert pending["status"] == "pending"
    assert datetime.fromisoformat(pending["created_at"]).tzinfo is not None
    for field in ("started_at", "finished_at", "score", "grade", "error"):
        assert pending[field] is None
    assert request_scan(client, headers, target["id"]).status_code == 409
    assert len(scan_queue.scan_ids) == 1
    assert client.get(f"/scans/{body['id']}/report", headers=headers).status_code == 409


def test_missing_target_returns_404(client, headers, scan_queue):
    assert request_scan(client, headers, str(uuid.uuid4())).status_code == 404
    assert scan_queue.scan_ids == []


def test_unverified_target_returns_409(client, headers, scan_queue):
    target = declare(client, headers).json()
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 409
    assert response.json()["detail"] == "Target not verified"
    assert scan_queue.scan_ids == []


def test_queue_failure_is_compensated_and_releases_active_lock(
    client, app, headers, target, scan_queue
):
    scan_queue.error = QueueUnavailableError()
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 503
    scan_id = scan_queue.scan_ids[0]
    failed = read_scan(client, headers, scan_id)
    assert failed["status"] == "failed"
    assert failed["error"] == "queue unavailable"
    assert failed["finished_at"] is not None
    assert client.get(f"/scans/{scan_id}/report", headers=headers).status_code == 409
    scan_queue.error = None
    assert request_scan(client, headers, target["id"]).status_code == 202


def test_scan_is_committed_before_enqueue(client, app, headers, target):
    class ObservingQueue:
        def enqueue(self, scan_id):
            with app.state.session_factory() as session:
                assert SqlAlchemyScanRepository(session).get(scan_id).status == ScanStatus.PENDING

    app.state.scan_queue = ObservingQueue()
    assert request_scan(client, headers, target["id"]).status_code == 202


def test_users_cannot_request_or_read_other_users_scan(client, headers, target):
    scan_id = request_scan(client, headers, target["id"]).json()["id"]
    other = auth_headers(client, "other@example.test")
    assert request_scan(client, other, target["id"]).status_code == 404
    for suffix in ("", "/report"):
        hidden = client.get(f"/scans/{scan_id}{suffix}", headers=other)
        missing = client.get(f"/scans/{uuid.uuid4()}{suffix}", headers=other)
        assert hidden.status_code == missing.status_code == 404
        assert hidden.json() == missing.json()


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/scans", {"target_id": str(uuid.uuid4())}),
        ("get", f"/scans/{uuid.uuid4()}", None),
        ("get", f"/scans/{uuid.uuid4()}/report", None),
    ],
)
def test_routes_require_authentication(client, method, path, body, scan_queue):
    response = client.request(method, path, json=body)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert scan_queue.scan_ids == []


@pytest.mark.parametrize("body", [{}, {"target_id": "wrong"}, {"target_id": None}])
def test_invalid_body_returns_422(client, headers, body):
    assert client.post("/scans", headers=headers, json=body).status_code == 422


def test_abandoned_scan_can_be_replaced(client, app, headers, target, settings):
    scan_id = uuid.UUID(request_scan(client, headers, target["id"]).json()["id"])
    with app.state.session_factory() as session:
        scans = SqlAlchemyScanRepository(session)
        old = scans.get(scan_id).start(
            datetime.now(UTC) - timedelta(seconds=settings.scan_timeout_seconds + 61)
        )
        scans.save(old)
        session.commit()
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 202
    assert response.json()["id"] != str(scan_id)
    failed = read_scan(client, headers, scan_id)
    assert failed["status"] == "failed"
    assert failed["error"] == "abandoned"


def test_end_to_end_scan_and_report(client, app, headers, target, worker, redis_connection):
    class ObservingScanner(FakeScanner):
        def run(self, scan_target):
            with app.state.session_factory() as session:
                scan = session.scalar(select(ScanModel))
                assert scan.status == "running"
                assert scan.attempts == 1
            return super().run(scan_target)

    scanner = ObservingScanner([FINDING])
    queue = worker([scanner])
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 202
    scan_id = response.json()["id"]
    assert queue.count == 1
    work(redis_connection)
    done = read_scan(client, headers, scan_id)
    assert done["status"] == "done"
    assert done["score"] == 90
    assert done["grade"] == "A"
    assert done["error"] is None
    assert datetime.fromisoformat(done["started_at"]) <= datetime.fromisoformat(done["finished_at"])
    response = client.get(f"/scans/{scan_id}/report", headers=headers)
    assert response.status_code == 200
    report = response.json()
    assert report["score"] == 90
    assert report["grade"] == "A"
    assert report["findings"] == [asdict(FINDING)]
    assert report["deductions"] == [
        {"finding_id": FINDING.id, "category": "headers", "severity": "medium", "points": 10}
    ]
    assert report["categories"] == [
        {"category": "headers", "score": 90, "grade": "A", "deductions": report["deductions"]}
    ]
    assert scanner.targets[0].url == "https://example.com/"
    assert queue.finished_job_registry.count == 1
    assert request_scan(client, headers, target["id"]).status_code == 202


def test_timeout_is_terminal_without_retry(
    client, headers, target, worker, redis_connection, settings
):
    settings.scan_timeout_seconds = 1
    queue = worker([FakeScanner(delay=2)])
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 202
    scan_id = response.json()["id"]
    job = queue.jobs[0]
    work(redis_connection)
    failed = read_scan(client, headers, scan_id)
    assert failed["status"] == "failed"
    assert failed["error"] == "timeout"
    assert failed["finished_at"] is not None
    job.refresh()
    assert job.retries_left == 0
    assert job.get_status() == JobStatus.FAILED
    assert queue.scheduled_job_registry.count == 0
    assert queue.count == 0
    assert queue.failed_job_registry.count == 1


@pytest.mark.parametrize("error", [httpx.ConnectError("unreachable"), SsrfBlockedError("blocked")])
def test_target_errors_fail_without_rq_retry(
    client, headers, target, worker, redis_connection, error
):
    queue = worker([FakeScanner(error=error)])
    scan_id = request_scan(client, headers, target["id"]).json()["id"]
    work(redis_connection)
    failed = read_scan(client, headers, scan_id)
    assert failed["status"] == "failed"
    assert failed["error"] == f"target error: {type(error).__name__}"
    assert queue.scheduled_job_registry.count == 0
    assert queue.finished_job_registry.count == 1


def test_infrastructure_error_retries_then_marks_failed(
    client, app, headers, target, worker, redis_connection
):
    queue = worker([FakeScanner(error=RuntimeError("infrastructure down"))])
    scan_id = request_scan(client, headers, target["id"]).json()["id"]
    job = queue.jobs[0]
    for attempt in range(1, 4):
        work(redis_connection)
        job.refresh()
        with app.state.session_factory() as session:
            scan = SqlAlchemyScanRepository(session).get(uuid.UUID(scan_id))
        assert scan.attempts == attempt
        if attempt < 3:
            assert scan.status == ScanStatus.RUNNING
            assert queue.scheduled_job_registry.count == 1
            assert job.retries_left == 2 - attempt
            queue.scheduled_job_registry.requeue(job)
        else:
            assert scan.status == ScanStatus.FAILED
            assert scan.error == "worker error"
            assert queue.scheduled_job_registry.count == 0
            assert queue.failed_job_registry.count == 1


def test_retry_can_succeed_and_replace_previous_findings(
    client, app, headers, target, worker, redis_connection
):
    scanner = FakeScanner(error=RuntimeError("temporary infrastructure error"))
    queue = worker([scanner])
    scan_id = request_scan(client, headers, target["id"]).json()["id"]
    job = queue.jobs[0]
    work(redis_connection)
    with app.state.session_factory() as session:
        SqlAlchemyScanRepository(session).replace_findings(uuid.UUID(scan_id), [FINDING, FINDING])
        session.commit()
    scanner.error = None
    scanner.findings = [FINDING]
    queue.scheduled_job_registry.requeue(job)
    work(redis_connection)
    assert read_scan(client, headers, scan_id)["status"] == "done"
    report = client.get(f"/scans/{scan_id}/report", headers=headers).json()
    assert report["findings"] == [asdict(FINDING)]
    assert report["score"] == 90
    with app.state.session_factory() as session:
        assert SqlAlchemyScanRepository(session).get(uuid.UUID(scan_id)).attempts == 2


def test_report_uses_injected_policy(client, app, headers, target, worker, redis_connection):
    worker([FakeScanner([FINDING])])
    scan_id = request_scan(client, headers, target["id"]).json()["id"]
    work(redis_connection)
    penalties = {severity: 0 for severity in DEFAULT_POLICY.penalties}
    app.state.scoring_policy = ScoringPolicy(penalties, DEFAULT_POLICY.thresholds)
    report = client.get(f"/scans/{scan_id}/report", headers=headers).json()
    # La note globale reste celle enregistrée à la fin du scan ; le détail suit le barème actuel.
    assert (report["score"], report["grade"]) == (90, "A")
    assert read_scan(client, headers, scan_id)["score"] == 90
    assert report["deductions"][0]["points"] == 0


def test_factory_stores_injected_queue_and_policy(settings, scan_queue):
    policy = replace(DEFAULT_POLICY)
    app = create_app(settings, scan_queue=scan_queue, scoring_policy=policy)
    assert app.state.scan_queue is scan_queue
    assert app.state.scoring_policy is policy


def test_factory_builds_default_queue_and_loads_policy(settings):
    app = create_app(settings)
    assert isinstance(app.state.scan_queue, RqScanQueue)
    assert app.state.scoring_policy == DEFAULT_POLICY


def test_second_scan_within_cooldown_returns_429_with_retry_after(
    client, headers, target, worker, redis_connection, settings
):
    settings.scan_cooldown_seconds = 600
    worker([FakeScanner([])])
    assert request_scan(client, headers, target["id"]).status_code == 202
    work(redis_connection)
    response = request_scan(client, headers, target["id"])
    assert response.status_code == 429
    assert 1 <= int(response.headers["retry-after"]) <= 600


def test_target_history_is_empty_then_matches_scan_response(client, headers, target):
    path = f"/targets/{target['id']}/scans"
    assert client.get(path, headers=headers).json() == []
    scan_id = request_scan(client, headers, target["id"]).json()["id"]
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    assert response.json() == [read_scan(client, headers, scan_id)]


def test_target_history_is_limited_and_ordered(client, app, headers, target):
    now = datetime.now(UTC)
    scans = [
        replace(
            Scan.create(uuid.UUID(target["id"])), created_at=now - timedelta(seconds=index)
        ).fail("reason", now)
        for index in range(23)
    ]
    with app.state.session_factory() as session:
        repository = SqlAlchemyScanRepository(session)
        for scan in reversed(scans):
            repository.add(scan)
        session.commit()
    response = client.get(f"/targets/{target['id']}/scans", headers=headers)
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [str(scan.id) for scan in scans[:20]]


def test_target_history_requires_owner(client, headers, target):
    path = f"/targets/{target['id']}/scans"
    assert client.get(path).status_code == 401
    other = auth_headers(client, "other@example.test")
    hidden = client.get(path, headers=other)
    missing = client.get(f"/targets/{uuid.uuid4()}/scans", headers=other)
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()
