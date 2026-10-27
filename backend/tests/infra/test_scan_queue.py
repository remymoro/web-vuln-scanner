import uuid

import pytest
from redis import Redis
from rq import Queue

from app.domain.scans import QueueUnavailableError
from app.infra.scan_queue import RqScanQueue
from app.workers.jobs import on_scan_failure


def test_enqueue_serializes_only_scan_id_and_configures_limits(redis_connection):
    scan_id = uuid.uuid4()
    queue = RqScanQueue(redis_connection, 42)
    queue.enqueue(scan_id)
    jobs = Queue("scans", connection=redis_connection).jobs
    assert len(jobs) == 1
    job = jobs[0]
    assert job.id == f"scan-{scan_id}"
    assert job.func_name == "app.workers.jobs.run_scan"
    assert job.args == (str(scan_id),)
    assert job.kwargs == {}
    assert job.timeout == 42
    assert job.retries_left == 2
    assert job.retry_intervals == [10, 30]
    assert job.failure_callback is on_scan_failure
    queue.enqueue(scan_id)
    assert Queue("scans", connection=redis_connection).count == 1


def test_unreachable_redis_is_translated():
    with Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.1) as connection:
        with pytest.raises(QueueUnavailableError):
            RqScanQueue(connection, 300).enqueue(uuid.uuid4())
