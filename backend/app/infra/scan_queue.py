"""Adaptateur Redis/RQ du port ScanQueue."""

import uuid

from redis import Redis
from redis.exceptions import RedisError
from rq import Callback, Queue, Retry
from rq.exceptions import DuplicateJobError

from app.domain.scans import QueueUnavailableError


class RqScanQueue:
    def __init__(self, connection: Redis, scan_timeout_seconds: int) -> None:
        self._queue = Queue("scans", connection=connection)
        self._timeout = scan_timeout_seconds

    def enqueue(self, scan_id: uuid.UUID) -> None:
        try:
            self._queue.enqueue(
                "app.workers.jobs.run_scan",
                str(scan_id),
                job_id=f"scan-{scan_id}",
                unique=True,
                job_timeout=self._timeout,
                retry=Retry(max=2, interval=[10, 30]),
                on_failure=Callback("app.workers.jobs.on_scan_failure"),
            )
        except DuplicateJobError:
            return
        except RedisError as exc:
            raise QueueUnavailableError from exc
