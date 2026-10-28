"""Fausses implémentations de ports partagées par plusieurs dossiers de tests."""


class FakeTxtResolver:
    def __init__(self, records: list[str] | None = None, error: Exception | None = None):
        self.records = records if records is not None else []
        self.error = error
        self.calls: list[str] = []

    def txt_records(self, name: str) -> list[str]:
        self.calls.append(name)
        if self.error is not None:
            raise self.error
        return self.records


class FakeScanQueue:
    def __init__(self, error=None):
        self.scan_ids = []
        self.error = error

    def enqueue(self, scan_id):
        self.scan_ids.append(scan_id)
        if self.error is not None:
            raise self.error


class FakeScanner:
    name = "fake"
    category = "headers"

    def __init__(self, findings=(), error=None, delay=0, name="fake", category="headers"):
        self.name = name
        self.category = category
        self.findings = list(findings)
        self.error = error
        self.delay = delay
        self.targets = []

    def run(self, target):
        import time

        self.targets.append(target)
        if self.delay:
            time.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return self.findings
