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
