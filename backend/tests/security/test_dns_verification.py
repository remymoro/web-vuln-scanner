from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from app.domain.ports import TxtRecordResolver
from app.domain.targets import DnsLookupError
from app.security.dns_verification import DnspythonTxtResolver


class FakeResolver:
    def __init__(self, records=(), error=None):
        self.records = records
        self.error = error
        self.calls = []

    def resolve(self, name, record_type, *, search):
        self.calls.append((name, record_type, search))
        if self.error is not None:
            raise self.error
        return [SimpleNamespace(strings=record) for record in self.records]


def test_txt_records_join_chunks_and_decode_utf8():
    fake = FakeResolver([(b"scanner-", b"verify=token"), (b"caf\xc3", b"\xa9"), (b"bad\xff",)])
    resolver: TxtRecordResolver = DnspythonTxtResolver(fake)
    assert resolver.txt_records("www.example.com") == ["scanner-verify=token", "café", "bad\ufffd"]
    assert fake.calls == [("www.example.com.", "TXT", False)]
    assert fake.timeout == 3.0
    assert fake.lifetime == 5.0


def test_timeout_and_lifetime_are_configurable():
    fake = FakeResolver()
    DnspythonTxtResolver(fake, timeout=1.0, lifetime=2.0)
    assert fake.timeout == 1.0
    assert fake.lifetime == 2.0


@pytest.mark.parametrize("error", [None, dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])
def test_absent_txt_returns_empty_list(error):
    assert DnspythonTxtResolver(FakeResolver(error=error)).txt_records("example.com") == []


@pytest.mark.parametrize(
    "error",
    [
        dns.exception.Timeout(),
        dns.resolver.LifetimeTimeout(),
        dns.resolver.NoNameservers(),
        dns.exception.DNSException("broken"),
    ],
)
def test_dns_errors_are_translated(error):
    with pytest.raises(DnsLookupError) as caught:
        DnspythonTxtResolver(FakeResolver(error=error)).txt_records("example.com")
    assert caught.value.__cause__ is error
