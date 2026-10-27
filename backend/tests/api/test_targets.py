import uuid
from datetime import datetime

import pytest

from app.domain.targets import DnsLookupError
from tests.api.test_auth import login, register


def auth_headers(client, email="remy@example.test"):
    assert register(client, email=email).status_code == 201
    token = login(client, email=email).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def headers(client):
    return auth_headers(client)


def declare(client, headers, url="https://EXAMPLE.com:443/path"):
    return client.post("/targets", headers=headers, json={"url": url})


def test_declare_verify_and_get_target(client, headers, txt_resolver):
    response = declare(client, headers)
    assert response.status_code == 201
    body = response.json()
    target_id = body["id"]
    uuid.UUID(target_id)
    assert body == {
        "id": target_id,
        "domain": "example.com",
        "verified": False,
        "verified_at": None,
        "dns_record": {"type": "TXT", "name": "example.com", "value": body["dns_record"]["value"]},
    }
    assert body["dns_record"]["value"].startswith("scanner-verify=")
    assert txt_resolver.calls == []
    assert client.get("/targets", headers=headers).json() == [body]
    assert client.get(f"/targets/{target_id}", headers=headers).json() == body
    txt_resolver.records = ["unrelated", " \t" + body["dns_record"]["value"] + "\n"]
    response = client.post(f"/targets/{target_id}/verify", headers=headers)
    assert response.status_code == 200
    verified = response.json()
    assert verified == {**body, "verified": True, "verified_at": verified["verified_at"]}
    assert datetime.fromisoformat(verified["verified_at"]).tzinfo is not None
    assert txt_resolver.calls == ["example.com"]
    assert client.get(f"/targets/{target_id}", headers=headers).json() == verified
    assert client.get("/targets", headers=headers).json() == [verified]
    txt_resolver.error = DnsLookupError()
    assert client.post(f"/targets/{target_id}/verify", headers=headers).json() == verified
    assert txt_resolver.calls == ["example.com"]


def test_targets_are_isolated_between_users(client, headers, txt_resolver):
    target = declare(client, headers).json()
    other_headers = auth_headers(client, "other@example.test")
    assert client.get("/targets", headers=other_headers).json() == []
    path = f"/targets/{target['id']}"
    hidden = client.get(path, headers=other_headers)
    missing = client.get(f"/targets/{uuid.uuid4()}", headers=other_headers)
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()
    assert client.post(path + "/verify", headers=other_headers).status_code == 404
    assert client.post(f"/targets/{uuid.uuid4()}/verify", headers=other_headers).status_code == 404
    assert txt_resolver.calls == []
    other = declare(client, other_headers).json()
    assert other["id"] != target["id"]
    assert other["dns_record"]["value"] != target["dns_record"]["value"]
    assert client.get("/targets", headers=other_headers).json() == [other]
    assert client.get("/targets", headers=headers).json() == [target]


def test_missing_txt_returns_instructions_and_does_not_verify(client, headers):
    target = declare(client, headers).json()
    path = f"/targets/{target['id']}"
    response = client.post(path + "/verify", headers=headers)
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert target["dns_record"]["name"] in detail
    assert target["dns_record"]["value"] in detail
    assert client.get(path, headers=headers).json() == target


def test_parent_domain_proof_does_not_verify_subdomain(client, headers, txt_resolver):
    parent = declare(client, headers).json()
    subdomain = declare(client, headers, "www.example.com").json()
    txt_resolver.records = [parent["dns_record"]["value"]]
    assert client.post(f"/targets/{parent['id']}/verify", headers=headers).status_code == 200
    assert client.post(f"/targets/{subdomain['id']}/verify", headers=headers).status_code == 400
    assert txt_resolver.calls == ["example.com", "www.example.com"]


def test_dns_failure_returns_503_and_does_not_verify(client, headers, txt_resolver):
    target = declare(client, headers).json()
    txt_resolver.error = DnsLookupError("unreachable")
    path = f"/targets/{target['id']}"
    assert client.post(path + "/verify", headers=headers).status_code == 503
    assert client.get(path, headers=headers).json() == target


def test_duplicate_domain_is_a_conflict(client, headers):
    target = declare(client, headers).json()
    assert declare(client, headers, "example.com.").status_code == 409
    assert client.get("/targets", headers=headers).json() == [target]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"url": None},
        {"url": 123},
        {"url": ""},
        {"url": "localhost"},
        {"url": "ftp://example.com"},
        {"url": "https://127.0.0.1"},
        {"url": "https://user:pass@example.com"},
        {"url": "https://example.com:8080"},
        {"url": "under_score.example.com"},
    ],
)
def test_invalid_url_returns_422(client, headers, body):
    assert client.post("/targets", headers=headers, json=body).status_code == 422
    assert client.get("/targets", headers=headers).json() == []


def test_idn_domain_is_normalized(client, headers):
    response = declare(client, headers, "https://BÜCHER.de/")
    assert response.status_code == 201
    assert response.json()["domain"] == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("post", "/targets", {"url": "example.com"}),
        ("get", "/targets", None),
        ("get", f"/targets/{uuid.uuid4()}", None),
        ("post", f"/targets/{uuid.uuid4()}/verify", None),
    ],
)
def test_all_routes_require_authentication(client, method, path, body, txt_resolver):
    response = client.request(method, path, json=body)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert txt_resolver.calls == []


def test_app_stores_injected_resolver(app, txt_resolver):
    assert app.state.txt_resolver is txt_resolver
