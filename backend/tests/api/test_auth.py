import base64
import uuid

import pytest
from sqlalchemy import text

from app.api.tokens import create_access_token

EMAIL = "remy@example.test"
PASSWORD = "correct horse battery"


def register(client, email=EMAIL, password=PASSWORD):
    return client.post("/auth/register", json={"email": email, "password": password})


def login(client, email=EMAIL, password=PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_register(client):
    response = register(client, email=" Remy@Example.TEST ")
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == EMAIL
    uuid.UUID(body["id"])
    assert "password" not in response.text


def test_register_duplicate_email_is_a_conflict(client):
    register(client)
    response = register(client, email="REMY@example.test")
    assert response.status_code == 409


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("not-an-email", PASSWORD),
        (EMAIL, "short"),
        (EMAIL, "a" * 129),
        ("a" * 321, PASSWORD),
    ],
)
def test_register_rejects_invalid_input(client, email, password):
    assert register(client, email, password).status_code == 422


def test_password_is_stored_hashed(client, migrated_engine):
    register(client)
    with migrated_engine.connect() as connection:
        stored = connection.scalar(text("SELECT password_hash FROM users"))
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_login_returns_a_working_bearer_token(client):
    user_id = register(client).json()["id"]
    response = login(client)
    assert response.status_code == 200
    token = response.json()
    assert token["token_type"] == "bearer"
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token['access_token']}"})
    assert me.status_code == 200
    assert me.json() == {"id": user_id, "email": EMAIL}


def test_wrong_password_and_unknown_email_get_the_same_answer(client):
    register(client)
    wrong_password = login(client, password="wrong password!")
    unknown_email = login(client, email="nobody@example.test")
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no-header"),
        pytest.param({"Authorization": "Bearer not.a.jwt"}, id="bad-token"),
        # Construit à l'exécution : un en-tête Basic écrit en dur ressemble à un vrai secret.
        pytest.param(
            {"Authorization": "Basic " + base64.b64encode(b"user:pass").decode()},
            id="wrong-scheme",
        ),
    ],
)
def test_me_requires_a_valid_token(client, headers):
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_token_of_a_deleted_user_is_rejected(client, settings):
    token = create_access_token(uuid.uuid4(), settings)
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
