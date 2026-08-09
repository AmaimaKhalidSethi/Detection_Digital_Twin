from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone
from jose import jwt

from app.core.auth import ALGORITHM, create_user, jwt_secret
from app.main import SessionLocal, app
from app.models.db import User


def _create_user(username="analyst@example.internal", password="correct-horse-battery-staple", role="analyst", is_active=True):
    with SessionLocal() as db:
        return create_user(db, username=username, password=password, role=role, is_active=is_active)


def _authenticated_client(monkeypatch, username="analyst@example.internal", password="correct-horse-battery-staple"):
    monkeypatch.setenv("DDT_AUTH_REQUIRED", "true")
    client = TestClient(app)
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return client, response.json()["csrf_token"]


def test_successful_user_creation_and_password_hashing():
    user = _create_user()
    assert user.username == "analyst@example.internal"
    assert user.role == "analyst"
    assert user.is_active is True
    assert user.password_hash != "correct-horse-battery-staple"
    assert user.password_hash.startswith("$2")


def test_duplicate_user_is_rejected():
    _create_user()
    with SessionLocal() as db:
        try:
            create_user(db, username="analyst@example.internal", password="another-secure-password")
        except ValueError as exc:
            assert str(exc) == "Username already exists"
        else:
            raise AssertionError("duplicate user was accepted")


def test_successful_login_and_me(monkeypatch):
    _create_user()
    client, _ = _authenticated_client(monkeypatch)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "analyst@example.internal"
    assert "password_hash" not in response.text


def test_login_rejects_wrong_password_and_unknown_account(monkeypatch):
    monkeypatch.setenv("DDT_AUTH_REQUIRED", "true")
    _create_user()
    client = TestClient(app)
    wrong = client.post("/auth/login", json={"username": "analyst@example.internal", "password": "wrong-password-value"})
    unknown = client.post("/auth/login", json={"username": "missing@example.internal", "password": "wrong-password-value"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "Invalid username or password"}


def test_inactive_account_cannot_login(monkeypatch):
    monkeypatch.setenv("DDT_AUTH_REQUIRED", "true")
    _create_user(is_active=False)
    response = TestClient(app).post("/auth/login", json={"username": "analyst@example.internal", "password": "correct-horse-battery-staple"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_protected_endpoint_rejects_unauthenticated_and_invalid_auth(monkeypatch):
    monkeypatch.setenv("DDT_AUTH_REQUIRED", "true")
    client = TestClient(app)
    assert client.get("/environments").status_code == 401
    assert client.get("/environments", headers={"Authorization": "Bearer not-a-token"}).status_code == 401


def test_protected_endpoint_rejects_expired_token(monkeypatch):
    monkeypatch.setenv("DDT_AUTH_REQUIRED", "true")
    user = _create_user()
    expired_token = jwt.encode(
        {"sub": user.id, "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
        jwt_secret(),
        algorithm=ALGORITHM,
    )
    response = TestClient(app).get("/environments", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401


def test_authenticated_analyst_can_access_detection_workflows(monkeypatch):
    _create_user()
    client, csrf_token = _authenticated_client(monkeypatch)
    assert client.get("/environments").status_code == 200
    response = client.post("/environments", json={"name": "SOC Lab"}, headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200


def test_authenticated_cookie_write_requires_csrf_token(monkeypatch):
    _create_user()
    client, _ = _authenticated_client(monkeypatch)
    response = client.post("/environments", json={"name": "SOC Lab"})
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed"


def test_logout_clears_session_and_protected_access(monkeypatch):
    _create_user()
    client, csrf_token = _authenticated_client(monkeypatch)
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token}).status_code == 200
    assert client.get("/auth/me").status_code == 401
    assert client.get("/environments").status_code == 401


def test_admin_and_analyst_roles_are_preserved_in_authenticated_identity(monkeypatch):
    _create_user(username="admin@example.internal", role="admin")
    _create_user(username="analyst@example.internal", role="analyst")
    admin_client, _ = _authenticated_client(monkeypatch, "admin@example.internal")
    assert admin_client.get("/auth/me").json()["user"]["role"] == "admin"
    analyst_client, _ = _authenticated_client(monkeypatch, "analyst@example.internal")
    assert analyst_client.get("/auth/me").json()["user"]["role"] == "analyst"
    with SessionLocal() as db:
        assert db.query(User).count() == 2
