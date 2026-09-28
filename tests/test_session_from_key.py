"""Обмен API-ключа на куку входа для браузерного UI (см. POST
/api/session/from-key в app/main.py) — придумано затем, чтобы
static/common.js больше не хранил сырой ключ в localStorage, откуда его
мог прочитать любой XSS где угодно на 32 страницах.

Куку выдаёт тот же COOKIE_NAME, что и вход по паролю (/api/login), но
через отдельную таблицу ApiKeySession (см. models.py) — у API-ключа нет
User, к которому обычная Session могла бы привязаться. auth.require_api_key
при чтении куки проверяет сначала Session (пароль/AD/OIDC), потом
ApiKeySession — так права не расходятся между способами входа."""

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKey, ApiKeyRole
from app.sessions import COOKIE_NAME


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def viewer_key(db):
    return generate_key(db, label="test-viewer", role=ApiKeyRole.viewer)


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="test-operator", role=ApiKeyRole.operator)


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


# --- обмен ключа на куку ---


def test_exchange_sets_httponly_secure_cookie(client, admin_key):
    resp = client.post("/api/session/from-key", json={"api_key": admin_key})
    assert resp.status_code == 200
    cookie_header = resp.headers["set-cookie"]
    assert "httponly" in cookie_header.lower()
    assert "samesite=lax" in cookie_header.lower()
    # secure ВЫКЛЮЧЕН по умолчанию — см. COOKIE_SECURE в app/sessions.py и
    # test_login.py::test_login_sets_httponly_cookie/
    # test_login_cookie_secure_when_enabled (тот же флаг, та же причина).
    assert "secure" not in cookie_header.lower()
    assert resp.json()["role"] == "admin"


def test_exchange_cookie_secure_when_enabled(client, admin_key, monkeypatch):
    monkeypatch.setattr("app.main.COOKIE_SECURE", True)
    resp = client.post("/api/session/from-key", json={"api_key": admin_key})
    assert resp.status_code == 200
    cookie_header = resp.headers["set-cookie"]
    assert "secure" in cookie_header.lower()


def test_exchanged_cookie_authenticates_at_correct_role(client, viewer_key, operator_key, admin_key):
    for raw_key, expected_role in [(viewer_key, "viewer"), (operator_key, "operator"), (admin_key, "admin")]:
        c = TestClient(app, base_url="https://testserver")
        c.post("/api/session/from-key", json={"api_key": raw_key})
        me = c.get("/api/whoami").json()
        assert me["role"] == expected_role
        assert me["kind"] == "api_key"


def test_exchanged_viewer_cookie_cannot_write(client, viewer_key):
    client.post("/api/session/from-key", json={"api_key": viewer_key})
    resp = client.post("/api/groups", json={"name": "test-group"})
    assert resp.status_code == 403  # кука валидна, роли не хватает — не 401


def test_invalid_key_rejected_no_cookie_set(client):
    resp = client.post("/api/session/from-key", json={"api_key": "does-not-exist"})
    assert resp.status_code == 401
    assert COOKIE_NAME not in resp.cookies


def test_revoked_key_rejected(client, db, admin_key):
    key_row = db.query(ApiKey).filter_by(label="test-admin").one()
    key_row.revoked = True
    db.commit()

    resp = client.post("/api/session/from-key", json={"api_key": admin_key})
    assert resp.status_code == 401
    assert client.get("/api/nodes").status_code == 401  # без куки, без заголовка


# --- заголовок X-API-Key остаётся полностью рабочим (регресс) ---


def test_header_path_unaffected_by_exchange_endpoint(client, admin_key):
    resp = client.get("/api/groups", headers={"X-API-Key": admin_key})
    assert resp.status_code == 200


# --- logout снимает куку независимо от её происхождения ---


def test_logout_clears_key_exchanged_cookie(client, admin_key):
    client.post("/api/session/from-key", json={"api_key": admin_key})
    assert client.get("/api/nodes").status_code == 200

    client.post("/api/logout")
    assert client.get("/api/nodes").status_code == 401


def test_logout_does_not_revoke_the_underlying_api_key(client, db, admin_key):
    """Выход из браузера — не повод молча гасить ключ, которым может
    пользоваться что-то ещё (скрипт, интеграция) — только кука."""
    client.post("/api/session/from-key", json={"api_key": admin_key})
    client.post("/api/logout")

    key_row = db.query(ApiKey).filter_by(label="test-admin").one()
    assert key_row.revoked is False
    # ключ сам по себе по-прежнему работает через заголовок
    assert client.get("/api/groups", headers={"X-API-Key": admin_key}).status_code == 200


# --- один и тот же код чтения куки для обоих происхождений (не два
# расходящихся пути) ---


def test_user_login_cookie_and_key_exchange_cookie_share_the_read_path(client, db, admin_key):
    """Один и тот же require_api_key читает gridforge_session и для входа
    по паролю, и для куки, обмененной из API-ключа — здесь просто
    проверяется, что оба варианта дают доступ на одном и том же клиенте
    без каких-либо специальных веток на стороне теста."""
    from app.models import User
    from app.passwords import hash_password

    db.add(User(username="кука-тест", password_hash=hash_password("длинный-пароль-1"), role=ApiKeyRole.admin))
    db.commit()

    # Вход по паролю
    user_client = TestClient(app, base_url="https://testserver")
    user_client.post("/api/login", json={"username": "кука-тест", "password": "длинный-пароль-1"})
    assert user_client.get("/api/whoami").json()["kind"] == "user"

    # Вход обменом ключа — другой клиент, чтобы не спутать куки
    key_client = TestClient(app, base_url="https://testserver")
    key_client.post("/api/session/from-key", json={"api_key": admin_key})
    assert key_client.get("/api/whoami").json()["kind"] == "api_key"

    # Оба одинаково проходят require_admin_key-эндпоинт
    assert user_client.post("/api/groups", json={"name": "g1"}).status_code == 201
    assert key_client.post("/api/groups", json={"name": "g2"}).status_code == 201
