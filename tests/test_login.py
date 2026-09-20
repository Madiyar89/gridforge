"""Вход по логину и паролю: сессии, встроенная учётка, права."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import ApiKeyRole, Group, Node, Session as SessionRow, User
from app.passwords import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    hash_password,
    is_default_password,
    password_problem,
    verify_password,
)
from app.sessions import COOKIE_NAME, bootstrap_first_user, resolve_session, revoke_all_for_user


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def user(db):
    u = User(username="петров", password_hash=hash_password("длинный-пароль-1"), role=ApiKeyRole.admin)
    db.add(u)
    db.commit()
    return u


# --- хеширование ---


def test_hash_is_not_the_password_itself():
    stored = hash_password("секретный-пароль")
    assert "секретный-пароль" not in stored
    assert stored.startswith("scrypt$")


def test_same_password_hashes_differently_each_time():
    """Соль на каждый пароль: иначе одинаковые пароли двух людей были бы
    видны как одинаковые хеши."""
    assert hash_password("одинаковый-пароль") != hash_password("одинаковый-пароль")


def test_verify_accepts_right_and_rejects_wrong():
    stored = hash_password("правильный-пароль")
    assert verify_password("правильный-пароль", stored)
    assert not verify_password("неправильный-пароль", stored)


def test_corrupted_hash_is_rejected_not_crashing():
    """Кривая строка в БД — это «не совпало», а не исключение: иначе одна
    испорченная запись ломала бы вход целиком."""
    assert not verify_password("любой", "мусор")
    assert not verify_password("любой", "")


def test_short_password_rejected():
    assert password_problem("коротк") is not None
    assert password_problem("достаточно-длинный-пароль") is None


# --- встроенная учётка ---


def test_bootstrap_creates_admin_only_once(db):
    assert bootstrap_first_user(db) is True
    assert bootstrap_first_user(db) is False  # второй раз не дублирует
    users = db.query(User).all()
    assert len(users) == 1
    assert users[0].username == DEFAULT_ADMIN_USERNAME
    assert users[0].role is ApiKeyRole.admin


def test_default_password_is_detectable(db):
    bootstrap_first_user(db)
    admin = db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
    assert is_default_password(admin.password_hash)

    admin.password_hash = hash_password("свой-надёжный-пароль")
    db.commit()
    assert not is_default_password(admin.password_hash)


def test_login_with_builtin_credentials_works(client, db):
    bootstrap_first_user(db)
    resp = client.post("/api/login", json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD})
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_whoami_warns_about_default_password(client, db):
    bootstrap_first_user(db)
    client.post("/api/login", json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD})
    assert client.get("/api/whoami").json()["default_password"] is True


# --- вход и сессия ---


def test_login_sets_httponly_cookie(client, user):
    resp = client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    assert resp.status_code == 200
    cookie_header = resp.headers["set-cookie"]
    assert "httponly" in cookie_header.lower()  # JavaScript не достанет — XSS не украдёт сессию
    assert "samesite=lax" in cookie_header.lower()


def test_session_grants_access_without_api_key(client, user):
    assert client.get("/api/nodes").status_code == 401  # до входа
    client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    assert client.get("/api/nodes").status_code == 200  # после входа, без X-API-Key


def test_wrong_password_rejected(client, user):
    resp = client.post("/api/login", json={"username": "петров", "password": "неверный-пароль"})
    assert resp.status_code == 401


def test_unknown_user_gives_same_error_as_wrong_password(client, user):
    """Ответ не должен подсказывать, существует ли логин."""
    wrong_pass = client.post("/api/login", json={"username": "петров", "password": "неверный"})
    no_user = client.post("/api/login", json={"username": "нет-такого", "password": "неверный"})
    assert wrong_pass.status_code == no_user.status_code == 401
    assert wrong_pass.json()["detail"] == no_user.json()["detail"]


def test_inactive_user_cannot_login(client, db, user):
    user.active = False
    db.commit()
    assert client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"}).status_code == 401


def test_logout_kills_the_session(client, user):
    client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    assert client.get("/api/nodes").status_code == 200
    client.post("/api/logout")
    assert client.get("/api/nodes").status_code == 401


def test_session_token_is_not_stored_in_plain_text(client, db, user):
    """Утёкшая копия БД не должна давать возможность войти чужой сессией."""
    resp = client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    raw_token = resp.cookies[COOKIE_NAME]
    stored = db.query(SessionRow).all()
    assert len(stored) == 1
    assert stored[0].token_hash != raw_token
    assert raw_token not in stored[0].token_hash


def test_garbage_cookie_is_rejected(client, user):
    # Токен ASCII-мусором, как и выглядел бы подделанный: значения кук по
    # HTTP не бывают кириллическими.
    client.cookies.set(COOKIE_NAME, "forged-token-not-in-database")
    assert client.get("/api/nodes").status_code == 401


def test_expired_session_is_rejected_and_cleaned(db, user):
    from datetime import timedelta

    from app.models import _now
    from app.sessions import _hash_token

    db.add(SessionRow(token_hash=_hash_token("старый"), user_id=user.id, expires_at=_now() - timedelta(days=1)))
    db.commit()

    assert resolve_session(db, "старый") is None
    assert db.query(SessionRow).count() == 0  # протухшая запись убрана, а не копится


# --- права и смена пароля ---


def test_role_from_session_is_enforced(client, db):
    viewer = User(username="смотритель", password_hash=hash_password("длинный-пароль-2"), role=ApiKeyRole.viewer)
    db.add(viewer)
    db.commit()
    client.post("/api/login", json={"username": "смотритель", "password": "длинный-пароль-2"})

    assert client.get("/api/nodes").status_code == 200
    assert client.post("/api/nodes", json={"name": "x", "address": "1.1.1.1"}).status_code == 403


def test_group_scope_from_session_is_enforced(client, db):
    """Ограничение по группе должно работать одинаково для входа по
    паролю и по ключу — иначе два пути входа разъедутся в правах."""
    own = Group(name="своя")
    other = Group(name="чужая")
    db.add_all([own, other])
    db.commit()
    db.add(Node(name="свой-узел", address="10.0.0.1", group_id=own.id))
    db.add(Node(name="чужой-узел", address="10.0.0.2", group_id=other.id))
    scoped = User(
        username="ограниченный",
        password_hash=hash_password("длинный-пароль-3"),
        role=ApiKeyRole.admin,
        group_id=own.id,
    )
    db.add(scoped)
    db.commit()

    client.post("/api/login", json={"username": "ограниченный", "password": "длинный-пароль-3"})
    names = [n["name"] for n in client.get("/api/nodes").json()]
    assert names == ["свой-узел"]


def test_password_change_closes_open_sessions(client, db, user):
    """Смена пароля обязана выгнать уже вошедших — иначе тот, из-за кого
    её делают, остался бы внутри."""
    client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    assert client.get("/api/nodes").status_code == 200

    revoke_all_for_user(db, user.id)
    assert client.get("/api/nodes").status_code == 401


def test_create_user_rejects_weak_password(client, db):
    admin = User(username="начальник", password_hash=hash_password("длинный-пароль-4"), role=ApiKeyRole.admin)
    db.add(admin)
    db.commit()
    client.post("/api/login", json={"username": "начальник", "password": "длинный-пароль-4"})

    resp = client.post("/api/users", json={"username": "новичок", "password": "123"})
    assert resp.status_code == 422


def test_user_list_never_exposes_password_hashes(client, db, user):
    client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    listed = client.get("/api/users").json()
    assert listed
    assert "password_hash" not in str(listed)
    assert "scrypt$" not in str(listed)
