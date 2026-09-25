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


# --- must_change_password: новым учёткам сразу нужна смена пароля
# (запрос пользователя, 2026-09-25) ---


def test_new_user_must_change_password_by_default(client, db, user):
    client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    client.post("/api/users", json={"username": "новичок2", "password": "временный-пароль-1"})
    listed = client.get("/api/users").json()
    new_user = next(u for u in listed if u["username"] == "новичок2")
    assert new_user["must_change_password"] is True


def test_whoami_reports_must_change_password_for_new_user(client, db):
    admin = User(username="начальник2", password_hash=hash_password("длинный-пароль-5"), role=ApiKeyRole.admin)
    db.add(admin)
    db.commit()
    client.post("/api/login", json={"username": "начальник2", "password": "длинный-пароль-5"})
    client.post("/api/users", json={"username": "новичок3", "password": "временный-пароль-2"})
    client.post("/api/logout")

    client.post("/api/login", json={"username": "новичок3", "password": "временный-пароль-2"})
    assert client.get("/api/whoami").json()["must_change_password"] is True


def test_admin_changing_users_password_clears_the_flag(client, db, user):
    client.post("/api/login", json={"username": "петров", "password": "длинный-пароль-1"})
    created = client.post("/api/users", json={"username": "новичок4", "password": "временный-пароль-3"}).json()
    client.post(f"/api/users/{created['id']}/password", json={"password": "новый-длинный-пароль"})
    listed = client.get("/api/users").json()
    assert next(u for u in listed if u["id"] == created["id"])["must_change_password"] is False


def test_self_service_password_change_available_to_viewer(client, db):
    """/api/me/password должен работать любой роли — viewer/operator не
    видят страницу «Пользователи» (require_admin_key), баннер «смени
    пароль» должен быть чем-то, что они реально могут сделать сами."""
    admin = User(username="начальник3", password_hash=hash_password("длинный-пароль-6"), role=ApiKeyRole.admin)
    db.add(admin)
    db.commit()
    client.post("/api/login", json={"username": "начальник3", "password": "длинный-пароль-6"})
    client.post("/api/users", json={"username": "смотритель2", "password": "временный-пароль-4", "role": "viewer"})
    client.post("/api/logout")

    client.post("/api/login", json={"username": "смотритель2", "password": "временный-пароль-4"})
    resp = client.post("/api/me/password", json={"password": "свой-новый-пароль-длинный"})
    assert resp.status_code == 200
    # Смена пароля закрывает и текущую сессию — дальше без повторного входа доступа быть не должно.
    assert client.get("/api/whoami").status_code == 401

    login_resp = client.post("/api/login", json={"username": "смотритель2", "password": "свой-новый-пароль-длинный"})
    assert login_resp.status_code == 200
    assert client.get("/api/whoami").json()["must_change_password"] is False


def test_self_service_rejects_api_key_principal(client, db):
    from app.auth import generate_key

    key = generate_key(db, label="скрипт", role=ApiKeyRole.admin)
    resp = client.post("/api/me/password", json={"password": "неважно-длинный-пароль"}, headers={"X-API-Key": key})
    assert resp.status_code == 400


# --- защита учётки Admin (запрос пользователя, 2026-09-25: "чтобы Admin
# учётку никто не видел и не мог её трогать") ---


def test_admin_account_hidden_from_other_admins(client, db):
    bootstrap_first_user(db)  # создаёт Admin
    other_admin = User(username="другой-админ", password_hash=hash_password("длинный-пароль-7"), role=ApiKeyRole.admin)
    db.add(other_admin)
    db.commit()

    client.post("/api/login", json={"username": "другой-админ", "password": "длинный-пароль-7"})
    listed = client.get("/api/users").json()
    assert DEFAULT_ADMIN_USERNAME not in [u["username"] for u in listed]


def test_admin_account_visible_to_itself(client, db):
    bootstrap_first_user(db)
    client.post("/api/login", json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD})
    listed = client.get("/api/users").json()
    assert DEFAULT_ADMIN_USERNAME in [u["username"] for u in listed]


def test_admin_account_cannot_be_deleted(client, db):
    bootstrap_first_user(db)
    admin_row = db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
    client.post("/api/login", json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD})
    resp = client.delete(f"/api/users/{admin_row.id}")
    assert resp.status_code == 403


def test_other_admin_cannot_change_admin_password(client, db):
    bootstrap_first_user(db)
    admin_row = db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
    other_admin = User(username="третий-админ", password_hash=hash_password("длинный-пароль-8"), role=ApiKeyRole.admin)
    db.add(other_admin)
    db.commit()

    client.post("/api/login", json={"username": "третий-админ", "password": "длинный-пароль-8"})
    resp = client.post(f"/api/users/{admin_row.id}/password", json={"password": "чужой-длинный-пароль"})
    assert resp.status_code == 403
