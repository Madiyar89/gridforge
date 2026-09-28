"""Вход через Active Directory.

Настоящего контроллера домена в тестах нет, поэтому сам LDAP-bind
подменяется. Проверяется то, что от него не зависит и где ошибиться
опаснее всего: отсечка пустого пароля, выбор роли, взаимодействие с
локальными учётками и то, что доменный пароль у нас не оседает.
"""

import pytest
from fastapi.testclient import TestClient

from app import ad_auth
from app.ad_auth import ad_enabled, check_ad_credentials, sync_ad_user
from app.main import app
from app.models import ApiKeyRole, User
from app.passwords import hash_password


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def ad_configured(monkeypatch):
    monkeypatch.setenv("GRIDFORGE_AD_SERVER", "dc.corp.test")
    monkeypatch.setenv("GRIDFORGE_AD_DOMAIN", "corp.test")


@pytest.fixture()
def ad_accepts_everything(monkeypatch, ad_configured):
    """Домен подтверждает любой НЕпустой пароль — так видно, что отказы
    ниже происходят по нашей логике, а не потому, что bind не прошёл."""
    monkeypatch.setattr("app.main.check_ad_credentials", lambda username, password: bool(password))


def test_ad_disabled_without_server(monkeypatch):
    monkeypatch.delenv("GRIDFORGE_AD_SERVER", raising=False)
    assert ad_enabled() is False
    assert check_ad_credentials("петров", "пароль") is False


def test_empty_password_never_reaches_the_server(ad_configured, monkeypatch):
    """Главная проверка модуля: LDAP bind с пустым паролем многие
    каталоги принимают как анонимный и отвечают успехом — так можно
    войти любым логином, не зная пароля. Пустой пароль обязан
    отвергаться ДО обращения к серверу."""
    def explode(*args, **kwargs):
        raise AssertionError("с пустым паролем до сервера доходить нельзя")

    monkeypatch.setattr(ad_auth.ldap3, "Connection", explode)
    assert check_ad_credentials("петров", "") is False
    assert check_ad_credentials("петров", None) is False


def test_empty_username_rejected(ad_configured, monkeypatch):
    monkeypatch.setattr(ad_auth.ldap3, "Connection", lambda *a, **k: pytest.fail("не должно вызываться"))
    assert check_ad_credentials("", "пароль") is False


def test_ldap_failure_is_just_a_refusal(ad_configured, monkeypatch):
    """Недоступный контроллер и неверный пароль для пользователя
    выглядят одинаково — исключение не должно всплывать наружу."""
    import ldap3

    def fail(*args, **kwargs):
        raise ldap3.core.exceptions.LDAPSocketOpenError("нет связи")

    monkeypatch.setattr(ad_auth.ldap3, "Connection", fail)
    assert check_ad_credentials("петров", "пароль") is False


def test_default_role_is_viewer(db, ad_configured, monkeypatch):
    monkeypatch.delenv("GRIDFORGE_AD_DEFAULT_ROLE", raising=False)
    user = sync_ad_user(db, "новичок")
    assert user.role is ApiKeyRole.viewer
    assert user.source == "ad"


def test_default_role_can_be_configured(db, ad_configured, monkeypatch):
    monkeypatch.setenv("GRIDFORGE_AD_DEFAULT_ROLE", "operator")
    assert sync_ad_user(db, "дежурный").role is ApiKeyRole.operator


def test_bad_default_role_falls_back_to_weakest(db, ad_configured, monkeypatch):
    """Опечатка в настройке не должна выдавать лишние права."""
    monkeypatch.setenv("GRIDFORGE_AD_DEFAULT_ROLE", "администратор")
    assert sync_ad_user(db, "кто-то").role is ApiKeyRole.viewer


def test_ad_user_has_no_local_password_hash(db, ad_configured):
    """Пароль остаётся в домене: утечка нашей базы не должна давать
    доменные учётки."""
    user = sync_ad_user(db, "доменный")
    assert user.password_hash == ""


def test_repeat_login_does_not_reset_assigned_role(db, ad_configured):
    """Роль назначает администратор GridForge — повторный вход через
    домен не должен сбрасывать её обратно в viewer."""
    user = sync_ad_user(db, "повышенный")
    user.role = ApiKeyRole.admin
    db.commit()

    again = sync_ad_user(db, "повышенный")
    assert again.role is ApiKeyRole.admin


def test_ad_login_creates_user_and_session(client, ad_accepts_everything):
    resp = client.post("/api/login", json={"username": "доменный-петров", "password": "доменный-пароль"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "viewer"
    assert client.get("/api/nodes").status_code == 200


def test_ad_login_with_empty_password_refused(client, ad_configured, monkeypatch):
    monkeypatch.setattr("app.main.check_ad_credentials", lambda username, password: bool(password))
    resp = client.post("/api/login", json={"username": "доменный-петров", "password": ""})
    assert resp.status_code == 401


def test_local_user_is_not_checked_against_ad(client, db, ad_accepts_everything):
    """Локальная учётка проверяется только своим паролем. Иначе домен,
    принимающий любой пароль, открывал бы и локального админа."""
    db.add(User(username="локальный", password_hash=hash_password("свой-пароль-1"), role=ApiKeyRole.admin))
    db.commit()

    wrong = client.post("/api/login", json={"username": "локальный", "password": "любой-другой"})
    assert wrong.status_code == 401

    right = client.post("/api/login", json={"username": "локальный", "password": "свой-пароль-1"})
    assert right.status_code == 200


def test_inactive_ad_user_cannot_login(client, db, ad_accepts_everything):
    db.add(User(username="уволенный", password_hash="", source="ad", role=ApiKeyRole.viewer, active=False))
    db.commit()

    resp = client.post("/api/login", json={"username": "уволенный", "password": "доменный-пароль"})
    assert resp.status_code == 401


def test_password_change_refused_for_ad_user(client, db, ad_accepts_everything):
    """Локальный пароль доменной учётке не завести: иначе у неё стало бы
    два разных пароля, и отзыв доступа в AD перестал бы закрывать вход
    в GridForge."""
    admin = User(username="начальник", password_hash=hash_password("свой-пароль-9"), role=ApiKeyRole.admin)
    ad_user = User(username="доменный2", password_hash="", source="ad", role=ApiKeyRole.viewer)
    db.add_all([admin, ad_user])
    db.commit()
    client.post("/api/login", json={"username": "начальник", "password": "свой-пароль-9"})

    resp = client.post(f"/api/users/{ad_user.id}/password", json={"password": "подменённый-пароль"})
    assert resp.status_code == 409
    db.refresh(ad_user)
    assert ad_user.password_hash == ""
