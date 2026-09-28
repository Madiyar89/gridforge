"""Роль для SSH-консоли (см. console_ws._authenticate): консоль даёт
интерактивный доступ к оборудованию, поэтому порог тот же, что и у
запуска Action (api_write, только admin) — не ниже, раз она даже более
прямой путь выполнить произвольную команду на узле, чем Action.

WebSocket-хендлер целиком (handle_console) здесь не тестируется —
приемлемо, он всего лишь маршрутизирует к _authenticate и к asyncssh;
именно проверка роли — та часть, где легко ошибиться, и она вынесена в
обычную async-функцию, тестируемую без установления настоящего
WebSocket-соединения."""

import asyncio

import pytest

from app.auth import generate_key
from app.console_ws import _authenticate
from app.models import ApiKeyRole


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def viewer_key(db):
    return generate_key(db, label="test-console-viewer", role=ApiKeyRole.viewer)


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="test-console-operator", role=ApiKeyRole.operator)


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-console-admin", role=ApiKeyRole.admin)


def test_missing_api_key_rejected():
    assert _run(_authenticate({})) == "api_key обязателен"


def test_unknown_key_rejected():
    assert _run(_authenticate({"api_key": "does-not-exist"})) == "неверный или отозванный API-ключ"


def test_viewer_key_rejected(viewer_key):
    error = _run(_authenticate({"api_key": viewer_key}))
    assert error is not None
    assert "admin" in error


def test_operator_key_rejected(operator_key):
    """Операции на узлах (бэкап/аудит/скан) идут через api_operate, но
    интерактивная SSH-консоль — не одна из них, ей нужна та же планка,
    что у /api/actions (api_write)."""
    error = _run(_authenticate({"api_key": operator_key}))
    assert error is not None
    assert "admin" in error


def test_admin_key_accepted(admin_key):
    assert _run(_authenticate({"api_key": admin_key})) is None


def test_revoked_admin_key_rejected(db, admin_key):
    from app.auth import _hash_key
    from app.models import ApiKey

    key_row = db.query(ApiKey).filter(ApiKey.key_hash == _hash_key(admin_key)).one()
    key_row.revoked = True
    db.commit()

    error = _run(_authenticate({"api_key": admin_key}))
    assert error == "неверный или отозванный API-ключ"
