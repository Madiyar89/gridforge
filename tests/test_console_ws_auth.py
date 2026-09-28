"""Роль для SSH-консоли (см. console_ws._authenticate): консоль даёт
интерактивный доступ к оборудованию, поэтому порог тот же, что и у
запуска Action (api_write, только admin) — не ниже, раз она даже более
прямой путь выполнить произвольную команду на узле, чем Action.

WebSocket-хендлер целиком (handle_console) в основном не тестируется —
приемлемо, он всего лишь маршрутизирует к _authenticate и к asyncssh;
именно проверка роли — та часть, где легко ошибиться, и она вынесена в
обычную async-функцию, тестируемую без установления настоящего
WebSocket-соединения. Исключение — ветка обработки ошибки подключения
(TestConnectErrorMessages ниже): аудит 2026-09-28 нашёл, что
key_path приходит от клиента напрямую и раньше исходный текст ошибки
asyncssh/OSError уходил обратно клиенту как есть — а он ощутимо
отличается ("No such file or directory" vs "not a valid key" vs
handshake-ошибка), что даёт уже аутентифицированному admin оракул
существования/читаемости произвольных файлов на сервере. Эта часть
теста и защищает от регресса именно этого поведения."""

import asyncio
import logging

import pytest

from app.auth import generate_key
from app.console_ws import _authenticate, handle_console
from app.models import ApiKeyRole, Node


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


def test_missing_api_key_and_no_cookie_rejected():
    principal, error = _run(_authenticate({}))
    assert principal is None
    assert error == "нужен api_key или вход в систему"


# --- вход через куку хендшейка (браузер, см. console.js/common.js —
# api_key в сообщении connect больше не шлётся, только gridforge_session)
# ---


def test_user_session_cookie_grants_access(db):
    from app.models import User
    from app.passwords import hash_password
    from app.sessions import create_session

    admin_user = User(username="test-console-user", password_hash=hash_password("длинный-пароль-x"), role=ApiKeyRole.admin)
    db.add(admin_user)
    db.commit()
    token = create_session(db, admin_user)

    principal, error = _run(_authenticate({}, token))
    assert error is None
    assert principal is not None and principal.role == ApiKeyRole.admin


def test_user_session_cookie_below_admin_rejected(db):
    from app.models import User
    from app.passwords import hash_password
    from app.sessions import create_session

    viewer_user = User(
        username="test-console-viewer-user", password_hash=hash_password("длинный-пароль-y"), role=ApiKeyRole.viewer
    )
    db.add(viewer_user)
    db.commit()
    token = create_session(db, viewer_user)

    principal, error = _run(_authenticate({}, token))
    assert principal is None
    assert error is not None
    assert "admin" in error


def test_api_key_session_cookie_grants_access(db, admin_key):
    from app.auth import resolve_api_key
    from app.sessions import create_api_key_session

    key_row = resolve_api_key(db, admin_key)
    token = create_api_key_session(db, key_row)

    principal, error = _run(_authenticate({}, token))
    assert error is None
    assert principal is not None and principal.role == ApiKeyRole.admin


def test_garbage_cookie_rejected():
    principal, error = _run(_authenticate({}, "forged-token-not-in-database"))
    assert principal is None
    assert error == "нужен api_key или вход в систему"


def test_unknown_key_rejected():
    principal, error = _run(_authenticate({"api_key": "does-not-exist"}))
    assert principal is None
    assert error == "неверный или отозванный API-ключ"


def test_viewer_key_rejected(viewer_key):
    principal, error = _run(_authenticate({"api_key": viewer_key}))
    assert principal is None
    assert error is not None
    assert "admin" in error


def test_operator_key_rejected(operator_key):
    """Операции на узлах (бэкап/аудит/скан) идут через api_operate, но
    интерактивная SSH-консоль — не одна из них, ей нужна та же планка,
    что у /api/actions (api_write)."""
    principal, error = _run(_authenticate({"api_key": operator_key}))
    assert principal is None
    assert error is not None
    assert "admin" in error


def test_admin_key_accepted(admin_key):
    principal, error = _run(_authenticate({"api_key": admin_key}))
    assert error is None
    assert principal is not None and principal.role == ApiKeyRole.admin


def test_revoked_admin_key_rejected(db, admin_key):
    from app.auth import _hash_key
    from app.models import ApiKey

    key_row = db.query(ApiKey).filter(ApiKey.key_hash == _hash_key(admin_key)).one()
    key_row.revoked = True
    db.commit()

    principal, error = _run(_authenticate({"api_key": admin_key}))
    assert principal is None
    assert error == "неверный или отозванный API-ключ"


class FakeWebSocket:
    """Минимальная замена fastapi.WebSocket для теста ветки ошибки
    подключения — handle_console вызывает только эти методы до того, как
    соединение установлено. `.cookies` — пустой словарь, как у реального
    WebSocket без куки в хендшейке (тесты этого класса используют вход
    через api_key в теле сообщения, не куку)."""

    def __init__(self, connect_payload: dict):
        import json

        self._raw = json.dumps(connect_payload)
        self.sent: list[dict] = []
        self.closed_code: int | None = None
        self.cookies: dict[str, str] = {}

    async def accept(self) -> None:
        pass

    async def receive_text(self) -> str:
        return self._raw

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000) -> None:
        self.closed_code = code


@pytest.fixture()
def console_node(db):
    node = Node(name="test-console-node", address="10.0.0.99")
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


def _run_connect_with_error(monkeypatch, admin_key, node, key_path, exc):
    from app import console_ws

    async def _raise(*args, **kwargs):
        raise exc

    monkeypatch.setattr(console_ws, "open_ssh_connection", _raise)

    ws = FakeWebSocket({
        "type": "connect",
        "api_key": admin_key,
        "node_id": node.id,
        "username": "svc",
        "key_path": key_path,
    })
    _run(handle_console(ws))
    return ws


class TestConnectErrorMessages:
    """Регресс-тест на находку аудита 2026-09-28: key_path приходит от
    клиента напрямую (см. docstring модуля), поэтому исходный текст
    asyncssh/OSError-исключения при неудачном подключении раньше уходил
    клиенту как есть — а он отличается в зависимости от того, СУЩЕСТВУЕТ
    ли файл по этому пути на сервере, что даёт уже аутентифицированному
    admin оракул для перебора произвольных путей файловой системы.
    Теперь все причины неудачи SSH-подключения (кроме HostKeyRejected —
    это MITM-предупреждение, не связанное с key_path) схлопнуты в одно
    сообщение; настоящая причина уходит только в лог сервера."""

    def test_missing_key_file_generic_message(self, admin_key, console_node, monkeypatch):
        exc = FileNotFoundError("[Errno 2] No such file or directory: '/etc/shadow'")
        ws = _run_connect_with_error(monkeypatch, admin_key, console_node, "/etc/shadow", exc)
        errors = [m["message"] for m in ws.sent if m.get("type") == "error"]
        assert errors, "ожидалось хотя бы одно сообщение об ошибке"
        assert errors[-1] == "не удалось подключиться по SSH — подробности в логах сервера"
        assert "shadow" not in errors[-1]
        assert "No such file" not in errors[-1]

    def test_permission_denied_same_generic_message(self, admin_key, console_node, monkeypatch):
        """Тот же текст, что и для 'файла нет' — иначе разница между
        двумя сообщениями сама стала бы новым оракулом."""
        exc = PermissionError("[Errno 13] Permission denied: '/root/.ssh/id_rsa'")
        ws = _run_connect_with_error(monkeypatch, admin_key, console_node, "/root/.ssh/id_rsa", exc)
        errors = [m["message"] for m in ws.sent if m.get("type") == "error"]
        assert errors[-1] == "не удалось подключиться по SSH — подробности в логах сервера"

    def test_asyncssh_error_same_generic_message(self, admin_key, console_node, monkeypatch):
        import asyncssh

        exc = asyncssh.Error(2, "not a valid OpenSSH private key")
        ws = _run_connect_with_error(monkeypatch, admin_key, console_node, "/etc/hosts", exc)
        errors = [m["message"] for m in ws.sent if m.get("type") == "error"]
        assert errors[-1] == "не удалось подключиться по SSH — подробности в логах сервера"

    def test_connect_failure_reason_logged_server_side(self, admin_key, console_node, monkeypatch, caplog):
        exc = FileNotFoundError("[Errno 2] No such file or directory: '/etc/shadow'")
        with caplog.at_level(logging.WARNING, logger="gridforge.console_ws"):
            _run_connect_with_error(monkeypatch, admin_key, console_node, "/etc/shadow", exc)
        messages = [rec.getMessage() for rec in caplog.records]
        assert any("shadow" in m for m in messages), (
            "детальная причина должна попасть в серверный лог — иначе у "
            "админа не остаётся способа продиагностировать неудачное "
            "подключение вообще"
        )

    def test_host_key_rejected_message_preserved(self, admin_key, console_node, monkeypatch):
        """HostKeyRejected — не про key_path, это TOFU-предупреждение о
        несовпадении host key узла; текст остаётся детальным, как и
        раньше, схлопывание его касаться не должно."""
        from app.ssh_client import HostKeyRejected

        exc = HostKeyRejected("host key устройства изменился — возможен MITM")
        ws = _run_connect_with_error(monkeypatch, admin_key, console_node, "/some/key", exc)
        errors = [m["message"] for m in ws.sent if m.get("type") == "error"]
        assert errors[-1] == "host key устройства изменился — возможен MITM"
