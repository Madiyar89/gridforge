"""SSH-консоль в браузере — WebSocket-мост между xterm.js на клиенте и
интерактивной PTY-сессией asyncssh на сервере. Свой велосипед вместо
Guacamole: последняя проксирует RDP/VNC/SSH через отдельный демон (guacd)
по собственному бинарному протоколу — переписать RDP с нуля за разумное
время нереально (сложный бинарный протокол, десятки RFC), поэтому здесь
сознательно только SSH, где протокол уже есть готовый (asyncssh),
достаточно смонтировать его на WebSocket.

Протокол поверх WebSocket (текстовые JSON-сообщения от клиента, кроме
{"type":"data"} — остальное тоже JSON, ответы сервера тоже JSON):
  клиент -> сервер:
    {"type": "connect", "api_key": "...", "node_id": 1, "username": "...",
     "key_path": "..." | "password": "...", "port": 22, "cols": 80, "rows": 24}
    {"type": "data", "data": "<нажатые символы>"}
    {"type": "resize", "cols": 80, "rows": 24}
  сервер -> клиент:
    {"type": "connected"}
    {"type": "data", "data": "<вывод с узла>"}
    {"type": "error", "message": "..."}
    {"type": "closed"}
"""

from __future__ import annotations

import asyncio
import json

import asyncssh
from fastapi import WebSocket, WebSocketDisconnect

from app.auth import ROLE_RANK, _hash_key  # переиспользуем ровно ту же проверку ключа, что и HTTP API
from app.credentials_engine import resolve_credential
from app.db import get_session
from app.models import ApiKey, ApiKeyRole, Node
from app.ssh_client import HostKeyRejected, open_ssh_connection

# Минимальная роль для SSH-консоли — та же граница, что и у /api/actions
# (api_write в main.py, только admin): запуск Action и интерактивная
# SSH-консоль обе дают произвольные команды на живом оборудовании, а
# консоль — даже более прямой путь к этому, чем Action, поэтому ей не
# место ниже той же планки.
MIN_CONSOLE_ROLE = ApiKeyRole.admin


async def _authenticate(payload: dict) -> str | None:
    """Возвращает None, если ключ валиден И его роли достаточно для
    SSH-консоли, иначе текст ошибки. Проверка ключа — та же, что
    require_api_key в auth.py, но без HTTP-зависимостей FastAPI
    (WebSocket — не обычный запрос); проверка роли — тот же ROLE_RANK,
    что require_admin_key использует на HTTP-стороне (см. auth.py)."""
    api_key = payload.get("api_key")
    if not api_key:
        return "api_key обязателен"
    db = get_session()
    try:
        key = db.query(ApiKey).filter(ApiKey.key_hash == _hash_key(api_key), ApiKey.revoked.is_(False)).first()
        if key is None:
            return "неверный или отозванный API-ключ"
        if ROLE_RANK[key.role] < ROLE_RANK[MIN_CONSOLE_ROLE]:
            return "недостаточно прав — SSH-консоль требует роль admin"
        return None
    finally:
        db.close()


async def handle_console(ws: WebSocket) -> None:
    await ws.accept()
    try:
        raw = await ws.receive_text()
        payload = json.loads(raw)
    except (json.JSONDecodeError, WebSocketDisconnect):
        await ws.close(code=1002)
        return

    if payload.get("type") != "connect":
        await ws.send_json({"type": "error", "message": "первое сообщение должно быть {type: connect}"})
        await ws.close(code=1002)
        return

    auth_error = await _authenticate(payload)
    if auth_error:
        await ws.send_json({"type": "error", "message": auth_error})
        await ws.close(code=1008)
        return

    node_id = payload.get("node_id")
    db = get_session()
    try:
        node = db.get(Node, node_id)
        username = payload.get("username")
        key_path = payload.get("key_path")
        password = payload.get("password")
        if not username:
            # Явной учётки нет — та же центральная учётка (Credential), что
            # использует HTTP-часть API (см. credentials_engine.py).
            cred = resolve_credential(db, node) if node is not None else None
            if cred is not None:
                username, password, key_path = cred["username"], cred["password"], cred["key_path"]
    finally:
        db.close()
    if node is None:
        await ws.send_json({"type": "error", "message": "Node не найден"})
        await ws.close(code=1002)
        return

    if not username:
        await ws.send_json({
            "type": "error",
            "message": "нужен логин — укажи явно или настрой центральную учётку в Настройки → Учётки",
        })
        await ws.close(code=1002)
        return

    if not key_path and not password:
        await ws.send_json({"type": "error", "message": "нужен key_path или password"})
        await ws.close(code=1002)
        return

    cols, rows = int(payload.get("cols", 80)), int(payload.get("rows", 24))

    # TOFU по Node.ssh_host_key_fingerprint — та же единая точка
    # проверки host key, что и у Probe/Action (см. ssh_client.py). node
    # уже загружен выше (сессия, которой он был загружен, уже закрыта,
    # но плоские колонки, включая fingerprint, доступны и после этого);
    # сохранение нового fingerprint открывает свою короткую сессию по id.
    def _get_fingerprint() -> str | None:
        return node.ssh_host_key_fingerprint

    def _store_fingerprint(fingerprint: str) -> None:
        write_db = get_session()
        try:
            fresh = write_db.get(Node, node.id)
            if fresh is not None:
                fresh.ssh_host_key_fingerprint = fingerprint
                write_db.commit()
        finally:
            write_db.close()

    try:
        conn = await open_ssh_connection(
            host=node.address,
            port=int(payload.get("port", 22)),
            username=username,
            timeout_seconds=10,
            key_path=key_path,
            password=password,
            host_key_fingerprint_getter=_get_fingerprint,
            host_key_fingerprint_setter=_store_fingerprint,
        )
    except (asyncssh.Error, OSError, HostKeyRejected) as exc:
        await ws.send_json({"type": "error", "message": str(exc) or exc.__class__.__name__})
        await ws.close(code=1011)
        return

    try:
        process = await conn.create_process(term_type="xterm-256color", term_size=(cols, rows))
    except asyncssh.Error as exc:
        await ws.send_json({"type": "error", "message": f"не удалось открыть сессию: {exc}"})
        conn.close()
        await ws.close(code=1011)
        return

    await ws.send_json({"type": "connected"})

    async def pump_ssh_to_ws() -> None:
        try:
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                await ws.send_json({"type": "data", "data": chunk})
        except (asyncssh.Error, ConnectionResetError):
            pass

    ssh_to_ws_task = asyncio.create_task(pump_ssh_to_ws())
    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            if msg.get("type") == "data":
                process.stdin.write(msg.get("data", ""))
            elif msg.get("type") == "resize":
                try:
                    process.change_terminal_size(int(msg["cols"]), int(msg["rows"]))
                except (KeyError, ValueError, asyncssh.Error):
                    pass
    except (WebSocketDisconnect, json.JSONDecodeError):
        pass
    finally:
        ssh_to_ws_task.cancel()
        process.stdin.write_eof()
        conn.close()
        try:
            await ws.send_json({"type": "closed"})
        except Exception:
            pass
