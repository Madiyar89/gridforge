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

`api_key` в {type: connect} — не единственный способ входа: браузер
(console.js) его больше не отправляет вовсе (см. common.js — ключ в
localStorage не хранится) и полагается на куку gridforge_session, которую
сам браузер прикладывает к WebSocket-хендшейку на тот же origin — она
проверяется здесь так же, как в auth.require_api_key (сессия входа по
паролю ИЛИ кука, полученная обменом API-ключа на POST
/api/session/from-key). Заголовок/поле api_key остаётся рабочим отдельно
— для не-браузерных клиентов, которым неоткуда взять куку.
"""

from __future__ import annotations

import asyncio
import json
import logging

import asyncssh
from fastapi import HTTPException, WebSocket, WebSocketDisconnect

from app.auth import (  # переиспользуем ровно ту же проверку ключа/роли/области, что и HTTP API
    ROLE_RANK,
    Principal,
    require_node_access,
    resolve_api_key,
)
from app.credentials_engine import resolve_credential
from app.db import get_session
from app.models import ApiKeyRole, Node
from app.sessions import COOKIE_NAME, resolve_api_key_session, resolve_session
from app.ssh_client import HostKeyRejected, open_ssh_connection

logger = logging.getLogger("gridforge.console_ws")

# Минимальная роль для SSH-консоли — та же граница, что и у /api/actions
# (api_write в main.py, только admin): запуск Action и интерактивная
# SSH-консоль обе дают произвольные команды на живом оборудовании, а
# консоль — даже более прямой путь к этому, чем Action, поэтому ей не
# место ниже той же планки.
MIN_CONSOLE_ROLE = ApiKeyRole.admin


async def _authenticate(payload: dict, cookie_token: str | None = None) -> tuple[Principal | None, str | None]:
    """Возвращает (Principal, None), если вход валиден И роли достаточно
    для SSH-консоли, иначе (None, текст ошибки). Порядок проверки — как в
    require_api_key (auth.py): сначала api_key из тела сообщения (годится
    и для браузера, и для скриптов), затем кука хендшейка — сессия входа
    по паролю, затем кука, выданная обменом API-ключа. Principal (а не
    голая роль) нужен ещё и ниже, в handle_console, для проверки области
    по группе узла через require_node_access — без неё ключ, ограниченный
    группой, мог бы открыть интерактивную сессию на чужом узле."""
    api_key = payload.get("api_key")
    db = get_session()
    try:
        principal: Principal | None = None
        if api_key:
            key = resolve_api_key(db, api_key)
            if key is None:
                return None, "неверный или отозванный API-ключ"
            principal = Principal(label=key.label, role=key.role, group_id=key.group_id, kind="api_key")
        else:
            user = resolve_session(db, cookie_token)
            if user is not None:
                principal = Principal(label=user.username, role=user.role, group_id=user.group_id, kind="user")
            else:
                key = resolve_api_key_session(db, cookie_token)
                if key is not None:
                    principal = Principal(label=key.label, role=key.role, group_id=key.group_id, kind="api_key")

        if principal is None:
            return None, "нужен api_key или вход в систему"
        if ROLE_RANK[principal.role] < ROLE_RANK[MIN_CONSOLE_ROLE]:
            return None, "недостаточно прав — SSH-консоль требует роль admin"
        return principal, None
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

    principal, auth_error = await _authenticate(payload, ws.cookies.get(COOKIE_NAME))
    if auth_error:
        await ws.send_json({"type": "error", "message": auth_error})
        await ws.close(code=1008)
        return

    node_id = payload.get("node_id")
    db = get_session()
    try:
        try:
            # Та же проверка области по группе, что и на HTTP-стороне у
            # бэкапа/скана/аудита — ключ, ограниченный группой, не должен
            # мочь открыть интерактивную сессию на чужом узле. 404 (не 403)
            # по тем же причинам, что в auth.require_node_access — не
            # подтверждать существование чужого узла.
            node = require_node_access(db, principal, node_id)
        except HTTPException:
            node = None
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
        await ws.close(code=1008)
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

    # TOFU по Node.ssh_key_fingerprint — та же единая точка
    # проверки host key, что и у Probe/Action (см. ssh_client.py). node
    # уже загружен выше (сессия, которой он был загружен, уже закрыта,
    # но плоские колонки, включая fingerprint, доступны и после этого);
    # сохранение нового fingerprint открывает свою короткую сессию по id.
    def _get_fingerprint() -> str | None:
        return node.ssh_key_fingerprint

    def _store_fingerprint(fingerprint: str) -> None:
        write_db = get_session()
        try:
            fresh = write_db.get(Node, node.id)
            if fresh is not None:
                fresh.ssh_key_fingerprint = fingerprint
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
    except HostKeyRejected as exc:
        # Не путать с веткой ниже: это осознанное предупреждение
        # безопасности (host key узла не совпал с сохранённым TOFU-
        # fingerprint), а не сведения о файловой системе сервера —
        # безопасно показать клиенту как есть.
        await ws.send_json({"type": "error", "message": str(exc)})
        await ws.close(code=1011)
        return
    except (asyncssh.Error, OSError) as exc:
        # key_path приходит от клиента напрямую (см. docstring модуля),
        # а не всегда через Credential — при явном username ниже
        # resolve_credential не участвует. asyncssh/OSError различают
        # "файла нет" (FileNotFoundError и т.п.) от "файл есть, но не
        # ключ" от "хендшейк не удался" — если отдать exc текстом как
        # есть, админ (уже прошедший auth-проверку выше) получает
        # оракул существования/читаемости произвольных файлов на
        # сервере через key_path. Раз доступ и так уже admin-only и
        # низкой критичности (аудит 2026-09-28), не городим отдельный
        # allowlist путей — просто не отдаём причину на клиент,
        # только в лог сервера, который админу и так доступен по SSH.
        logger.warning(
            "SSH-консоль: подключение к node_id=%s (%s@%s:%s) не удалось: %s",
            node.id, username, node.address, payload.get("port", 22), exc,
        )
        await ws.send_json({
            "type": "error",
            "message": "не удалось подключиться по SSH — подробности в логах сервера",
        })
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
