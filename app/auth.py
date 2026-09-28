"""Вход и права.

Три способа войти, но все сводятся к одному объекту Principal, чтобы
права не разъезжались между путями: API-ключ в заголовке `X-API-Key`
(программы, интеграции), логин с паролем через куку сессии (люди в
браузере, см. passwords.py и sessions.py) и — для той же куки — обмен
API-ключа на куку через POST /api/session/from-key (main.py), чтобы
браузерный UI не держал сырой ключ в localStorage, доступном любому XSS
(см. ApiKeySession в models.py и create_api_key_session/
resolve_api_key_session в sessions.py).

Две оси прав: роль (viewer < operator < admin, см. ROLE_RANK) и
необязательное ограничение области одной группой узлов (нижняя половина
файла)."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from fastapi import Cookie, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import ApiKey, ApiKeyRole, Backup, Node, Probe
from app.sessions import resolve_api_key_session, resolve_session


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def generate_key(db: Session, label: str, role: ApiKeyRole, group_id: int | None = None) -> str:
    """Создаёт новый ключ, возвращает сырое значение — вызывающая сторона
    показывает его ровно один раз (см. main.py: POST /api/api-keys и
    bootstrap_first_key ниже используют один и тот же путь).

    `group_id=None` — ключ видит все группы (поведение по умолчанию и всех
    ключей, выданных до появления ограничения по группам)."""
    raw_key = secrets.token_urlsafe(32)
    db.add(ApiKey(key_hash=_hash_key(raw_key), label=label, role=role, group_id=group_id))
    db.commit()
    return raw_key


def bootstrap_first_key(db: Session) -> str | None:
    """Если ключей ещё нет вообще — генерирует первый (роль admin) и
    печатает в консоль ОДИН раз (тот же паттерн, что уже применялся в
    соседних проектах этого же владельца — случайный секрет, выводится
    один раз, дальше только хеш в БД). Возвращает сырой ключ, если он был
    сгенерирован, иначе None."""
    if db.query(ApiKey).count() > 0:
        return None
    return generate_key(db, label="bootstrap", role=ApiKeyRole.admin)


@dataclass
class Principal:
    """Кто выполняет запрос — независимо от того, как он вошёл.

    Войти можно двумя способами: API-ключом в заголовке (программы,
    интеграции) и логином с паролем через куку сессии (люди в браузере).
    Права при этом обязаны быть одни и те же, поэтому всё, что дальше
    решает о доступе, работает с этим объектом, а не с ApiKey или User по
    отдельности — иначе два пути неизбежно разъехались бы в правах.
    """

    label: str               # метка ключа или имя пользователя — для сообщений и whoami
    role: ApiKeyRole
    group_id: int | None
    kind: str                # "api_key" | "user"


def _principal_from_key(key: ApiKey) -> Principal:
    return Principal(label=key.label, role=key.role, group_id=key.group_id, kind="api_key")


def resolve_api_key(db: Session, raw_key: str) -> ApiKey | None:
    """Живой (не отозванный) ApiKey по сырому значению — общая точка
    хеширования и поиска, используется и здесь (заголовок X-API-Key), и
    в main.py: POST /api/session/from-key (обмен ключа на куку)."""
    return db.query(ApiKey).filter(ApiKey.key_hash == _hash_key(raw_key), ApiKey.revoked.is_(False)).first()


async def require_api_key(
    x_api_key: str | None = Header(default=None),
    gridforge_session: str | None = Cookie(default=None),
) -> Principal:
    """Действующий API-ключ (заголовок ИЛИ обменянный на куку через
    /api/session/from-key) ИЛИ живая сессия входа по паролю — для чтения
    (GET). См. require_admin_key ниже для операций записи.

    Заголовок проверяется первым и по-прежнему работает независимо от
    куки — внешние интеграции, curl, Sync Node это изменение не
    затрагивает вообще."""
    db = get_session()
    try:
        if x_api_key:
            key = resolve_api_key(db, x_api_key)
            if key is None:
                raise HTTPException(status_code=401, detail="Неверный или отозванный API-ключ")
            return _principal_from_key(key)

        user = resolve_session(db, gridforge_session)
        if user is not None:
            return Principal(label=user.username, role=user.role, group_id=user.group_id, kind="user")

        key = resolve_api_key_session(db, gridforge_session)
        if key is not None:
            return _principal_from_key(key)

        raise HTTPException(status_code=401, detail="Нужен заголовок X-API-Key или вход в систему")
    finally:
        db.close()


ROLE_RANK = {ApiKeyRole.viewer: 0, ApiKeyRole.operator: 1, ApiKeyRole.admin: 2}


async def require_operator_key(key: Principal = Depends(require_api_key)) -> Principal:
    """operator и выше — запуск операций на узлах (бэкап, аудит, скан,
    захват трафика). Сами операции ничего не меняют в конфигурации
    GridForge, поэтому не требуют admin; но и viewer их запускать не
    должен — они лезут на боевое оборудование."""
    if ROLE_RANK[key.role] < ROLE_RANK[ApiKeyRole.operator]:
        raise HTTPException(status_code=403, detail="Требуется ключ с ролью operator или admin")
    return key


async def require_admin_key(key: Principal = Depends(require_api_key)) -> Principal:
    """Только role=admin — изменение инвентаря/правил/каналов и выдача
    ключей. viewer/operator здесь получают 403, не 401 (ключ валиден,
    прав не хватает — разные вещи)."""
    if key.role != ApiKeyRole.admin:
        raise HTTPException(status_code=403, detail="Требуется ключ с ролью admin")
    return key


# --- Вторая ось прав: ограничение области видимости группой узлов ---
#
# Всё, что касается «видит ли этот ключ этот узел», живёт здесь, а не
# россыпью по эндпоинтам: пропущенная проверка в одном месте сводит на
# нет все остальные, поэтому точка принятия решения должна быть одна.


def key_sees_group(key: Principal, group_id: int | None) -> bool:
    """Ключ без группы видит всё. Ключ с группой видит ТОЛЬКО свою — узлы
    без группы для него тоже закрыты (иначе «общая» группа стала бы
    дырой в изоляции)."""
    if key.group_id is None:
        return True
    return group_id == key.group_id


def scope_nodes(query, key: Principal):
    """Сужение любого запроса, отбирающего Node, до области ключа."""
    if key.group_id is None:
        return query
    return query.filter(Node.group_id == key.group_id)


def require_node_access(db: Session, key: Principal, node_id: int) -> Node:
    """Достать Node с проверкой области ключа.

    Узел вне области отдаёт 404, а не 403 — сознательно: 403 подтвердил бы
    существование узла, и по перебору node_id можно было бы составить
    карту чужих групп, ничего в них не читая.
    """
    node = db.get(Node, node_id)
    if node is None or not key_sees_group(key, node.group_id):
        raise HTTPException(status_code=404, detail="Node не найден")
    return node


def require_probe_access(db: Session, key: Principal, probe_id: int) -> Probe:
    """Probe принадлежит узлу — доступ наследуется от узла. Иначе
    ограничение по группам обходилось бы заходом «сбоку», через probe_id."""
    probe = db.get(Probe, probe_id)
    if probe is None or not key_sees_group(key, probe.node.group_id):
        raise HTTPException(status_code=404, detail="Probe не найден")
    return probe


def require_backup_access(db: Session, key: Principal, backup_id: int) -> Backup:
    """То же для Backup — в нём лежит конфиг устройства, самое чувствительное
    из того, что хранит GridForge."""
    backup = db.get(Backup, backup_id)
    if backup is None or not key_sees_group(key, backup.node.group_id):
        raise HTTPException(status_code=404, detail="Бэкап не найден")
    return backup
