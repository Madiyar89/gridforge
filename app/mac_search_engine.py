"""Поиск MAC-адреса сразу по всему парку — перенесено из NetOpsHub
(app/modules/reports/routes.py:mac_search, там ищет по уже собранным
mac_*.yml-снимкам на диске).

У GridForge нет отдельного хранимого MAC-снимка всего парка — тот же
принцип живого запроса, что уже применяется в hub_detection_engine.py
(полная MAC-таблица узла по кнопке, не по расписанию): обходит все
Cisco-узлы параллельно (тот же MAX_PARALLEL/Semaphore, что у Sweep и
у поиска хабов), фильтрует найденные MAC по подстроке.

Только Cisco (cisco_ios/cisco_ios_telnet) — та же причина, что и у
hub_detection_engine: Junos-разбор MAC-таблицы не проверен на живом
оборудовании."""

from __future__ import annotations

import asyncio
import re

from sqlalchemy.orm import Session

from app.models import Node, Vendor
from app.ports_engine import FULL_MAC_COMMAND_CISCO, parse_cisco_mac_table

_SEARCH_VENDORS = (Vendor.cisco_ios, Vendor.cisco_ios_telnet)
MAX_PARALLEL = 8


def _normalize_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


async def _search_one(
    semaphore: asyncio.Semaphore, node: Node, query_norm: str,
    *, username: str, password: str | None, key_path: str | None, timeout_seconds: float,
) -> list[dict]:
    from app.device_client import default_port, run_device_command

    async with semaphore:
        result = await run_device_command(
            vendor=node.vendor,
            host=node.address,
            command=FULL_MAC_COMMAND_CISCO,
            username=username,
            password=password,
            key_path=key_path,
            port=default_port(node.vendor),
            timeout_seconds=timeout_seconds,
        )
    if not result.ok:
        return []

    rows = []
    for row in parse_cisco_mac_table(result.stdout):
        mac = row.get("mac", "")
        if query_norm in _normalize_mac(mac):
            rows.append({
                "hostname": node.name, "node_id": node.id,
                "port": row.get("port", ""), "mac": mac, "vlan": row.get("vlan", ""),
            })
    return rows


async def search_mac(db: Session, query: str, *, resolve_credential) -> dict:
    query_norm = _normalize_mac(query)
    if len(query_norm) < 4:
        return {"rows": [], "skipped": [], "error": "Введите хотя бы 4 hex-символа MAC-адреса"}

    nodes = db.query(Node).filter(Node.vendor.in_(_SEARCH_VENDORS), Node.active.is_(True)).all()
    tasks = []
    skipped: list[str] = []
    semaphore = asyncio.Semaphore(MAX_PARALLEL)
    for node in nodes:
        cred = resolve_credential(db, node)
        if cred is None:
            skipped.append(f"{node.name}: нет учётки")
            continue
        tasks.append(
            _search_one(
                semaphore, node, query_norm,
                username=cred["username"], password=cred["password"], key_path=cred["key_path"],
                timeout_seconds=20.0,
            )
        )

    results = await asyncio.gather(*tasks, return_exceptions=True)
    rows: list[dict] = []
    for r in results:
        if isinstance(r, Exception):
            continue
        rows.extend(r)
    rows.sort(key=lambda r: (r["hostname"], r["port"]))
    return {"rows": rows, "skipped": skipped, "error": None}
