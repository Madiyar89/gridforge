"""Обнаружение вероятных хабов/неуправляемых свитчей за access-портами —
перенесено из NetOpsHub (hub_detection.py).

Хаб сам по себе не виден ни одному протоколу (чистый L1). Детектируется
не хаб, а симптом: access-порт (не trunk), на котором коммутатор видит
несколько разных MAC разом. Эвристика: 2 MAC чаще всего "IP-телефон +
ПК" (нормально), 3+ — уже подозрительно на хаб.

В отличие от NetOpsHub (читает уже собранные mac_*.yml/loop_info_*.yml
снимки на диске) — здесь MAC-таблица живая, СПРАШИВАЕТСЯ У КАЖДОГО узла
заново по кнопке (у GridForge просто нет отдельного хранимого mac-снимка
всего парка, см. ports_engine.live_port_mac — тот же принцип живого
запроса). Access/trunk-классификация порта берётся из уже снятого
PortSnapshot (is_trunk), опрашивать это заново не нужно.

Только Cisco (cisco_ios/cisco_ios_telnet) — Junos-разбор MAC-таблицы
(ports_engine.parse_junos_mac_table) не проверен на живом оборудовании,
добавлять сюда ещё один непроверенный слой поверх эвристики уже
избыточный риск ложных находок."""

from __future__ import annotations

import asyncio

from sqlalchemy.orm import Session

from app.models import Node, PortSnapshot, Vendor
from app.ports_engine import FULL_MAC_COMMAND_CISCO, parse_cisco_mac_table

_HUB_VENDORS = (Vendor.cisco_ios, Vendor.cisco_ios_telnet)
MAX_PARALLEL = 8


async def _scan_one(semaphore: asyncio.Semaphore, node: Node, access_ports: set[str], *, username: str, password: str | None, key_path: str | None, timeout_seconds: float) -> list[dict]:
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

    counts: dict[str, int] = {}
    for row in parse_cisco_mac_table(result.stdout):
        port = row.get("port", "")
        if port:
            counts[port] = counts.get(port, 0) + 1

    rows = []
    for port, mac_count in counts.items():
        if port not in access_ports or mac_count < 2:
            continue
        rows.append({
            "hostname": node.name, "node_id": node.id, "port": port,
            "mac_count": mac_count, "verdict": "hub" if mac_count >= 3 else "maybe_phone",
        })
    return rows


async def find_probable_hubs(db: Session, *, resolve_credential) -> dict:
    """Обходит все Cisco-узлы с уже снятым PortSnapshot, живым запросом
    полной MAC-таблицы (параллельно, с ограничением — тот же принцип, что
    у Sweep, см. app/sweep_engine.py). Узлы без учётки/бэкапа портов
    честно пропускаются, попадают в skipped, не считаются ни хабом, ни
    чистым."""
    nodes = db.query(Node).filter(Node.vendor.in_(_HUB_VENDORS), Node.active.is_(True)).all()

    tasks = []
    skipped: list[str] = []
    semaphore = asyncio.Semaphore(MAX_PARALLEL)
    for node in nodes:
        snapshot = (
            db.query(PortSnapshot)
            .filter(PortSnapshot.node_id == node.id)
            .order_by(PortSnapshot.taken_at.desc())
            .first()
        )
        if snapshot is None or not snapshot.ok:
            skipped.append(f"{node.name}: нет снимка портов")
            continue
        access_ports = {p["name"] for p in snapshot.ports if not p.get("is_trunk")}
        if not access_ports:
            continue
        cred = resolve_credential(db, node)
        if cred is None:
            skipped.append(f"{node.name}: нет учётки")
            continue
        tasks.append(
            _scan_one(
                semaphore, node, access_ports,
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
    return {"rows": rows, "skipped": skipped}
