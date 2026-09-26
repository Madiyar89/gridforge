"""Обнаружение вероятных хабов/неуправляемых свитчей за access-портами —
перенесено из NetOpsHub (hub_detection.py).

Хаб сам по себе не виден ни одному протоколу (чистый L1). Детектируется
не хаб, а симптом: access-порт (не trunk), на котором коммутатор видит
несколько разных MAC разом. Базовая эвристика (как в NetOpsHub): 2 MAC
чаще всего "IP-телефон + ПК" (нормально), 3+ — уже подозрительно на хаб.

Уточнение (2026-09-26, по прямому запросу пользователя "надо улучшить
данную проверку") — то самое, что NetOpsHub сознательно отложил в своей
версии ("CDP-соседа на этом порту сознательно НЕ проверяем... может быть
добавлено отдельно как уточнение", см. исходный докстринг): GridForge уже
умеет надёжно разбирать `show cdp neighbors detail`
(cable_discovery_engine.py, реальный баг с форматом имён портов там уже
пойман и исправлен 2026-09-24) — эта же команда и парсер переиспользованы
здесь для access-портов, не только транковых. IP-телефоны Cisco сами
говорят по CDP (Capabilities содержит "Phone") — если сосед на порту с
несколькими MAC подтверждён как телефон, это больше не догадка по числу
MAC, а факт из протокола. Если сосед на "access"-порту — Switch/Router
(порт с несколькими MAC, но это на самом деле линк на управляемый
коммутатор, а не хаб) — отдельный вердикт "не хаб, но порт стоит
перевести в trunk", не путать с находкой про неуправляемое L1-железо.
Порт без CDP-соседа вообще — обычная ситуация для хаба (сам хаб CDP не
говорит), эвристика по числу MAC остаётся единственным сигналом.

В отличие от NetOpsHub (читает уже собранные mac_*.yml/loop_info_*.yml
снимки на диске) — здесь и MAC-таблица, и CDP живые, СПРАШИВАЮТСЯ У
КАЖДОГО узла заново по кнопке. Access/trunk-классификация порта берётся
из уже снятого PortSnapshot (is_trunk), опрашивать это заново не нужно.

Только Cisco (cisco_ios/cisco_ios_telnet) — Junos-разбор MAC-таблицы
(ports_engine.parse_junos_mac_table) не проверен на живом оборудовании,
добавлять сюда ещё один непроверенный слой поверх эвристики уже
избыточный риск ложных находок."""

from __future__ import annotations

import asyncio

from sqlalchemy.orm import Session

from app.cable_discovery_engine import CDP_COMMAND, parse_cdp_neighbors_detail
from app.models import Node, PortSnapshot, Vendor
from app.ports_engine import FULL_MAC_COMMAND_CISCO, normalize_iface, parse_cisco_mac_table

_HUB_VENDORS = (Vendor.cisco_ios, Vendor.cisco_ios_telnet)
MAX_PARALLEL = 8


def _verdict_for(mac_count: int, capabilities: str | None) -> str:
    caps = (capabilities or "").lower()
    if "phone" in caps or "host" in caps:
        return "phone_confirmed"  # CDP-факт, не догадка — сосед сам сказал, что он телефон
    if "switch" in caps or "router" in caps or "bridge" in caps:
        return "switch_misclassified"  # это не хаб — на порту управляемый сетевой узел, порт стоит сделать trunk
    return "hub" if mac_count >= 3 else "maybe_phone"


async def _scan_one(
    semaphore: asyncio.Semaphore, node: Node, access_ports: set[str], *,
    username: str, password: str | None, key_path: str | None, timeout_seconds: float,
) -> list[dict]:
    from app.device_client import default_port, run_device_command

    async def _run(command: str) -> str:
        result = await run_device_command(
            vendor=node.vendor, host=node.address, command=command,
            username=username, password=password, key_path=key_path,
            port=default_port(node.vendor), timeout_seconds=timeout_seconds,
        )
        return result.stdout if result.ok else ""

    async with semaphore:
        mac_output = await _run(FULL_MAC_COMMAND_CISCO)
        if not mac_output:
            return []
        cdp_output = await _run(CDP_COMMAND)

    counts: dict[str, int] = {}
    for row in parse_cisco_mac_table(mac_output):
        port = row.get("port", "")
        if port:
            counts[port] = counts.get(port, 0) + 1

    capabilities_by_port: dict[str, str] = {}
    if cdp_output:
        for neighbor in parse_cdp_neighbors_detail(cdp_output):
            capabilities_by_port[normalize_iface(neighbor["local_port"])] = neighbor.get("capabilities", "")

    rows = []
    for port, mac_count in counts.items():
        if port not in access_ports or mac_count < 2:
            continue
        capabilities = capabilities_by_port.get(normalize_iface(port))
        rows.append({
            "hostname": node.name, "node_id": node.id, "port": port,
            "mac_count": mac_count, "verdict": _verdict_for(mac_count, capabilities),
        })
    return rows


async def find_probable_hubs(db: Session, *, resolve_credential, key=None, group_id: int | None = None) -> dict:
    """Обходит Cisco-узлы (все в области видимости ключа, либо только
    выбранной группы — по прямому запросу пользователя, "1 выбрать группу
    2 кнопка для сканирование") с уже снятым PortSnapshot, живым запросом
    MAC-таблицы + CDP-соседей (параллельно по узлам, с ограничением — тот
    же принцип, что у Sweep, см. app/sweep_engine.py). Узлы без учётки/
    снимка портов честно пропускаются, попадают в skipped, не считаются
    ни хабом, ни чистым.

    `key` — тот же RBAC, что у остальных отчётов по узлам (scope_nodes):
    ключ, ограниченный группой, не видит чужие узлы, даже если group_id
    не передан явно."""
    from app.auth import scope_nodes

    query = db.query(Node).filter(Node.vendor.in_(_HUB_VENDORS), Node.active.is_(True))
    if key is not None:
        query = scope_nodes(query, key)
    if group_id is not None:
        query = query.filter(Node.group_id == group_id)
    nodes = query.all()

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
