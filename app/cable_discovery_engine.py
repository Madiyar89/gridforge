"""Автоопрос транковых кабельных соединений через CDP — заполняет журнал
(app/models.py:CableLink) без ручного ввода. Первый шаг сознательно узкий:

- Только CDP (Cisco IOS/IOS-Telnet), не LLDP/Junos — команда та же, что
  уже показывается пользователю как готовая кнопка "Соседи" на Рубке
  (см. sweep_commands.py:PRESETS["neighbors"]), но раньше это был просто
  текст на экране, без разбора и без записи. Junos LLDP оставлен на
  потом: табличный вывод `show lldp neighbors` слишком разнится между
  версиями ПО, разбирать его вслепую — верный способ тихо записать в
  журнал неправильные порты (тот же принцип осторожности, что уже
  применён в hub_detection_engine.py: там тоже только Cisco).
- Только транковые порты (Port.is_trunk из уже снятого PortSnapshot) —
  по прямой просьбе пользователя ("для начала транковые соединения").
- Второй конец записи — всегда текст (см. докстринг CableLink): узнать
  ИМЯ соседа с CDP легко, а вот надёжно сопоставить его с существующим
  Node в GridForge — нет (короткое имя в CDP часто не совпадает с тем,
  как узел называется здесь), собственное решение пользователя после
  обсуждения вариантов.

Найденные записи помечаются source="cdp" (в отличие от "manual") и
обновляются НА МЕСТЕ при повторном опросе того же узла+порта — иначе
каждый повторный прогон плодил бы дубли. Ручные записи (source="manual")
никогда не трогаются автоопросом, даже если они на тот же порт."""

from __future__ import annotations

import asyncio
import re

from sqlalchemy.orm import Session

from app.models import CableLink, Node, PortSnapshot, Vendor

_CDP_VENDORS = (Vendor.cisco_ios, Vendor.cisco_ios_telnet)
_CDP_COMMAND = "show cdp neighbors detail"
MAX_PARALLEL = 8

_DEVICE_RE = re.compile(r"Device ID:\s*(\S+)")
_IFACE_RE = re.compile(r"Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)")


def parse_cdp_neighbors_detail(output: str) -> list[dict]:
    """Разбор `show cdp neighbors detail` (Cisco IOS). Блоки разделены
    строкой из дефисов; в каждом — "Device ID: ..." и "Interface: LOCAL,
    Port ID (outgoing port): REMOTE". Соседей без обеих строк (обрезанный
    вывод, нестандартная платформа) — пропускаем, не гадаем."""
    neighbors: list[dict] = []
    for block in re.split(r"^-+$", output, flags=re.MULTILINE):
        device_match = _DEVICE_RE.search(block)
        iface_match = _IFACE_RE.search(block)
        if not device_match or not iface_match:
            continue
        # Device ID часто приходит как FQDN ("sw2.domain.local") — берём
        # только короткое имя для читаемости журнала, как показывает CLI.
        remote_device = device_match.group(1).split(".")[0]
        local_port, remote_port = iface_match.group(1), iface_match.group(2)
        neighbors.append({"local_port": local_port, "remote_device": remote_device, "remote_port": remote_port})
    return neighbors


async def _discover_one(
    semaphore: asyncio.Semaphore,
    node: Node,
    trunk_ports: set[str],
    *,
    username: str,
    password: str | None,
    key_path: str | None,
    timeout_seconds: float,
) -> list[dict]:
    from app.device_client import default_port, run_device_command

    async with semaphore:
        result = await run_device_command(
            vendor=node.vendor,
            host=node.address,
            command=_CDP_COMMAND,
            username=username,
            password=password,
            key_path=key_path,
            port=default_port(node.vendor),
            timeout_seconds=timeout_seconds,
        )
    if not result.ok:
        return []
    neighbors = parse_cdp_neighbors_detail(result.stdout)
    return [n for n in neighbors if n["local_port"] in trunk_ports]


async def discover_trunk_cable_links(db: Session, group_id: int, *, resolve_credential) -> dict:
    """Обходит Cisco-узлы группы с уже снятым PortSnapshot, живым CDP-
    опросом транковых портов (параллельно, тот же принцип ограничения,
    что у Sweep/hub_detection), и записывает/обновляет CableLink с
    source="cdp". Возвращает сводку для интерфейса."""
    nodes = (
        db.query(Node)
        .filter(Node.group_id == group_id, Node.vendor.in_(_CDP_VENDORS), Node.active.is_(True))
        .all()
    )

    tasks = []
    task_nodes = []
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
        trunk_ports = {p["name"] for p in snapshot.ports if p.get("is_trunk")}
        if not trunk_ports:
            continue
        cred = resolve_credential(db, node)
        if cred is None:
            skipped.append(f"{node.name}: нет учётки")
            continue
        tasks.append(
            _discover_one(
                semaphore, node, trunk_ports,
                username=cred["username"], password=cred["password"], key_path=cred["key_path"],
                timeout_seconds=20.0,
            )
        )
        task_nodes.append(node)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    created = 0
    updated = 0
    for node, r in zip(task_nodes, results):
        if isinstance(r, Exception):
            skipped.append(f"{node.name}: {r}")
            continue
        for neighbor in r:
            existing = (
                db.query(CableLink)
                .filter(
                    CableLink.node_id == node.id,
                    CableLink.port_name == neighbor["local_port"],
                    CableLink.source == "cdp",
                )
                .first()
            )
            label = f"CDP: {neighbor['remote_device']}, {neighbor['remote_port']}"
            if existing is None:
                db.add(
                    CableLink(
                        group_id=group_id,
                        node_id=node.id,
                        port_name=neighbor["local_port"],
                        other_label=label,
                        status="active",
                        source="cdp",
                    )
                )
                created += 1
            elif existing.other_label != label:
                existing.other_label = label
                updated += 1
    db.commit()

    return {"created": created, "updated": updated, "checked_nodes": len(task_nodes), "skipped": skipped}


async def run_due_cable_discovery_schedules(get_session) -> None:
    """Проверяется раз в минуту из Scheduler.run_forever() (app/scheduler.py)
    — тот же принцип, что у run_due_vuln_schedules (app/vuln_scan_engine.py):
    находит расписания на сегодня, чьё время уже наступило и сегодня ещё
    не запускались, помечает last_triggered_on СРАЗУ (до опроса, не
    после — опрос группы узлов может занять заметное время)."""
    import datetime as _dt

    from app.credentials_engine import resolve_credential
    from app.models import CableDiscoverySchedule

    db = get_session()
    try:
        now = _dt.datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        current_hm = now.strftime("%H:%M")
        due = (
            db.query(CableDiscoverySchedule)
            .filter(
                CableDiscoverySchedule.enabled.is_(True),
                CableDiscoverySchedule.weekday == now.weekday(),
            )
            .all()
        )
        for sched in due:
            if sched.last_triggered_on == today_str or current_hm < sched.start_time:
                continue
            sched.last_triggered_on = today_str
            db.commit()
            await discover_trunk_cable_links(db, sched.group_id, resolve_credential=resolve_credential)
    finally:
        db.close()
