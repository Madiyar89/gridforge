"""Состояние портов коммутатора: опрос и разбор вывода.

Разбор — самая хрупкая часть: вывод рассчитан на человека, а не на
программу, и у разных моделей отличается. Два наблюдения с реального
оборудования, которые определили реализацию:

1. **Колонки разбираются по позициям, а не по пробелам.** Поле Name
   бывает пустым, а бывает содержит пробелы («ADMIN SHUTDOWN»,
   «>> Link to Admins»). Обычный split() на таких строках разъезжается и
   молча приписывает порту чужой статус.
2. **Ширина колонок не фиксирована** — у одного коммутатора `Gi1/0/1`
   занимает 10 символов, у другого 13. Поэтому границы вычисляются по
   строке заголовка каждого вывода, а не зашиты числами.

Juniper: формат `show interfaces terse` разобран по документации, на
реальном выводе НЕ проверен — в доступных снимках Juniper-устройств не
оказалось. Это помечено и здесь, и в тестах; при первом же запуске на
живом EX стоит сверить результат глазами.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.models import Vendor

# Команда снятия состояния по вендорам. Только чтение.
STATUS_COMMANDS = {
    Vendor.cisco_ios: "show interfaces status",
    Vendor.cisco_ios_telnet: "show interfaces status",  # те же команды, другой транспорт
    Vendor.junos: "show interfaces terse",
}


class PortState:
    """Состояния, которые показываем на схеме.

    Свой набор, а не дословные слова вендора: у Cisco `connected`, у
    Juniper `up` — на схеме это одно и то же, и раскрашивать их надо
    одинаково."""

    UP = "up"                    # линк есть
    NOT_CONNECTED = "notconnect"  # порт включён, но кабель не воткнут
    DISABLED = "disabled"        # выключен администратором
    ERR_DISABLED = "err-disabled"  # выключен автоматически из-за нарушения
    UNKNOWN = "unknown"


_CISCO_STATE = {
    "connected": PortState.UP,
    "notconnect": PortState.NOT_CONNECTED,
    "disabled": PortState.DISABLED,
    "err-disabled": PortState.ERR_DISABLED,
    "errdisable": PortState.ERR_DISABLED,
    "monitoring": PortState.UP,   # порт SPAN — линк есть, трафик зеркалится
    "inactive": PortState.NOT_CONNECTED,
    "faulty": PortState.ERR_DISABLED,
}


@dataclass
class Port:
    name: str
    state: str
    description: str = ""
    vlan: str = ""
    speed: str = ""
    is_trunk: bool = False
    extras: dict = field(default_factory=dict)


def _column_bounds(header: str, titles: list[str]) -> dict[str, tuple[int, int | None]]:
    """Границы колонок по строке заголовка.

    Именно из-за этого разбор переживает разную ширину колонок: позиции
    берутся из конкретного вывода, а не из зашитых чисел."""
    positions = []
    for title in titles:
        index = header.find(title)
        if index < 0:
            return {}
        positions.append((title, index))
    positions.sort(key=lambda pair: pair[1])

    bounds: dict[str, tuple[int, int | None]] = {}
    for i, (title, start) in enumerate(positions):
        end = positions[i + 1][1] if i + 1 < len(positions) else None
        bounds[title] = (start, end)
    return bounds


def _slice(line: str, bounds: tuple[int, int | None]) -> str:
    start, end = bounds
    return line[start:end].strip() if end is not None else line[start:].strip()


def _looks_like_interface(name: str) -> bool:
    """Похоже ли на имя интерфейса: 2-4 буквы, дальше цифры и слэши.

    Слэш НЕ обязателен. Сначала я его потребовал — и потерял шесть
    настоящих портов `Fa0` (management-интерфейс) на реальных снимках.
    Мусор вроде `ABBD8026` из hex-блоков сертификатов под этот шаблон
    тоже подходит, но отсеивается следующей проверкой — по состоянию,
    которого у него не бывает осмысленным."""
    return bool(re.match(r"^[A-Za-z]{2,4}[0-9]+(/[0-9]+)*$", name))


def parse_cisco_status(output: str) -> list[Port]:
    """Разбирает `show interfaces status`."""
    lines = output.splitlines()
    header_index = next(
        (i for i, line in enumerate(lines) if line.lstrip().startswith("Port") and "Status" in line),
        None,
    )
    if header_index is None:
        return []

    header = lines[header_index]
    bounds = _column_bounds(header, ["Port", "Name", "Status", "Vlan", "Duplex", "Speed", "Type"])
    if not bounds:
        return []

    ports: list[Port] = []
    for line in lines[header_index + 1:]:
        if not line.strip():
            continue
        port_name = _slice(line, bounds["Port"])
        if not _looks_like_interface(port_name):
            continue

        raw_state = _slice(line, bounds["Status"]).lower()
        # Вторая проверка — по состоянию. Нужна из-за реальной находки:
        # разбор 9 снимков с боевых коммутаторов дал 4 лишних «порта»
        # вроде ABBD8026 со «статусом» 414d414d — это hex-блоки
        # сертификатов из секций файла НИЖЕ таблицы. Имя у них случайно
        # похоже на интерфейс, но состояние выдаёт мусор сразу.
        if raw_state not in _CISCO_STATE and "/" not in port_name:
            continue
        vlan = _slice(line, bounds["Vlan"])
        ports.append(
            Port(
                name=port_name,
                state=_CISCO_STATE.get(raw_state, PortState.UNKNOWN),
                description=_slice(line, bounds["Name"]),
                vlan=vlan,
                speed=_slice(line, bounds["Speed"]),
                is_trunk=vlan.lower() == "trunk",
                extras={"raw_state": raw_state} if raw_state not in _CISCO_STATE else {},
            )
        )
    return ports


def parse_junos_terse(output: str) -> list[Port]:
    """Разбирает `show interfaces terse`.

    ВНИМАНИЕ: на реальном выводе не проверено (в доступных снимках
    Juniper-устройств не было). Разобрано по документированному формату:
        Interface    Admin  Link  Proto  Local  Remote
        ge-0/0/1     up     up
        ge-0/0/1.0   up     up    eth-switch
    Логические подынтерфейсы (с точкой) пропускаем — на схеме порты
    физические."""
    ports: list[Port] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, admin, link = parts[0], parts[1].lower(), parts[2].lower()
        if not re.match(r"^[a-z]+-\d+/\d+/\d+$", name):
            continue  # заголовок, подынтерфейс (ge-0/0/1.0) или мусор

        if admin != "up":
            state = PortState.DISABLED
        elif link == "up":
            state = PortState.UP
        else:
            state = PortState.NOT_CONNECTED
        ports.append(Port(name=name, state=state, extras={"admin": admin, "link": link}))
    return ports


def parse_ports(vendor: Vendor | None, output: str) -> list[Port]:
    if vendor is Vendor.junos:
        return parse_junos_terse(output)
    # Узлы без указанного вендора разбираем как Cisco: в этом парке они
    # преобладают, а неподходящий формат просто даст пустой список, а не
    # неверные данные.
    return parse_cisco_status(output)


def group_ports(ports: list[Port]) -> list[dict]:
    """Группирует порты по модулю (Gi1/0/… и Gi1/1/… — разные ряды).

    На схеме это важно: у коммутатора 48 портов основного модуля и
    отдельно 4 аплинка, и рисовать их одной лентой неправильно."""
    groups: dict[str, list[Port]] = {}
    for port in ports:
        match = re.match(r"^([A-Za-z]+[0-9]+(?:/[0-9]+)*)/[0-9]+$", port.name)
        prefix = match.group(1) if match else port.name
        groups.setdefault(prefix, []).append(port)

    def sort_key(port: Port) -> int:
        tail = port.name.rsplit("/", 1)[-1]
        return int(tail) if tail.isdigit() else 0

    return [
        {"prefix": prefix, "ports": sorted(items, key=sort_key)}
        for prefix, items in sorted(groups.items())
    ]


async def collect_ports(
    db,
    node,
    *,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout_seconds: float = 20.0,
):
    """Снимает состояние портов узла и сохраняет снимок.

    Неудачный опрос тоже сохраняется — с ok=False и текстом ошибки:
    «не удалось снять» это полезная информация, а молча оставлять на
    схеме вчерашние данные хуже, чем честно показать, что связи нет.
    """
    from app.device_client import default_port, run_device_command
    from app.models import PortSnapshot

    # Telnet-устройства опрашиваются тем же вызовом: транспорт выбирается
    # по вендору внутри device_client.
    command = STATUS_COMMANDS.get(node.vendor or Vendor.cisco_ios, STATUS_COMMANDS[Vendor.cisco_ios])
    result = await run_device_command(
        vendor=node.vendor,
        host=node.address,
        command=command,
        username=username,
        password=password,
        key_path=key_path,
        port=port if port not in (0, 22) else default_port(node.vendor),
        timeout_seconds=timeout_seconds,
    )

    snapshot = PortSnapshot(node_id=node.id, command=command, ok=result.ok)
    if result.ok:
        parsed = parse_ports(node.vendor, result.stdout)
        snapshot.ports = [
            {
                "name": p.name,
                "state": p.state,
                "description": p.description,
                "vlan": p.vlan,
                "speed": p.speed,
                "is_trunk": p.is_trunk,
            }
            for p in parsed
        ]
        if not parsed:
            # Команда прошла, а портов не видно — формат не тот, что
            # ожидали. Молчать нельзя: пустая схема выглядит как
            # «коммутатор без портов».
            snapshot.ok = False
            snapshot.error = "вывод получен, но портов в нём не распознано — проверь вендора узла"
    else:
        snapshot.error = result.error

    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def latest_snapshot(db, node_id: int):
    from app.models import PortSnapshot

    return (
        db.query(PortSnapshot)
        .filter(PortSnapshot.node_id == node_id)
        .order_by(PortSnapshot.taken_at.desc())
        .first()
    )
