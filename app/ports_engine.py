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
        # "-?" — у Juniper буквенный префикс отделён дефисом (ge-0/0/0),
        # у Cisco дефиса нет (Gi1/0/1). Без него каждый Juniper-порт
        # попадал в собственную группу из одного порта: regex не совпадал
        # вообще, и весь port.name уходил в prefix как есть.
        match = re.match(r"^([A-Za-z]+-?[0-9]+(?:/[0-9]+)*)/[0-9]+$", port.name)
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


# Команда MAC-таблицы, отфильтрованная по конкретному порту — по прямому
# запросу пользователя (перенос "По устройству" из NetOpsHub, живым
# запросом по кнопке, не отдельным хранимым снимком). {port} подставляется
# уже подтверждённым именем существующего порта (из PortSnapshot), не
# произвольным пользовательским вводом — command injection risk нет.
MAC_COMMANDS = {
    Vendor.cisco_ios: "show mac address-table interface {port}",
    Vendor.cisco_ios_telnet: "show mac address-table interface {port}",
    Vendor.junos: "show ethernet-switching table interface {port}",
}

# Полная MAC-таблица (все порты разом, без фильтра) — для обнаружения
# вероятных хабов (app/hub_detection_engine.py), парсится тем же
# parse_cisco_mac_table (Ports-колонка теперь читается всегда).
FULL_MAC_COMMAND_CISCO = "show mac address-table"

_MAC_RE = re.compile(r"([0-9a-f]{4}[.:][0-9a-f]{4}[.:][0-9a-f]{4}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.IGNORECASE)


def parse_cisco_mac_table(output: str) -> list[dict]:
    """Разбирает `show mac address-table interface <port>`."""
    lines = output.splitlines()
    header_index = next(
        (i for i, line in enumerate(lines) if "Mac Address" in line and "Vlan" in line),
        None,
    )
    if header_index is None:
        return []
    header = lines[header_index]
    bounds = _column_bounds(header, ["Vlan", "Mac Address", "Type", "Ports"])
    if not bounds:
        return []
    rows = []
    for line in lines[header_index + 1:]:
        if not line.strip() or set(line.strip()) <= {"-"}:
            continue
        mac = _slice(line, bounds["Mac Address"])
        if not _MAC_RE.search(mac):
            continue
        rows.append({
            "vlan": _slice(line, bounds["Vlan"]), "mac": mac, "type": _slice(line, bounds["Type"]),
            "port": _slice(line, bounds["Ports"]) if "Ports" in bounds else "",
        })
    return rows


def parse_junos_mac_table(output: str) -> list[dict]:
    """Разбирает `show ethernet-switching table interface <port>` — не
    проверено на живом Juniper (тот же статус, что и parse_junos_terse
    выше), разобрано по документированному формату."""
    rows = []
    for line in output.splitlines():
        match = _MAC_RE.search(line)
        if not match:
            continue
        parts = line.split()
        vlan = parts[0] if parts else ""
        rows.append({"vlan": vlan, "mac": match.group(1), "type": ""})
    return rows


def parse_mac_table(vendor: Vendor | None, output: str) -> list[dict]:
    if vendor is Vendor.junos:
        return parse_junos_mac_table(output)
    return parse_cisco_mac_table(output)


# === Down/Up Time (флаппинг) — перенесено из NetOpsHub
# (app/port_overview_parser.py). Cisco: "show interfaces link" даёт
# фиксированную таблицу Port/Name/Down Time/Up Time на ВСЕ порты разом
# (в отличие от MAC-таблицы, эту команду нельзя ограничить одним портом),
# нужная строка выбирается после разбора. Juniper: "show interfaces
# {port} extensive" — ЭТУ команду, в отличие от NetOpsHub (там без
# аргумента — сразу все порты), можно ограничить одним портом, так
# дешевле для живого запроса по кнопке. Состояние линка (Up/Down) и
# "Last flapped" видны в одном и том же блоке вывода."""

DOWNUP_COMMANDS = {
    Vendor.cisco_ios: "show interfaces link",
    Vendor.cisco_ios_telnet: "show interfaces link",
    Vendor.junos: "show interfaces {port} extensive",
}

_IFACE_PREFIXES = [
    ("HundredGigE", "Hu"),
    ("FortyGigabitEthernet", "Fo"),
    ("TwentyFiveGigE", "Twe"),
    ("TenGigabitEthernet", "Te"),
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("AppGigabitEthernet", "Ap"),
    ("Port-channel", "Po"),
    ("Vlan", "Vl"),
]


def normalize_iface(name: str) -> str:
    """"GigabitEthernet1/0/1" и "Gi1/0/1" -> одинаковый ключ "gi1/0/1"."""
    name = name.strip()
    for long, short in _IFACE_PREFIXES:
        if name.startswith(long):
            name = short + name[len(long):]
            break
    return name.lower()


def parse_cisco_link_times(output: str, port_name: str) -> dict | None:
    """Разбирает `show interfaces link`, возвращает Down/Up Time для
    ОДНОГО запрошенного порта (или None, если порт не нашёлся в выводе —
    например, устройство не поддерживает эту команду вообще, реальный
    случай на старых 2950/2960)."""
    lines = output.splitlines()
    header_index = next(
        (i for i, line in enumerate(lines) if "Port" in line and "Down Time" in line and "Up Time" in line),
        None,
    )
    if header_index is None:
        return None
    header = lines[header_index]
    bounds = _column_bounds(header, ["Port", "Name", "Down Time", "Up Time"])
    if not bounds:
        return None
    target = normalize_iface(port_name)
    for line in lines[header_index + 1:]:
        if not line.strip() or set(line.strip()) <= {"-"}:
            continue
        port = _slice(line, bounds["Port"])
        if normalize_iface(port) != target:
            continue
        return {"down_time": _slice(line, bounds["Down Time"]), "up_time": _slice(line, bounds["Up Time"])}
    return None


_JUNOS_PHYS_RE = re.compile(r"Physical link is (Up|Down)\b")
_JUNOS_LAST_FLAPPED_RE = re.compile(r"Last flapped\s*:\s*(.+)")
_JUNOS_AGO_RE = re.compile(r"\(([^)]*ago)\)")


def parse_junos_link_time(output: str) -> dict | None:
    """Разбирает `show interfaces <port> extensive` — не проверено на
    живом Juniper (тот же статус, что и остальные Junos-парсеры в этом
    файле)."""
    link_match = _JUNOS_PHYS_RE.search(output)
    if link_match is None:
        return None
    is_up = link_match.group(1) == "Up"
    flap_match = _JUNOS_LAST_FLAPPED_RE.search(output)
    duration = ""
    if flap_match:
        raw = flap_match.group(1).strip()
        if raw.lower().startswith("never"):
            duration = "never"
        else:
            ago_match = _JUNOS_AGO_RE.search(raw)
            duration = re.sub(r"\s*ago\s*$", "", ago_match.group(1)).strip() if ago_match else raw
    return {"down_time": "00:00:00" if is_up else duration, "up_time": duration if is_up else "00:00:00"}


async def live_port_downup(
    node,
    port_name: str,
    *,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout_seconds: float = 20.0,
) -> dict:
    """Живой запрос Down/Up Time на конкретном порту — тот же принцип, что
    live_port_mac выше: по кнопке, ничего не сохраняется."""
    from app.device_client import default_port, run_device_command

    template = DOWNUP_COMMANDS.get(node.vendor or Vendor.cisco_ios, DOWNUP_COMMANDS[Vendor.cisco_ios])
    command = template.format(port=port_name)
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
    if not result.ok:
        return {"ok": False, "error": result.error, "down_time": None, "up_time": None}
    times = (
        parse_junos_link_time(result.stdout)
        if node.vendor is Vendor.junos
        else parse_cisco_link_times(result.stdout, port_name)
    )
    if times is None:
        return {"ok": False, "error": "команда не поддержана устройством или порт не найден в выводе", "down_time": None, "up_time": None}
    return {"ok": True, "error": None, "down_time": times["down_time"], "up_time": times["up_time"]}


async def live_port_mac(
    node,
    port_name: str,
    *,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout_seconds: float = 20.0,
) -> dict:
    """Живой запрос MAC-адресов на конкретном порту — по кнопке, ничего не
    сохраняется (в отличие от PortSnapshot, который снимает состояние ВСЕХ
    портов и хранится). Тот же принцип, что STP-чеклист уже применяет к
    port-map: спросить устройство сейчас, а не поддерживать ещё один
    хранимый снимок ради редко нужной детали."""
    from app.device_client import default_port, run_device_command

    template = MAC_COMMANDS.get(node.vendor or Vendor.cisco_ios, MAC_COMMANDS[Vendor.cisco_ios])
    command = template.format(port=port_name)
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
    if not result.ok:
        return {"ok": False, "error": result.error, "macs": []}
    return {"ok": True, "error": None, "macs": parse_mac_table(node.vendor, result.stdout)}


def latest_snapshot(db, node_id: int):
    from app.models import PortSnapshot

    return (
        db.query(PortSnapshot)
        .filter(PortSnapshot.node_id == node_id)
        .order_by(PortSnapshot.taken_at.desc())
        .first()
    )
