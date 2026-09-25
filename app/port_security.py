"""Port Security и защита STP — чтение состояния из конфигурации.

Разбирается сохранённый снимок конфигурации (Backup), а не живой опрос:
конфигурации уже снимаются регулярно, и отдельный поход на устройство
ради того же текста был бы лишней нагрузкой на старые коммутаторы.

Главная тонкость, из-за которой это отдельный модуль с тестами.
Включающая строка у Cisco выглядит так:

    switchport port-security

а под-настройки — так:

    switchport port-security maximum 4
    switchport port-security violation restrict
    switchport port-security mac-address sticky

Команда `no switchport port-security` убирает ТОЛЬКО первую строку;
под-настройки остаются в конфигурации «на память», хотя защита уже
выключена. Проверка вхождением подстроки поэтому даёт ложное
«порт защищён» на каждом отключённом порте, где остались хвосты — этот
дефект реально жил в похожем инструменте и показывал защиту там, где её
не было. Здесь сравнение идёт с голой строкой целиком.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Голая включающая строка: ничего, кроме неё самой, в строке быть не должно.
_PS_ENABLED = re.compile(r"^\s*switchport port-security\s*$", re.M)
_PS_MAXIMUM = re.compile(r"^\s*switchport port-security maximum (\d+)\s*$", re.M)
_PS_VIOLATION = re.compile(r"^\s*switchport port-security violation (\w+)\s*$", re.M)
_PS_STICKY = re.compile(r"^\s*switchport port-security mac-address sticky\s*$", re.M)

_BPDU_GUARD = re.compile(r"^\s*spanning-tree bpduguard enable\s*$", re.M)
_BPDU_FILTER = re.compile(r"^\s*spanning-tree bpdufilter enable\s*$", re.M)
_PORTFAST = re.compile(r"^\s*spanning-tree portfast", re.M)
_GUARD_ROOT = re.compile(r"^\s*spanning-tree guard root\s*$", re.M)
_GUARD_LOOP = re.compile(r"^\s*spanning-tree guard loop\s*$", re.M)
_MODE_TRUNK = re.compile(r"^\s*switchport mode trunk\s*$", re.M)

# Глобальные настройки STP.
_GLOBAL_LOOPGUARD = re.compile(r"^spanning-tree loopguard default\s*$", re.M)
_GLOBAL_PORTFAST_BPDU = re.compile(r"^spanning-tree portfast bpduguard default\s*$", re.M)
_GLOBAL_PRIORITY = re.compile(r"^spanning-tree vlan ([\d,\-]+) priority (\d+)\s*$", re.M)
_GLOBAL_MODE = re.compile(r"^spanning-tree mode (\S+)\s*$", re.M)


@dataclass
class PortProtection:
    name: str
    port_security: bool = False
    max_mac: int | None = None
    violation: str = ""
    sticky: bool = False
    bpdu_guard: bool = False
    bpdu_filter: bool = False
    portfast: bool = False
    guard_root: bool = False
    guard_loop: bool = False
    is_trunk: bool = False


def split_interface_blocks(config: str) -> dict[str, str]:
    """Режет running-config на блоки по интерфейсам.

    Блок заканчивается следующей строкой нулевого отступа: у Cisco это
    либо `!`, либо начало новой секции."""
    blocks: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []

    for line in config.splitlines():
        match = re.match(r"^interface (\S+)\s*$", line)
        if match:
            if current_name is not None:
                blocks[current_name] = "\n".join(current_lines)
            current_name = match.group(1)
            current_lines = []
            continue
        if current_name is not None:
            # Строка без отступа завершает блок интерфейса.
            if line and not line.startswith((" ", "\t")):
                blocks[current_name] = "\n".join(current_lines)
                current_name = None
                current_lines = []
                continue
            current_lines.append(line)

    if current_name is not None:
        blocks[current_name] = "\n".join(current_lines)
    return blocks


def parse_port_protection(config: str) -> dict[str, PortProtection]:
    """Состояние защиты по каждому интерфейсу из конфигурации."""
    result: dict[str, PortProtection] = {}
    for name, block in split_interface_blocks(config).items():
        maximum = _PS_MAXIMUM.search(block)
        violation = _PS_VIOLATION.search(block)
        result[name] = PortProtection(
            name=name,
            # Только голая строка — см. пояснение в начале модуля.
            port_security=bool(_PS_ENABLED.search(block)),
            max_mac=int(maximum.group(1)) if maximum else None,
            violation=violation.group(1) if violation else "",
            sticky=bool(_PS_STICKY.search(block)),
            bpdu_guard=bool(_BPDU_GUARD.search(block)),
            bpdu_filter=bool(_BPDU_FILTER.search(block)),
            portfast=bool(_PORTFAST.search(block)),
            guard_root=bool(_GUARD_ROOT.search(block)),
            guard_loop=bool(_GUARD_LOOP.search(block)),
            is_trunk=bool(_MODE_TRUNK.search(block)),
        )
    return result


# Port Security для Juniper — реальный формат `show configuration
# ethernet-switching-options`, проверено на живом EX (LAB-28,
# 2026-09-25, по запросу пользователя: раньше для Juniper эта панель
# ВСЕГДА показывала "нет снимка конфигурации" — не из-за отсутствия
# бэкапа (обычный бэкап Juniper уже снимает полный `show
# configuration`, включая эту секцию), а потому что parse_port_protection
# выше понимает только синтаксис Cisco IOS (interface-блоки строками),
# для фигурных скобок Junos не находил вообще ничего):
#     secure-access-port {
#         interface ge-0/0/1.0 {
#             mac-limit 1 action drop;
#         }
#     }
# Логический юнит (.0) отбрасывается — на схеме порты физические, тем
# же именем, что и в show interfaces terse/ports_engine.py.
_JUNOS_IFACE_BLOCK_RE = re.compile(r"interface\s+(\S+?)(?:\.\d+)?\s*\{([^{}]*)\}")
_JUNOS_MAC_LIMIT_RE = re.compile(r"mac-limit\s+(\d+)\s+action\s+(\S+?);")


def parse_junos_port_protection(config: str) -> dict[str, PortProtection]:
    """Port Security по каждому интерфейсу из `show configuration` (или
    scoped `show configuration ethernet-switching-options`) Juniper.
    STP-защита Junos (edge-port/bpdu-block) — не тот же формат, что у
    Cisco, здесь сознательно не парсится (за рамками конкретной жалобы
    пользователя — "Защита: нет снимка конфигурации" была именно про
    Port Security)."""
    result: dict[str, PortProtection] = {}
    for m in _JUNOS_IFACE_BLOCK_RE.finditer(config):
        limit_match = _JUNOS_MAC_LIMIT_RE.search(m.group(2))
        if not limit_match:
            continue  # interface {...} без mac-limit — не про Port Security
        name = m.group(1)
        result[name] = PortProtection(
            name=name,
            port_security=True,
            max_mac=int(limit_match.group(1)),
            violation=limit_match.group(2),
        )
    return result


def parse_stp_global(config: str) -> dict:
    """Глобальные настройки STP — то, что задаётся не на интерфейсе."""
    priorities = {vlans: int(priority) for vlans, priority in _GLOBAL_PRIORITY.findall(config)}
    mode = _GLOBAL_MODE.search(config)
    return {
        "mode": mode.group(1) if mode else "",
        "loopguard_default": bool(_GLOBAL_LOOPGUARD.search(config)),
        "portfast_bpduguard_default": bool(_GLOBAL_PORTFAST_BPDU.search(config)),
        "vlan_priorities": priorities,
        # Приоритет 0-8192 означает, что коммутатор назначен корнем STP
        # намеренно. Показываем отдельно: корень доступа вместо ядра —
        # классическая причина странной топологии.
        "is_root_somewhere": any(p <= 8192 for p in priorities.values()),
    }


def protection_summary(ports: dict[str, PortProtection], stp: dict) -> dict:
    """Сводка для интерфейса и для проверки «а всё ли защищено»."""
    access_ports = [p for p in ports.values() if not p.is_trunk and _is_physical(p.name)]
    trunks = [p for p in ports.values() if p.is_trunk]
    return {
        "access_total": len(access_ports),
        "with_port_security": sum(1 for p in access_ports if p.port_security),
        "with_bpdu_guard": sum(1 for p in access_ports if p.bpdu_guard),
        # Опасное сочетание: bpdufilter на access-порту отключает
        # обработку BPDU вместо защиты — петля через такой порт не будет
        # ни замечена, ни заблокирована.
        "with_bpdu_filter": sum(1 for p in access_ports if p.bpdu_filter),
        "trunks_total": len(trunks),
        "trunks_with_guard_root": sum(1 for p in trunks if p.guard_root),
        "stp": stp,
    }


def _is_physical(name: str) -> bool:
    return bool(re.match(r"^(Gi|Fa|Te|Twe|Fo|Eth)[a-zA-Z]*\d", name))
