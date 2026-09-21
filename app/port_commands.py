"""Команды для точечного изменения одного порта (описание/VLAN/up-down,
Port Security, отбить порт) — перенесено из NetOpsHub
(hub/backend/app/vendor_plugins/cisco_ios.py, junos.py), та же логика
построения команд, без Ansible/Nornir.

STP-защита (root bridge/BPDU Guard/Loop Guard — операция на чеклист
портов сразу, не один порт) сюда не попала — отдельная фича поверх
Scenario, следующим шагом."""

from __future__ import annotations

import asyncio

from app.device_client import run_device_command
from app.models import Node, Vendor

TELNET_VENDORS_WITH_CISCO_SYNTAX = {Vendor.cisco_ios_telnet}

# Те же дефолты, что в NetOpsHub vendor_plugins (cisco_ios.py
# DEFAULT_PORT_SECURITY_MAXIMUM, junos.py JUNOS_PORT_SECURITY_MAC_LIMIT) —
# включение с одной карточки порта не должно расходиться с тем, что раньше
# делал чеклист.
DEFAULT_PORT_SECURITY_MAXIMUM = 2

BOUNCE_DELAY_SECONDS = 5


class PortCommandError(ValueError):
    pass


def build_port_lines(
    vendor: Vendor | None,
    port: str,
    *,
    description: str | None,
    vlan: str | None,
    state: str | None,
    port_security: str | None = None,
    port_security_maximum: int | str | None = None,
) -> list[str]:
    """Строки, специфичные для конкретного порта (без обвязки
    configure/end/commit — её добавляет build_full_command)."""
    if (
        description is None
        and vlan is None
        and state is None
        and port_security is None
        and not port_security_maximum
    ):
        raise PortCommandError("хотя бы одно из description/vlan/state/port_security/port_security_maximum обязательно")

    if vendor == Vendor.junos:
        lines: list[str] = []
        if description is not None:
            lines.append(f'set interfaces {port} description "{description}"')
        if vlan is not None:
            # "set ... vlan members" ДОБАВЛЯЕТ к списку, не заменяет — сперва
            # снимаем все текущие члены, потом ставим новый (см. разбор в
            # NetOpsHub vendor_plugins/junos.py, реальный баг на LAB-19).
            lines.append(f"delete interfaces {port} unit 0 family ethernet-switching vlan members")
            lines.append(f"set interfaces {port} unit 0 family ethernet-switching vlan members {vlan}")
        if state == "down":
            lines.append(f"set interfaces {port} disable")
        elif state == "up":
            lines.append(f"delete interfaces {port} disable")
        if port_security == "on":
            lines.append(
                f"set ethernet-switching-options secure-access-port interface {port} "
                f"mac-limit {port_security_maximum or DEFAULT_PORT_SECURITY_MAXIMUM} action drop"
            )
        elif port_security == "off":
            lines.append(f"delete ethernet-switching-options secure-access-port interface {port}")
        elif port_security_maximum:
            lines.append(
                f"set ethernet-switching-options secure-access-port interface {port} "
                f"mac-limit {port_security_maximum} action drop"
            )
        return lines

    # cisco_ios / cisco_ios_telnet — общий IOS CLI, применяется внутри
    # "interface {port}" (см. build_full_command).
    lines = []
    if description is not None:
        lines.append(f"description {description}")
    if vlan is not None:
        lines.append(f"switchport access vlan {vlan}")
    if state == "down":
        lines.append("shutdown")
    elif state == "up":
        lines.append("no shutdown")
    if port_security == "on":
        # Без "mac-address sticky" — намеренно (2026-09-11 в NetOpsHub,
        # офис с частыми переездами людей между кабинетами: sticky вешает
        # MAC намертво в конфиг старого порта, при переезде новый порт
        # блокирует тот же MAC как violation). Без sticky MAC учится
        # динамически и сам забывается при обрыве линка.
        lines.append("switchport port-security")
        lines.append(f"switchport port-security maximum {port_security_maximum or DEFAULT_PORT_SECURITY_MAXIMUM}")
        lines.append("switchport port-security violation restrict")
    elif port_security == "off":
        # Снимаем и под-настройки явно — "no switchport port-security" сам
        # по себе оставляет maximum/violation/sticky в running-config "на
        # память" (реальный случай в NetOpsHub, LAB-2 Gi1/0/25).
        lines.append("no switchport port-security")
        lines.append("no switchport port-security maximum")
        lines.append("no switchport port-security violation")
        lines.append("no switchport port-security mac-address sticky")
    elif port_security_maximum:
        lines.append(f"switchport port-security maximum {port_security_maximum}")
    return lines


def build_full_command(vendor: Vendor | None, port: str, lines: list[str]) -> str:
    if vendor == Vendor.junos:
        return "configure\n" + "\n".join(lines) + "\ncommit and-quit"
    return f"configure terminal\ninterface {port}\n" + "\n".join(lines) + "\nend\nwrite memory"


async def apply_port(
    node: Node,
    port: str,
    *,
    description: str | None,
    vlan: str | None,
    state: str | None,
    port_security: str | None,
    port_security_maximum: int | str | None,
    username: str,
    password: str | None,
    key_path: str | None,
    conn_port: int,
    timeout_seconds: float,
) -> dict:
    lines = build_port_lines(
        node.vendor,
        port,
        description=description,
        vlan=vlan,
        state=state,
        port_security=port_security,
        port_security_maximum=port_security_maximum,
    )
    command = build_full_command(node.vendor, port, lines)
    outcome = await run_device_command(
        vendor=node.vendor,
        host=node.address,
        command=command,
        username=username,
        password=password,
        key_path=key_path,
        port=conn_port,
        timeout_seconds=timeout_seconds,
    )
    return {
        "ok": outcome.ok,
        "commands": lines,
        "output": (outcome.stdout or None) if outcome.ok else None,
        "error": outcome.error if not outcome.ok else None,
    }


async def bounce_port(
    node: Node,
    port: str,
    *,
    username: str,
    password: str | None,
    key_path: str | None,
    conn_port: int,
    timeout_seconds: float,
    delay_seconds: float = BOUNCE_DELAY_SECONDS,
) -> dict:
    """shutdown -> пауза -> no shutdown, как в bounce_port_cisco.yml/
    bounce_port_juniper.yml — два отдельных выполнения команды, не одна
    команда со сном внутри (пауза должна быть реальным ожиданием между
    двумя SSH-сессиями, ровно как делал плейбук)."""
    down_lines = build_port_lines(node.vendor, port, description=None, vlan=None, state="down")
    up_lines = build_port_lines(node.vendor, port, description=None, vlan=None, state="up")

    down_outcome = await run_device_command(
        vendor=node.vendor,
        host=node.address,
        command=build_full_command(node.vendor, port, down_lines),
        username=username,
        password=password,
        key_path=key_path,
        port=conn_port,
        timeout_seconds=timeout_seconds,
    )
    if not down_outcome.ok:
        return {"ok": False, "commands": down_lines, "output": None, "error": down_outcome.error}

    await asyncio.sleep(delay_seconds)

    up_outcome = await run_device_command(
        vendor=node.vendor,
        host=node.address,
        command=build_full_command(node.vendor, port, up_lines),
        username=username,
        password=password,
        key_path=key_path,
        port=conn_port,
        timeout_seconds=timeout_seconds,
    )
    return {
        "ok": up_outcome.ok,
        "commands": down_lines + [f"— пауза {delay_seconds:.0f}с —"] + up_lines,
        "output": (up_outcome.stdout or None) if up_outcome.ok else None,
        "error": up_outcome.error if not up_outcome.ok else None,
    }
