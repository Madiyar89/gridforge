"""Команды для точечного изменения одного порта (описание/VLAN/up-down) —
перенесено из NetOpsHub (hub/backend/app/vendor_plugins/cisco_ios.py,
junos.py), та же логика построения команд, без Ansible/Nornir.

Port Security и STP-защита сюда намеренно не попали (см. GridForge
Scenario для массовых изменений и /api/nodes/{id}/protection для чтения
уже настроенной защиты) — это первый, самый частый набор операций с
карточки порта, остальное можно добавить тем же способом позже."""

from __future__ import annotations

from app.device_client import run_device_command
from app.models import Node, Vendor

TELNET_VENDORS_WITH_CISCO_SYNTAX = {Vendor.cisco_ios_telnet}


class PortCommandError(ValueError):
    pass


def build_port_lines(vendor: Vendor | None, port: str, *, description: str | None, vlan: str | None, state: str | None) -> list[str]:
    """Строки, специфичные для конкретного порта (без обвязки
    configure/end/commit — её добавляет build_full_command)."""
    if description is None and vlan is None and state is None:
        raise PortCommandError("хотя бы одно из description/vlan/state обязательно")

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
    username: str,
    password: str | None,
    key_path: str | None,
    conn_port: int,
    timeout_seconds: float,
) -> dict:
    lines = build_port_lines(node.vendor, port, description=description, vlan=vlan, state=state)
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
