"""STP-защита от петель: root bridge priority + BPDU Guard на
access-портах + Loop Guard на trunk-портах — перенесено из NetOpsHub
(hub/ansible/playbooks/stp_protection_cisco.yml,
stp_protection_juniper.yml), та же логика построения команд, без
Ansible.

В отличие от port_commands.py (один порт) здесь сразу список
access-портов и список trunk-портов — источник этого списка обычно
последний снимок портов узла (is_trunk на каждом порту, см.
GET /api/nodes/{id}/ports), пользователь может его поправить перед
применением.

Junos: Loop Guard для trunk-портов НЕ реализован — тот же осознанный
пропуск, что и в NetOpsHub (команда JunOS для этого не была проверена и
не подтверждена документацией настолько же уверенно, как остальное
здесь, фабриковать вслепую для боевого оборудования не стали — см.
комментарий в оригинальном stp_protection_juniper.yml)."""

from __future__ import annotations

from app.device_client import run_device_config
from app.models import Node, Vendor

STP_BRIDGE_PRIORITY = 0  # 0 = максимальный приоритет (гарантированный root bridge)


class StpProtectionError(ValueError):
    pass


def build_stp_lines(
    vendor: Vendor | None,
    *,
    access_ports: list[str],
    trunk_ports: list[str],
    set_root_bridge: bool,
    root_bridge_vlans: list[str],
    bpdu_guard: bool,
    loop_guard: bool,
) -> list[str]:
    if set_root_bridge and vendor != Vendor.junos and not root_bridge_vlans:
        # PVST у Cisco — свой root bridge на каждый VLAN, дефолта "[1]" нет
        # намеренно (реальная сеть NetOpsHub, где VLAN 1 отключён вообще) —
        # см. комментарий в оригинальном stp_protection_cisco.yml.
        raise StpProtectionError(
            "set_root_bridge включён, но root_bridge_vlans пуст — укажи реальные VLAN этого коммутатора"
        )
    if not set_root_bridge and not (bpdu_guard and access_ports) and not (loop_guard and trunk_ports):
        raise StpProtectionError(
            "нечего применять — включи root bridge, или укажи access-порты (BPDU Guard), или trunk-порты (Loop Guard)"
        )

    if vendor == Vendor.junos:
        lines: list[str] = []
        if set_root_bridge:
            lines.append(f"set protocols rstp bridge-priority {STP_BRIDGE_PRIORITY}")
        for port in access_ports:
            lines.append(f"set protocols rstp interface {port} edge")
        if bpdu_guard and access_ports:
            lines.append("set protocols rstp bpdu-block-on-edge")
        # Loop Guard для trunk-портов — не реализовано, см. докстринг модуля.
        return lines

    # cisco_ios / cisco_ios_telnet
    lines = []
    if set_root_bridge:
        for vlan in root_bridge_vlans:
            lines.append(f"spanning-tree vlan {vlan} root primary")
    if bpdu_guard:
        for port in access_ports:
            lines.append(f"interface {port}")
            lines.append("spanning-tree bpduguard enable")
    if loop_guard:
        for port in trunk_ports:
            lines.append(f"interface {port}")
            lines.append("spanning-tree guard loop")
    return lines


def build_full_lines(vendor: Vendor | None, lines: list[str]) -> list[str]:
    """Полная последовательность строк для интерактивной сессии — см.
    подробный разбор в port_commands.build_full_lines (тот же реальный
    баг с однократным exec на боевых Cisco/Junos)."""
    if vendor == Vendor.junos:
        return ["configure", *lines, "commit and-quit"]
    return ["configure terminal", *lines, "end", "write memory"]


async def apply_stp_protection(
    node: Node,
    *,
    access_ports: list[str],
    trunk_ports: list[str],
    set_root_bridge: bool,
    root_bridge_vlans: list[str],
    bpdu_guard: bool,
    loop_guard: bool,
    username: str,
    password: str | None,
    key_path: str | None,
    conn_port: int,
    timeout_seconds: float,
) -> dict:
    lines = build_stp_lines(
        node.vendor,
        access_ports=access_ports,
        trunk_ports=trunk_ports,
        set_root_bridge=set_root_bridge,
        root_bridge_vlans=root_bridge_vlans,
        bpdu_guard=bpdu_guard,
        loop_guard=loop_guard,
    )
    outcome = await run_device_config(
        vendor=node.vendor,
        host=node.address,
        lines=build_full_lines(node.vendor, lines),
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
