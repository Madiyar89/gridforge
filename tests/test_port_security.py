"""Разбор Port Security и защиты STP из конфигурации.

Ключевой тест здесь — test_leftover_settings_do_not_mean_protected. Он
про реальную ловушку формата Cisco, из-за которой похожий инструмент
показывал защиту на портах, где её уже не было. На настоящих
конфигурациях этой сети таких портов оказалось 161 — то есть ошибка
была бы не теоретической, а массовой.
"""

from app.port_security import (
    parse_port_protection,
    parse_stp_global,
    protection_summary,
    split_interface_blocks,
)

CONFIG = """\
version 15.2
!
spanning-tree mode rapid-pvst
spanning-tree loopguard default
spanning-tree vlan 1-100 priority 4096
!
interface GigabitEthernet1/0/1
 description user port
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/2
 description protection was removed here
 switchport mode access
 switchport port-security maximum 4
 switchport port-security violation restrict
 switchport port-security mac-address sticky
!
interface GigabitEthernet1/0/3
 switchport mode trunk
 spanning-tree guard root
!
interface Vlan1
 ip address 10.0.0.1 255.255.255.0
!
end
"""


def test_interface_blocks_are_split():
    blocks = split_interface_blocks(CONFIG)
    assert set(blocks) == {
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/3",
        "Vlan1",
    }


def test_enabled_port_security_is_detected():
    ports = parse_port_protection(CONFIG)
    port = ports["GigabitEthernet1/0/1"]
    assert port.port_security is True
    assert port.max_mac == 2
    assert port.violation == "restrict"
    assert port.sticky is True


def test_leftover_settings_do_not_mean_protected():
    """Команда `no switchport port-security` убирает только включающую
    строку — maximum/violation/sticky остаются в конфигурации. Проверка
    вхождением подстроки считала бы такой порт защищённым: строка
    «switchport port-security maximum 4» её содержит.

    На реальных конфигурациях этой сети таких портов 161."""
    port = parse_port_protection(CONFIG)["GigabitEthernet1/0/2"]
    assert port.port_security is False   # защиты нет
    assert port.max_mac == 4             # но хвосты остались
    assert port.sticky is True


def test_bpdu_guard_and_portfast():
    ports = parse_port_protection(CONFIG)
    assert ports["GigabitEthernet1/0/1"].bpdu_guard is True
    assert ports["GigabitEthernet1/0/1"].portfast is True
    assert ports["GigabitEthernet1/0/2"].bpdu_guard is False


def test_trunk_and_guard_root():
    port = parse_port_protection(CONFIG)["GigabitEthernet1/0/3"]
    assert port.is_trunk is True
    assert port.guard_root is True


def test_global_stp_settings():
    stp = parse_stp_global(CONFIG)
    assert stp["mode"] == "rapid-pvst"
    assert stp["loopguard_default"] is True
    assert stp["vlan_priorities"] == {"1-100": 4096}
    assert stp["is_root_somewhere"] is True  # 4096 <= 8192


def test_root_detection_ignores_default_priority():
    """32768 — значение по умолчанию, оно не означает намеренного корня."""
    config = "spanning-tree vlan 1-100 priority 32768\n"
    assert parse_stp_global(config)["is_root_somewhere"] is False


def test_summary_counts_only_physical_access_ports():
    """Vlan1 — виртуальный интерфейс, в счёт access-портов он не идёт."""
    ports = parse_port_protection(CONFIG)
    summary = protection_summary(ports, parse_stp_global(CONFIG))
    assert summary["access_total"] == 2          # Gi1/0/1 и Gi1/0/2
    assert summary["with_port_security"] == 1    # только Gi1/0/1
    assert summary["trunks_total"] == 1
    assert summary["trunks_with_guard_root"] == 1


def test_bpdu_filter_counted_separately_from_guard():
    """bpdufilter на access-порту не защищает, а наоборот отключает
    обработку BPDU — петля через такой порт не будет ни замечена, ни
    заблокирована. Поэтому он считается отдельно, а не вместе с guard."""
    config = """\
interface GigabitEthernet1/0/9
 switchport mode access
 spanning-tree bpdufilter enable
!
"""
    ports = parse_port_protection(config)
    summary = protection_summary(ports, parse_stp_global(config))
    assert summary["with_bpdu_filter"] == 1
    assert summary["with_bpdu_guard"] == 0


def test_empty_config_is_handled():
    assert parse_port_protection("") == {}
    assert parse_stp_global("")["vlan_priorities"] == {}
