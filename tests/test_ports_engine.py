"""Разбор вывода состояния портов.

Образцы ниже повторяют СТРУКТУРУ реального вывода с оборудования
владельца — выравнивание колонок, пустое поле Name, имена с пробелами и
«>>», разную ширину колонки Port у разных моделей. Содержимое при этом
вымышленное: настоящие имена линков и номера VLAN боевой сети в
репозиторий продукта попадать не должны.

Именно эти особенности формата и ломают наивный разбор, поэтому они
здесь воспроизведены дословно.
"""

import pytest

from app.models import Vendor
from app.ports_engine import (
    PortState,
    group_ports,
    parse_cisco_status,
    parse_junos_combined,
    parse_junos_descriptions,
    parse_junos_terse,
    parse_junos_vlan_info,
    parse_ports,
)

# Узкая колонка Port (10 символов) — как у одной из моделей.
CISCO_NARROW = """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   ADMIN SHUTDOWN     connected    308        a-full  a-100 10/100/1000BaseTX
Gi1/0/2                      connected    308        a-full a-1000 10/100/1000BaseTX
Gi1/0/3   ADMIN SHUTDOWN     notconnect   308          auto   auto 10/100/1000BaseTX
Gi1/0/4   proverka           disabled     513          auto   auto 10/100/1000BaseTX
"""

# Широкая колонка Port (13 символов) и описания с «>>» — другая модель.
CISCO_WIDE = """\
Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      >> Link to core    connected    trunk      a-full  a-100 10/100/1000BaseTX
Gi1/0/2      >> Link to floor   err-disabled 777          auto   auto 10/100/1000BaseTX
Gi1/1/1                         notconnect   1            auto   auto 10/100/1000BaseTX
"""


def test_port_names_and_states():
    ports = parse_cisco_status(CISCO_NARROW)
    assert [p.name for p in ports] == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"]
    assert [p.state for p in ports] == [
        PortState.UP,
        PortState.UP,
        PortState.NOT_CONNECTED,
        PortState.DISABLED,
    ]


def test_description_with_spaces_does_not_shift_columns():
    """Главная ловушка формата: «ADMIN SHUTDOWN» — это ОДНО поле из двух
    слов. Разбор по пробелам принял бы «SHUTDOWN» за статус."""
    ports = parse_cisco_status(CISCO_NARROW)
    assert ports[0].description == "ADMIN SHUTDOWN"
    assert ports[0].state == PortState.UP  # именно connected, а не «shutdown»


def test_empty_description_is_not_confused_with_status():
    ports = parse_cisco_status(CISCO_NARROW)
    assert ports[1].description == ""
    assert ports[1].state == PortState.UP
    assert ports[1].vlan == "308"


def test_wider_port_column_is_handled():
    """У разных моделей ширина колонок отличается — границы берутся из
    заголовка конкретного вывода, а не зашиты числами."""
    ports = parse_cisco_status(CISCO_WIDE)
    assert [p.name for p in ports] == ["Gi1/0/1", "Gi1/0/2", "Gi1/1/1"]
    assert ports[0].description == ">> Link to core"


def test_trunk_is_detected():
    ports = parse_cisco_status(CISCO_WIDE)
    assert ports[0].is_trunk is True
    assert ports[0].vlan == "trunk"
    assert ports[1].is_trunk is False


def test_err_disabled_is_its_own_state():
    """err-disabled — не то же самое, что выключенный вручную: порт
    отключила сама защита, и разбираться надо по-разному."""
    ports = parse_cisco_status(CISCO_WIDE)
    assert ports[1].state == PortState.ERR_DISABLED


def test_unknown_state_is_marked_not_guessed():
    output = CISCO_NARROW.replace("connected ", "wobbling  ", 1)
    ports = parse_cisco_status(output)
    assert ports[0].state == PortState.UNKNOWN
    assert ports[0].extras["raw_state"] == "wobbling"


def test_garbage_output_gives_empty_list_not_crash():
    assert parse_cisco_status("") == []
    assert parse_cisco_status("% Invalid input detected at '^' marker.") == []
    assert parse_cisco_status("Router>") == []


def test_prompt_lines_are_skipped():
    noisy = CISCO_NARROW + "SW-1#\nSW-1#exit\n"
    assert len(parse_cisco_status(noisy)) == 4


# --- Juniper: формат по документации, на живом выводе не проверен ---

JUNOS_TERSE = """\
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   eth-switch
ge-0/0/1                up    down
ge-0/0/2                down  down
ae0                     up    up
"""


def test_junos_physical_ports_only():
    """Логический подынтерфейс (ge-0/0/0.0) и агрегат (ae0) на схеме
    портов не рисуются — там только физические."""
    ports = parse_junos_terse(JUNOS_TERSE)
    assert [p.name for p in ports] == ["ge-0/0/0", "ge-0/0/1", "ge-0/0/2"]


def test_junos_states():
    ports = parse_junos_terse(JUNOS_TERSE)
    assert ports[0].state == PortState.UP             # admin up, link up
    assert ports[1].state == PortState.NOT_CONNECTED  # admin up, link down
    assert ports[2].state == PortState.DISABLED       # admin down


def test_vendor_dispatch():
    assert parse_ports(Vendor.junos, JUNOS_TERSE)[0].name == "ge-0/0/0"
    assert parse_ports(Vendor.cisco_ios, CISCO_NARROW)[0].name == "Gi1/0/1"


# Реальный вывод с живого EX (LAB-28, 2026-09-25) — структура и
# выравнивание дословные, содержимое (имена линков, VLAN) вымышленное,
# тот же принцип, что у образцов Cisco выше. `show interfaces terse`
# физически не содержит description/VLAN — это отдельные команды,
# отсюда три разных фикстуры ниже вместо одной.
JUNOS_DESCRIPTIONS = """\
Interface       Admin Link Description
ge-0/0/0        down  down ADMIN SHUTDOWN
ge-0/0/1        up    up   LINK_to_SW2-Gi1/0/48
"""

# Trunk-порт (ge-0/0/1) печатается НЕСКОЛЬКИМИ строками — первая с именем
# интерфейса, дальше только VLAN/Tag/Tagging без повтора имени.
JUNOS_ETH_SWITCHING = """\
Interface    State  VLAN members        Tag   Tagging  Blocking
ae0.0        down   VLAN_A              100   tagged   blocked by STP
ge-0/0/0.0   down   VLAN_B              999   untagged blocked by STP
ge-0/0/1.0   up     VLAN_A              100   tagged   unblocked
                    VLAN_C              200   tagged   unblocked
ge-0/0/2.0   up     VLAN_B              999   untagged unblocked
"""


def test_junos_descriptions_only_lists_ports_that_have_one():
    result = parse_junos_descriptions(JUNOS_DESCRIPTIONS)
    assert result == {"ge-0/0/0": "ADMIN SHUTDOWN", "ge-0/0/1": "LINK_to_SW2-Gi1/0/48"}
    assert "ge-0/0/2" not in result  # без описания — просто нет строки в выводе


def test_junos_vlan_info_access_port():
    result = parse_junos_vlan_info(JUNOS_ETH_SWITCHING)
    assert result["ge-0/0/2"] == {"tags": ["999"], "trunk": False}


def test_junos_vlan_info_trunk_port_spans_multiple_lines():
    """Реальная находка на живом устройстве: trunk-порт не в одной
    строке — вторая VLAN идёт отдельной строкой без имени интерфейса,
    наивный разбор по фиксированным колонкам потерял бы её."""
    result = parse_junos_vlan_info(JUNOS_ETH_SWITCHING)
    assert result["ge-0/0/1"] == {"tags": ["100", "200"], "trunk": True}


def test_junos_vlan_info_skips_aggregated_interfaces():
    result = parse_junos_vlan_info(JUNOS_ETH_SWITCHING)
    assert "ae0" not in result


def test_junos_combined_merges_all_three_commands():
    ports = parse_junos_combined(JUNOS_TERSE, JUNOS_DESCRIPTIONS, JUNOS_ETH_SWITCHING)
    by_name = {p.name: p for p in ports}
    assert by_name["ge-0/0/0"].description == "ADMIN SHUTDOWN"
    assert by_name["ge-0/0/2"].vlan == "999"
    assert by_name["ge-0/0/2"].is_trunk is False


def test_junos_combined_missing_description_snapshot_does_not_crash():
    """Best-effort: если description/VLAN не удалось снять (устройство
    не ответило на одну из трёх команд), остальные данные всё равно
    сохраняются — не всё-или-ничего."""
    ports = parse_junos_combined(JUNOS_TERSE, "", "")
    assert [p.name for p in ports] == ["ge-0/0/0", "ge-0/0/1", "ge-0/0/2"]
    assert ports[0].description == ""


def test_node_without_vendor_is_parsed_as_cisco():
    """Вендор у узла может быть не заполнен — не повод терять данные."""
    assert parse_ports(None, CISCO_NARROW)[0].name == "Gi1/0/1"


def test_wrong_format_gives_nothing_rather_than_wrong_data():
    """Juniper-вывод, разобранный как Cisco, должен дать пустой список —
    молчание лучше выдуманных портов."""
    assert parse_ports(Vendor.cisco_ios, JUNOS_TERSE) == []


# --- группировка для схемы ---


def test_ports_grouped_by_module():
    """48 портов основного модуля и 4 аплинка — разные ряды на схеме."""
    groups = group_ports(parse_cisco_status(CISCO_WIDE))
    assert [g["prefix"] for g in groups] == ["Gi1/0", "Gi1/1"]
    assert [p.name for p in groups[0]["ports"]] == ["Gi1/0/1", "Gi1/0/2"]


def test_junos_ports_grouped_by_pic_not_one_per_port():
    """Регрессия: у Juniper буквенный префикс отделён дефисом (ge-0/0/0),
    и старая регулярка (без "-?") вообще не совпадала с таким именем —
    каждый порт уходил в собственную группу из одного элемента вместо
    одной сетки на весь PIC, как для Cisco."""
    groups = group_ports(parse_junos_terse(JUNOS_TERSE))
    assert len(groups) == 1
    assert groups[0]["prefix"] == "ge-0/0"
    assert len(groups[0]["ports"]) > 1


def test_ports_sorted_numerically_not_alphabetically():
    """По алфавиту Gi1/0/10 встал бы между Gi1/0/1 и Gi1/0/2 — на схеме
    порты обязаны идти по номерам."""
    output = """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/10                     connected    1          a-full a-1000 10/100/1000BaseTX
Gi1/0/2                      connected    1          a-full a-1000 10/100/1000BaseTX
Gi1/0/1                      connected    1          a-full a-1000 10/100/1000BaseTX
"""
    groups = group_ports(parse_cisco_status(output))
    assert [p.name for p in groups[0]["ports"]] == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/10"]


# --- регрессии, найденные на реальных снимках с боевых коммутаторов ---


def test_management_port_without_slash_is_kept():
    """Fa0 — management-интерфейс, слэша в имени нет. Первая версия
    требовала слэш обязательно и молча теряла шесть таких портов на
    реальных снимках."""
    output = """\
Port      Name               Status       Vlan       Duplex  Speed Type 
Fa0                          notconnect   1            auto   auto 10/100BaseTX
Gi1/0/1                      connected    1          a-full a-1000 10/100/1000BaseTX
"""
    ports = parse_cisco_status(output)
    assert [p.name for p in ports] == ["Fa0", "Gi1/0/1"]


def test_hex_blocks_below_the_table_are_not_taken_for_ports():
    """В снимке под таблицей идут другие секции конфигурации, включая
    hex-блоки сертификатов. Их строки случайно похожи на «имя + поле», и
    разбор принимал ABBD8026 за порт со статусом 414d414d."""
    output = """\
Port      Name               Status       Vlan       Duplex  Speed Type 
Gi1/0/1                      connected    1          a-full a-1000 10/100/1000BaseTX

crypto pki certificate chain TP-self-signed
 certificate self-signed 01
  ABBD8026 414d414d E3AF3082 0123A003
  DC040016 69B00830 0D06092A 864886F7
"""
    ports = parse_cisco_status(output)
    assert [p.name for p in ports] == ["Gi1/0/1"]
