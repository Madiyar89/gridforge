"""Белый список команд массового прогона.

Основная ценность этих тестов — не «разрешённое работает», а «запрет
нельзя обойти». Команда уходит сразу на десятки боевых коммутаторов, и
дыра здесь означает не испорченный ответ, а аварию сети.
"""

import pytest

from app.models import Vendor
from app.sweep_commands import (
    MAX_COMMAND_LENGTH,
    CommandRejected,
    command_for_node,
    preset_catalog,
    validate_custom_command,
)


def test_preset_resolves_per_vendor():
    assert command_for_node("mac_table", Vendor.cisco_ios) == "show mac address-table"
    assert command_for_node("mac_table", Vendor.junos) == "show ethernet-switching table"


def test_node_without_vendor_falls_back_to_cisco():
    """Вендор у узла может быть не заполнен — это не повод падать."""
    assert command_for_node("version", None) == "show version"


def test_unknown_preset_rejected():
    with pytest.raises(CommandRejected):
        command_for_node("reload_everything", Vendor.cisco_ios)


def test_catalog_does_not_leak_raw_commands():
    """Каталог — для кнопок. Конкретная строка выбирается по вендору узла
    в момент запуска, а не приходит с клиента: иначе клиент мог бы
    подменить её на произвольную."""
    for item in preset_catalog():
        assert set(item) == {"key", "label", "hint"}


def test_plain_show_allowed():
    assert validate_custom_command("show version") == "show version"


def test_whitespace_is_normalised():
    assert validate_custom_command("  show    ip   route  ") == "show ip route"


def test_ping_and_traceroute_allowed():
    assert validate_custom_command("ping 10.0.0.1")
    assert validate_custom_command("traceroute 10.0.0.1")


@pytest.mark.parametrize(
    "command",
    [
        "reload",
        "configure terminal",
        "write memory",
        "delete flash:config.text",
        "erase startup-config",
        "request system reboot",
    ],
)
def test_configuration_changing_commands_rejected(command):
    """Ничего, что меняет состояние устройства, не должно проходить —
    даже если очень хочется."""
    with pytest.raises(CommandRejected):
        validate_custom_command(command)


@pytest.mark.parametrize(
    "command",
    [
        "show version; reload",
        "show version && reload",
        "show version || reload",
        "show version & reload",
        "show version `reload`",
        "show version $(reload)",
        "show version ${IFS}reload",
        "show version > /etc/passwd",
        "show version < /etc/passwd",
        "show version\nreload",
        "show version\r\nreload",
    ],
)
def test_second_command_cannot_be_appended(command):
    """Главный способ обойти белый список — начать с разрешённого глагола
    и дописать вторую команду. Узлом может оказаться обычный Linux-сервер,
    где это уже полноценный шелл."""
    with pytest.raises(CommandRejected):
        validate_custom_command(command)


def test_safe_filter_allowed():
    assert validate_custom_command("show running-config | include username")


@pytest.mark.parametrize(
    "command",
    [
        "show version | sh",
        "show version | bash",
        "show version | tee /tmp/x",
        "show version | xargs reload",
    ],
)
def test_dangerous_filters_rejected(command):
    """`|` оставлен ради фильтров сетевого CLI, но на Linux-узле это
    конвейер — поэтому после него допустим только известный фильтр."""
    with pytest.raises(CommandRejected):
        validate_custom_command(command)


def test_multiple_pipes_rejected():
    with pytest.raises(CommandRejected):
        validate_custom_command("show run | include a | include b")


def test_empty_filter_rejected():
    with pytest.raises(CommandRejected):
        validate_custom_command("show run |")


def test_empty_command_rejected():
    with pytest.raises(CommandRejected):
        validate_custom_command("")
    with pytest.raises(CommandRejected):
        validate_custom_command("   ")


def test_too_long_command_rejected():
    with pytest.raises(CommandRejected):
        validate_custom_command("show " + "x" * MAX_COMMAND_LENGTH)


def test_control_characters_rejected():
    with pytest.raises(CommandRejected):
        validate_custom_command("show version\x00reload")


def test_verb_check_is_case_insensitive():
    assert validate_custom_command("SHOW VERSION")


def test_verb_must_be_a_whole_word():
    """`showdown` начинается с «show», но это не команда show."""
    with pytest.raises(CommandRejected):
        validate_custom_command("showdown now")
