"""Белый список команд для массового прогона (Sweep).

Почему список белый, а не чёрный. Обычная SSH-консоль GridForge
(console_ws.py) намеренно ничего не ограничивает: там человек сидит на
одном узле и отвечает за то, что вводит. Здесь всё иначе — одна строка
уходит сразу на десятки боевых коммутаторов, и опечатка вроде `reload`
превращается в аварию всей сети. Поэтому разрешено только то, что
перечислено явно, а не «всё, кроме опасного»: чёрный список всегда
неполон, а цена пропуска тут слишком велика.

Команды только читают состояние. Ничего, что меняет конфигурацию, сюда
не попадает даже с подтверждением — для изменений есть отдельные,
осознанно узкие механизмы.

Отдельная тонкость про `|`. На сетевом CLI это безобидный фильтр вывода
(`show run | include username`), но тот же символ в POSIX-шелле —
конвейер, а узлом может оказаться обычный Linux-сервер. Поэтому канал
разрешён, но только с известными фильтрами и только один раз: см.
_SAFE_FILTERS и validate_custom_command.
"""

from __future__ import annotations

import re

from app.models import Vendor

# Готовые кнопки. Ключ — что спрашиваем, значение — как это звучит у
# каждого вендора. Вендор берётся у самого узла (Node.vendor); для узлов
# без вендора используется вариант cisco_ios как самый распространённый в
# этом парке — и это честно показывается в интерфейсе.
PRESETS: dict[str, dict] = {
    "interfaces": {
        "label": "Интерфейсы",
        "hint": "краткое состояние портов",
        "by_vendor": {
            Vendor.cisco_ios: "show ip interface brief",
            Vendor.junos: "show interfaces terse",
        },
    },
    "routes": {
        "label": "Маршруты",
        "hint": "таблица маршрутизации",
        "by_vendor": {
            Vendor.cisco_ios: "show ip route",
            Vendor.junos: "show route",
        },
    },
    "mac_table": {
        "label": "MAC-таблица",
        "hint": "кто подключён к портам",
        "by_vendor": {
            Vendor.cisco_ios: "show mac address-table",
            Vendor.junos: "show ethernet-switching table",
        },
    },
    "arp": {
        "label": "ARP",
        "hint": "соответствие IP и MAC",
        "by_vendor": {
            Vendor.cisco_ios: "show arp",
            Vendor.junos: "show arp",
        },
    },
    "neighbors": {
        "label": "Соседи",
        "hint": "LLDP/CDP — что подключено рядом",
        "by_vendor": {
            Vendor.cisco_ios: "show cdp neighbors detail",
            Vendor.junos: "show lldp neighbors",
        },
    },
    "version": {
        "label": "Версия",
        "hint": "модель и версия прошивки",
        "by_vendor": {
            Vendor.cisco_ios: "show version",
            Vendor.junos: "show version",
        },
    },
    "logs": {
        "label": "Логи",
        "hint": "последние события",
        "by_vendor": {
            Vendor.cisco_ios: "show logging | last 20",
            Vendor.junos: "show log messages | last 20",
        },
    },
    "local_users": {
        "label": "Учётки",
        "hint": "локальные пользователи в конфигурации",
        "by_vendor": {
            Vendor.cisco_ios: "show running-config | include username",
            Vendor.junos: "show configuration system login",
        },
    },
}

_DEFAULT_VENDOR = Vendor.cisco_ios

# Глаголы, с которых может начинаться произвольный запрос. Все они только
# читают: show/display — вывод состояния, ping/traceroute — диагностика
# связности. Ничего, что пишет в конфигурацию или перезагружает.
_ALLOWED_VERBS = {"show", "display", "ping", "traceroute", "tracert"}

# Фильтры после `|`, которые есть в CLI сетевых вендоров и не делают
# ничего, кроме отбора строк.
_SAFE_FILTERS = {"include", "exclude", "match", "begin", "section", "last", "count", "no-more", "grep"}

# Символы, через которые в POSIX-шелле склеивается вторая команда. На
# сетевом CLI они не нужны ни для чего, а если узел окажется обычным
# сервером — это прямой путь к выполнению произвольного кода.
_SHELL_METACHARACTERS = [";", "&", "`", "$(", "${", ">", "<", "\n", "\r", "&&", "||"]

MAX_COMMAND_LENGTH = 200


class CommandRejected(ValueError):
    """Команда не прошла проверку. Текст — то, что видит пользователь."""


def command_for_node(preset_key: str, vendor: Vendor | None) -> str:
    preset = PRESETS.get(preset_key)
    if preset is None:
        raise CommandRejected(f"Неизвестная команда: {preset_key!r}")
    by_vendor = preset["by_vendor"]
    return by_vendor.get(vendor or _DEFAULT_VENDOR, by_vendor[_DEFAULT_VENDOR])


def validate_custom_command(raw: str) -> str:
    """Проверяет произвольный запрос. Возвращает нормализованную команду
    или бросает CommandRejected с понятной причиной."""
    original = raw or ""

    # Опасные символы ищем в ИСХОДНОЙ строке, до схлопывания пробелов.
    # Иначе перевод строки («show version\nreload» — в шелле это две
    # команды) превратился бы в обычный пробел и прошёл бы проверку, тихо
    # став бессмысленным «show version reload». Отказать честно лучше, чем
    # молча выполнить не то, что написал человек.
    for meta in _SHELL_METACHARACTERS:
        if meta in original:
            raise CommandRejected(f"Символ {meta!r} запрещён — через него можно дописать вторую команду")
    if re.search(r"[\x00-\x1f\x7f]", original):
        raise CommandRejected("Команда содержит управляющие символы")

    command = " ".join(original.split())  # только теперь нормализуем пробелы
    if not command:
        raise CommandRejected("Пустая команда")
    if len(command) > MAX_COMMAND_LENGTH:
        raise CommandRejected(f"Слишком длинная команда (больше {MAX_COMMAND_LENGTH} символов)")

    verb = command.split()[0].lower()
    if verb not in _ALLOWED_VERBS:
        allowed = ", ".join(sorted(_ALLOWED_VERBS))
        raise CommandRejected(f"Команда должна начинаться с одного из: {allowed}")

    if "|" in command:
        parts = command.split("|")
        if len(parts) > 2:
            raise CommandRejected("Допустим только один фильтр после |")
        filter_part = parts[1].strip()
        if not filter_part:
            raise CommandRejected("После | не указан фильтр")
        filter_name = filter_part.split()[0].lower()
        if filter_name not in _SAFE_FILTERS:
            allowed = ", ".join(sorted(_SAFE_FILTERS))
            raise CommandRejected(f"После | допустимы только: {allowed}")

    return command


def preset_catalog() -> list[dict]:
    """Список кнопок для интерфейса — без самих команд по вендорам:
    какая именно строка уйдёт на устройство, решается в момент запуска по
    вендору конкретного узла."""
    return [
        {"key": key, "label": preset["label"], "hint": preset["hint"]}
        for key, preset in PRESETS.items()
    ]
