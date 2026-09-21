"""Стартовый каталог Scenario — конфигурирующие команды, перенесённые из
плейбуков NetOpsHub (hub/ansible/playbooks/*.yml) на прямой SSH/Telnet,
без Ansible. Список короче исходного каталога NetOpsHub (~70 плейбуков) —
сюда попали только те, что не требуют per-порт данных (VLAN на порту,
security на конкретном интерфейсе и т.п.) и реально безопасны для
массового запуска через выбор узлов, не отдельного узла.

Заполняется один раз при первом старте (см. seed_default_scenarios,
вызывается из lifespan в main.py) — дальше каталог живёт в БД, его можно
менять через сайт (POST/DELETE /api/scenarios), файл этот больше не
источник правды после первого запуска (та же идея, что у catalog.json в
NetOpsHub, только в БД, а не в JSON на диске)."""

from __future__ import annotations

from app.models import Scenario

SEED_SCENARIOS: list[dict] = [
    {
        "key": "ntp_timezone",
        "label": "NTP / часовой пояс",
        "category": "config",
        "params": ["ntp_server", "timezone_name", "timezone_offset", "timezone_iana"],
        "commands_by_vendor": {
            "cisco_ios": (
                "configure terminal\n"
                "clock timezone {timezone_name} {timezone_offset}\n"
                "ntp server {ntp_server} prefer\n"
                "end\n"
                "write memory"
            ),
            "junos": (
                "configure\n"
                "set system time-zone {timezone_iana}\n"
                "set system ntp server {ntp_server} prefer\n"
                "commit and-quit"
            ),
        },
    },
    {
        "key": "syslog_forward",
        "label": "Отправлять логи на сборщик",
        "category": "config",
        "params": ["syslog_host"],
        "commands_by_vendor": {
            "cisco_ios": (
                "configure terminal\n"
                "logging host {syslog_host}\n"
                # "notice" — реальная ошибка ("% Invalid input detected"),
                # найдена вживую на LAB-1 (2026-09-21): Cisco IOS требует
                # полное имя ключевого слова severity — "notifications", не
                # сокращение "notice" (тот же уровень 5, просто другое
                # написание). Скопировано было из hub/ansible/playbooks/
                # enable_syslog_cisco.yml NetOpsHub без проверки вживую.
                "logging trap notifications\n"
                "end\n"
                "write memory"
            ),
            "junos": (
                "configure\n"
                "set system syslog host {syslog_host} any notice\n"
                "commit and-quit"
            ),
        },
    },
    {
        "key": "login_banner",
        "label": "Баннер входа (motd)",
        "category": "config",
        "params": ["banner_text"],
        "commands_by_vendor": {
            "cisco_ios": (
                "configure terminal\n"
                "banner motd $\n"
                "{banner_text}\n"
                "$\n"
                "end\n"
                "write memory"
            ),
            "junos": (
                "configure\n"
                'set system login message "{banner_text}"\n'
                "commit and-quit"
            ),
        },
    },
    {
        "key": "aaa_remove_vty_override",
        "label": "AAA: убрать принудительный privilege 15 с vty 0-4",
        "category": "security",
        "params": [],
        "commands_by_vendor": {
            "cisco_ios": (
                "configure terminal\n"
                "line vty 0 4\n"
                "no privilege level 15\n"
                "end\n"
                "write memory"
            ),
        },
    },
    {
        "key": "aaa_default_local",
        "label": "AAA: добавить default local (для NETCONF)",
        "category": "security",
        "params": [],
        "commands_by_vendor": {
            "cisco_ios": (
                "configure terminal\n"
                "aaa authentication login default local\n"
                "aaa authorization exec default local\n"
                "end\n"
                "write memory"
            ),
        },
    },
]


def seed_default_scenarios(db) -> int:
    """Добавляет отсутствующие сценарии из SEED_SCENARIOS. Идемпотентно —
    сверяется по key, уже существующие не трогает (в т.ч. если их
    отредактировали через сайт)."""
    existing_keys = {row[0] for row in db.query(Scenario.key).all()}
    created = 0
    for entry in SEED_SCENARIOS:
        if entry["key"] in existing_keys:
            continue
        db.add(
            Scenario(
                key=entry["key"],
                label=entry["label"],
                category=entry["category"],
                commands_by_vendor=entry["commands_by_vendor"],
                params=entry["params"],
            )
        )
        created += 1
    if created:
        db.commit()
    return created
