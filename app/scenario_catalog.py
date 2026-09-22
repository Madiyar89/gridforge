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
            # Тот же IOS CLI, что у cisco_ios — разница только в транспорте
            # (Telnet вместо SSH, см. device_client.run_device_config), по
            # прямому запросу пользователя (перенос ntp_cisco_telnet.yml).
            "cisco_ios_telnet": (
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
        # syslog_port добавлен по прямому запросу пользователя
        # (2026-09-22, "проверь коммутаторы на предмет отправки логов на
        # 192.0.2.244") — реальная проверка на проде показала, что ни
        # один коммутатор не шлёт логи на сам GridForge, только на старый
        # сборщик NetOpsHub (192.0.2.115, UDP 514 по умолчанию).
        # GridForge слушает НЕ 514 (root не нужен), а 5140 — см.
        # syslog.html/syslog_server.py — без явного порта в команде
        # логи ушли бы на 514, где никто не слушает.
        "params": ["syslog_host", "syslog_port"],
        "commands_by_vendor": {
            "cisco_ios": (
                "configure terminal\n"
                "logging host {syslog_host} transport udp port {syslog_port}\n"
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
            "cisco_ios_telnet": (
                "configure terminal\n"
                "logging host {syslog_host} transport udp port {syslog_port}\n"
                "logging trap notifications\n"
                "end\n"
                "write memory"
            ),
            "junos": (
                "configure\n"
                "set system syslog host {syslog_host} port {syslog_port} any notice\n"
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
            "cisco_ios_telnet": (
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
        "key": "create_local_user",
        "label": "Создать локального пользователя",
        "category": "security",
        "params": ["username", "password", "privilege"],
        "commands_by_vendor": {
            # Своя, упрощённая версия create_local_user_cisco.yml/
            # create_named_local_user_cisco.yml из NetOpsHub — там
            # логин/пароль брались из отдельного vault-хранилища
            # (group_vars/local_device_users), у GridForge такого
            # хранилища нет, поэтому логин/пароль/привилегия — обычные
            # параметры формы запуска, как у остальных сценариев.
            "cisco_ios": (
                "configure terminal\n"
                "username {username} privilege {privilege} secret {password}\n"
                "end\n"
                "write memory"
            ),
            "cisco_ios_telnet": (
                "configure terminal\n"
                "username {username} privilege {privilege} secret {password}\n"
                "end\n"
                "write memory"
            ),
            # Junos не различает числовую привилегию — используем
            # класс super-user (полный доступ), параметр privilege на
            # эту команду не влияет, но остаётся в форме — иначе на
            # Junos-узле поле пришлось бы прятать отдельной логикой,
            # которой у формы сценария сейчас нет.
            "junos": (
                "configure\n"
                "set system login user {username} class super-user authentication plain-text-password\n"
                "{password}\n"
                "{password}\n"
                "commit and-quit"
            ),
        },
    },
    {
        "key": "create_vlan",
        "label": "Создать VLAN на устройстве",
        "category": "config",
        "params": ["vlan_id", "vlan_name"],
        "commands_by_vendor": {
            # Только сам VLAN на устройстве (create_vlan_*.yml из
            # NetOpsHub) — назначение VLAN на конкретный порт уже есть
            # отдельно на странице "Порты" (там же выбор порта, тут его
            # нет и не должно быть).
            "cisco_ios": (
                "configure terminal\n"
                "vlan {vlan_id}\n"
                "name {vlan_name}\n"
                "end\n"
                "write memory"
            ),
            "cisco_ios_telnet": (
                "configure terminal\n"
                "vlan {vlan_id}\n"
                "name {vlan_name}\n"
                "end\n"
                "write memory"
            ),
            "junos": (
                "configure\n"
                "set vlans {vlan_name} vlan-id {vlan_id}\n"
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
            "cisco_ios_telnet": (
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
