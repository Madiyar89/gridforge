"""IP → hostname/пользователь — своя версия Graylog-поиска из NetOpsHub,
но без Graylog: ищем по уже накопленным SyslogMessage (см. syslog_server.py)
вместо похода во внешний стек. На небольшом-среднем объёме сообщений
(лабораторный/офисный масштаб, не оператор связи) собственная таблица —
достаточный источник данных, не хуже отдельного Graylog для этой задачи.

Извлечение hostname/пользователя — эвристика по паттернам типовых логов
(DHCP-аренда, аутентификация), не гарантированный разбор произвольного
формата — честно возвращаем None, если паттерн не совпал, не гадаем."""

from __future__ import annotations

import re

# isc-dhcp: "DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (client-host) via eth0"
_DHCP_ISC_RE = re.compile(
    r"DHCPACK\s+on\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+[0-9a-f:]{17}\s+\((?P<host>[\w.-]+)\)",
    re.IGNORECASE,
)
# dnsmasq: "DHCPACK(eth0) 192.168.1.50 aa:bb:cc:dd:ee:ff client-host"
_DHCP_DNSMASQ_RE = re.compile(
    r"DHCPACK\([^)]*\)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+[0-9a-f:]{17}\s+(?P<host>[\w.-]+)",
    re.IGNORECASE,
)
# sshd/auth: "Accepted password for jdoe from 10.0.0.5 port 51000"
_AUTH_RE = re.compile(r"Accepted \w+ for (?P<user>[\w.-]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
# общий "hostname 'X'" / "host=X" паттерн некоторых устройств
_GENERIC_HOST_RE = re.compile(r"host(?:name)?[=:\s]+['\"]?(?P<host>[\w.-]+)['\"]?", re.IGNORECASE)


def extract_hints(message: str) -> dict:
    """Возвращает {"hostname": ..., "user": ...} — оба поля None, если
    ничего не распозналось (не выдумываем)."""
    hostname = None
    user = None

    m = _DHCP_ISC_RE.search(message) or _DHCP_DNSMASQ_RE.search(message)
    if m:
        hostname = m.group("host")

    m = _AUTH_RE.search(message)
    if m:
        user = m.group("user")

    if hostname is None:
        m = _GENERIC_HOST_RE.search(message)
        if m:
            hostname = m.group("host")

    return {"hostname": hostname, "user": user}
