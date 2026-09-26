"""Факты для аудита конфигураций сетевого оборудования (Cisco IOS / Junos) —
перенесено из NetOpsHub (hub/backend/app/modules/compliance_audit/facts.py
+ пять проверок из app/config_analysis.py, которые там были отдельным
finding-based путём, здесь слиты в те же факты — у GridForge нет отдельного
слоя findings под бэкапы, только Backup.content).

Тот же стиль: простой re.search по тексту бэкапа running-config, без
TextFSM. Junos-проверки намеренно слабее (substring/loose regex, без опоры
на точную иерархию `show configuration`) — тот же принцип, что в NetOpsHub:
точный формат бэкапа не был исчерпывающе сверен на всех реальных
устройствах, лучше слабый сигнал с явной оговоркой, чем уверенный ложный."""

from __future__ import annotations

import re


def extract_cisco_facts(text: str) -> dict:
    facts: dict = {}

    facts["aaa_configured"] = bool(re.search(r"^aaa new-model\b", text, re.MULTILINE))
    facts["exec_timeout_set"] = bool(re.search(r"^\s*exec-timeout \d+ \d+", text, re.MULTILINE))
    facts["http_server_enabled"] = bool(re.search(r"^ip http(?:-secure)? server\b", text, re.MULTILINE))
    facts["snmp_v2c_enabled"] = bool(re.search(r"^snmp-server community \S+", text, re.MULTILINE))
    facts["snmp_v3_configured"] = "snmp-server group" in text and re.search(r"\bv3\b", text) is not None
    facts["syslog_host_configured"] = bool(re.search(r"^logging host \S+", text, re.MULTILINE))
    facts["hostname_is_default"] = bool(re.search(r"^hostname\s+(Switch|Router)\d*\s*$", text, re.MULTILINE | re.IGNORECASE))

    facts["hostname_raw"] = m.group(1) if (m := re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)) else None
    facts["local_usernames"] = re.findall(r"^username (\S+)", text, re.MULTILINE)
    facts["snmp_community_strings"] = re.findall(r"^snmp-server community (\S+)", text, re.MULTILINE)
    facts["http_server_raw_lines"] = re.findall(r"^(ip http(?:-secure)? server\b.*)$", text, re.MULTILINE)
    facts["line_blocks_present"] = re.findall(r"^line (con \d+|vty \d+(?: \d+)?|aux \d+)", text, re.MULTILINE)

    facts["hsrp_configured"] = bool(re.search(r"^\s*standby \d+ ip\b", text, re.MULTILINE))
    facts["hsrp_auth_configured"] = bool(re.search(r"^\s*standby \d+ authentication\b", text, re.MULTILINE))
    facts["hsrp_priority_set"] = bool(re.search(r"^\s*standby \d+ priority\b", text, re.MULTILINE))
    facts["hsrp_preempt_set"] = bool(re.search(r"^\s*standby \d+ preempt\b", text, re.MULTILINE))
    facts["stp_priority_set"] = bool(re.search(r"^spanning-tree vlan \S+ priority \d+", text, re.MULTILINE))
    facts["ospf_configured"] = bool(re.search(r"^router ospf\b", text, re.MULTILINE))
    facts["ospf_auth_configured"] = "ip ospf authentication" in text
    facts["bgp_configured"] = bool(re.search(r"^router bgp\b", text, re.MULTILINE))
    facts["bgp_auth_configured"] = bool(re.search(r"neighbor \S+ password\b", text))
    facts["bgp_maxprefix_set"] = bool(re.search(r"neighbor \S+ maximum-prefix \d+", text))
    facts["copp_configured"] = bool(re.search(r"^control-plane\b", text, re.MULTILINE)) and "service-policy input" in text
    facts["lacp_configured"] = bool(re.search(r"channel-group \d+ mode active", text))

    facts["access_ports_present"] = bool(re.search(r"switchport (mode access|access vlan)", text))
    facts["port_security_configured"] = "switchport port-security" in text
    facts["port_security_maxmac_set"] = bool(re.search(r"switchport port-security maximum \d+", text))
    facts["dhcp_snooping_configured"] = bool(re.search(r"^ip dhcp snooping\b", text, re.MULTILINE))
    facts["trunk_present"] = "switchport mode trunk" in text
    facts["native_vlan_changed"] = bool(re.search(r"switchport trunk native vlan (?!1\b)\d+", text))
    facts["allowed_vlan_explicit"] = bool(re.search(r"switchport trunk allowed vlan \d", text))
    facts["storm_control_configured"] = bool(re.search(r"storm-control (broadcast|multicast|unicast) level", text))

    facts["finger_enabled"] = bool(re.search(r"^service finger\b", text, re.MULTILINE))
    facts["bootp_server_enabled"] = bool(re.search(r"^ip bootp server\b", text, re.MULTILINE))
    facts["small_servers_enabled"] = bool(re.search(r"^service (tcp|udp)-small-servers\b", text, re.MULTILINE))
    facts["source_route_enabled"] = bool(re.search(r"^ip source-route\b", text, re.MULTILINE))
    facts["proxy_arp_explicitly_disabled"] = bool(re.search(r"^\s*no ip proxy-arp\b", text, re.MULTILINE))

    # --- перенесено из config_analysis.py (было отдельными Finding) ---
    facts["banner_configured"] = bool(re.search(r"^banner\s+motd", text, re.MULTILINE))
    facts["ntp_configured"] = bool(re.search(r"^ntp server\s+\S+", text, re.MULTILINE))
    facts["stp_guard_configured"] = bool(re.search(r"spanning-tree (bpduguard enable|guard loop)", text))

    vty_blocks = re.findall(r"^line vty[^\n]*\n((?: .*\n?)*)", text, re.MULTILINE)
    has_telnet = any(re.search(r"transport input (telnet|all)\b", block) for block in vty_blocks)
    has_ssh_only = any(re.search(r"transport input ssh\b", block) for block in vty_blocks) and not has_telnet
    facts["vty_ssh_only"] = has_ssh_only and not has_telnet
    facts["vty_telnet_raw"] = ["line vty с transport input telnet/all"] if has_telnet else []

    facts["weak_password_type7"] = bool(re.search(r"\bpassword 7 \S+", text))

    # --- доразбор аудита сети (2026-09-26, по прямому запросу пользователя:
    # "написать правила по всему парку") ---
    facts["arp_inspection_configured"] = bool(re.search(r"^ip arp inspection vlan\b", text, re.MULTILINE))
    facts["vty_source_restricted"] = any(
        re.search(r"access-class \S+ in\b", block) for block in vty_blocks
    )
    facts["junos_root_login_denied"] = True  # концепции root-логина как у Junos на Cisco IOS нет — правило не должно на нём срабатывать

    facts["unused_ports_raw"] = _find_unused_cisco_ports(text)

    return facts


def _find_unused_cisco_ports(text: str) -> list[str]:
    """Слабый эвристический сигнал, не факт: интерфейс без `description` и
    без `shutdown` — вероятно, физически не используется и не описан, но
    из статического running-config нельзя узнать реальное состояние линка
    (это operational-вывод show interfaces, не конфиг) — тот же принцип
    "слабый сигнал с явной оговоркой", что уже применяется в этом модуле
    для Junos-фактов (см. докстринг файла). Порт с port-security/access
    vlan, отличным от дефолтного, или подключённый в port-channel — не
    считается "неиспользуемым", даже без description."""
    unused = []
    for m in re.finditer(r"^interface (\S+)\n((?: .*\n?)*)", text, re.MULTILINE):
        name, block = m.group(1), m.group(2)
        if re.search(r"^\s*(description|shutdown|channel-group)\b", block, re.MULTILINE):
            continue
        if re.search(r"switchport (port-security|access vlan (?!1\b)\d)", block):
            continue
        if not re.search(r"^\s*switchport\b", block, re.MULTILINE):
            continue  # не L2-порт (SVI/routed-порт без switchport) — не тот случай, который спрашивали
        unused.append(name)
    return unused


def extract_junos_facts(text: str) -> dict:
    facts: dict = {}
    low = text.lower()

    facts["aaa_configured"] = "authentication-order" in low
    facts["exec_timeout_set"] = bool(re.search(r"idle-timeout \d+", text, re.IGNORECASE))
    facts["http_server_enabled"] = "web-management" in low
    facts["snmp_v2c_enabled"] = "snmp" in low and "community" in low
    facts["snmp_v3_configured"] = "snmp" in low and re.search(r"\bv3\b", low) is not None
    facts["syslog_host_configured"] = "syslog" in low and bool(re.search(r"\bhost\s+\S+", text, re.IGNORECASE))

    facts["hostname_raw"] = m.group(1) if (m := re.search(r"host-name\s+(\S+);", text, re.IGNORECASE)) else None
    facts["local_usernames"] = re.findall(r"login user (\S+)", text, re.IGNORECASE)
    facts["snmp_community_strings"] = re.findall(r"community\s+(\S+)\s*\{", text, re.IGNORECASE)
    facts["http_server_raw_lines"] = ["web-management"] if facts["http_server_enabled"] else []
    facts["line_blocks_present"] = []
    facts["hostname_is_default"] = False  # Junos не имеет аналога заводского hostname вида Switch1

    facts["hsrp_configured"] = "vrrp-group" in low
    facts["hsrp_auth_configured"] = facts["hsrp_configured"] and "authentication-key" in low
    facts["hsrp_priority_set"] = facts["hsrp_configured"] and "priority" in low
    facts["hsrp_preempt_set"] = facts["hsrp_configured"] and "preempt" in low
    facts["stp_priority_set"] = "bridge-priority" in low
    facts["ospf_configured"] = bool(re.search(r"\bospf\b", low))
    facts["ospf_auth_configured"] = facts["ospf_configured"] and ("authentication-key" in low or "authentication-type" in low)
    facts["bgp_configured"] = bool(re.search(r"\bbgp\b", low))
    facts["bgp_auth_configured"] = facts["bgp_configured"] and "authentication-key" in low
    facts["bgp_maxprefix_set"] = facts["bgp_configured"] and "prefix-limit" in low
    facts["copp_configured"] = "policer" in low and "lo0" in low
    facts["lacp_configured"] = "802.3ad" in text or "8023ad" in low

    facts["access_ports_present"] = "ethernet-switching" in low
    facts["port_security_configured"] = "mac-limit" in low
    facts["port_security_maxmac_set"] = bool(re.search(r"mac-limit\s+\d+", text, re.IGNORECASE))
    facts["dhcp_snooping_configured"] = "dhcp-security" in low
    facts["trunk_present"] = bool(re.search(r"\btrunk\b", low))
    facts["native_vlan_changed"] = bool(re.search(r"native-vlan-id\s+(?!1\b)\d+", text, re.IGNORECASE))
    facts["allowed_vlan_explicit"] = "vlan members" in low
    facts["storm_control_configured"] = "storm-control" in low

    facts["finger_enabled"] = False
    facts["bootp_server_enabled"] = False
    facts["small_servers_enabled"] = False
    facts["source_route_enabled"] = "source-route" in low and "no-source-route" not in low
    facts["proxy_arp_explicitly_disabled"] = "no-proxy-arp" in low or "proxy-arp" not in low

    # --- перенесено из config_analysis.py ---
    facts["banner_configured"] = bool(re.search(r'^\s*message\s+"', text, re.MULTILINE)) or bool(
        re.search(r"\blogin\s+message\b", text, re.IGNORECASE)
    )
    facts["ntp_configured"] = bool(re.search(r"\bntp\b", text, re.IGNORECASE)) and bool(re.search(r"\bserver\b", text, re.IGNORECASE))
    facts["stp_guard_configured"] = "bpdu-block-on-edge" in text
    facts["vty_ssh_only"] = True  # Junos управляется через netconf/ssh, отдельного transport-input-эквивалента нет
    facts["vty_telnet_raw"] = []
    facts["weak_password_type7"] = False  # Junos не имеет аналога обратимого type 7

    # --- доразбор аудита сети (2026-09-26) ---
    facts["arp_inspection_configured"] = "arp-inspection" in low
    facts["vty_source_restricted"] = True  # управление доступом к самому Junos — через firewall filter на lo0, не VTY-аналог; отдельная тема, не эта проверка
    facts["junos_root_login_denied"] = bool(re.search(r"root-login\s+deny\b", text, re.IGNORECASE))
    facts["unused_ports_raw"] = _find_unused_junos_ports(text)

    return facts


def _top_level_blocks(text: str, header: str) -> list[tuple[str, str]]:
    """Разбор иерархического Junos-конфига (`show configuration`, фигурные
    скобки — реальный формат бэкапа, не `| display set`, живой прогон
    2026-09-26 поймал именно это несоответствие). Ищет `header { ... }` на
    верхнем уровне, возвращает дочерние блоки первого уровня внутри как
    [(имя, содержимое)] — учитывает вложенные фигурные скобки простым
    счётчиком глубины, не полноценный парсер Junos, но для "есть ли
    description/disable внутри блока интерфейса" этого достаточно."""
    m = re.search(re.escape(header) + r"\s*\{", text)
    if not m:
        return []
    start = m.end()
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    body = text[start : i - 1]

    blocks = []
    depth = 0
    child_start = None
    child_name = None
    j = 0
    while j < len(body):
        ch = body[j]
        if depth == 0 and ch not in "{}\n" and child_name is None:
            # начало имени дочернего блока — читаем до "{"
            k = body.find("{", j)
            if k == -1:
                break
            child_name = body[j:k].strip()
            child_start = k + 1
            depth = 1
            j = child_start
            continue
        if depth >= 1:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((child_name, body[child_start : j]))
                    child_name = None
        j += 1
    return blocks


def _find_unused_junos_ports(text: str) -> list[str]:
    """Тот же слабый эвристический сигнал, что у Cisco (см.
    _find_unused_cisco_ports) — интерфейс без description и без явного
    disable; где-либо внутри своего блока (в т.ч. вложенно, под unit)."""
    unused = []
    for name, block in _top_level_blocks(text, "interfaces"):
        if not name or name.startswith(("lo", "vlan", "irb", "ae")):
            continue  # логические/агрегированные интерфейсы — не тот "физический незанятый порт", который спрашивали
        if "unit" not in block:
            continue  # нет ни одной unit-конфигурации — не L2-порт в обычном смысле здесь
        if re.search(r"\bdescription\b", block) or re.search(r"^\s*disable\s*;", block, re.MULTILINE):
            continue
        unused.append(name)
    return sorted(unused)


def extract_facts(vendor: str, text: str) -> dict | None:
    """vendor — значение app.models.Vendor. None, если вендор не поддержан
    (аудит честно исключает такие устройства, не подставляет нули)."""
    if vendor in ("cisco_ios", "cisco_ios_telnet"):
        return extract_cisco_facts(text)
    if vendor == "junos":
        return extract_junos_facts(text)
    return None
