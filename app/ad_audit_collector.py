"""Сбор фактов из AD по LDAP для аудита — перенесено из NetOpsHub
(hub/backend/app/modules/ad_audit/collector.py), та же логика запросов,
своя реализация на ldap3 (GridForge уже использует ldap3 для входа
через AD, см. ad_auth.py).

Один проход — несколько LDAP-поисков, результат складывается в плоский
dict ("факты"), дальше правила (ad_audit_rules.py) читают из него, не
трогая LDAP заново — тот же приём, что у сетевого аудита (сначала
извлечь факты из текста конфигурации, потом матчить правила на фактах),
разница только в источнике фактов."""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import ldap3

PRIVILEGED_GROUP_NAMES = ("Domain Admins", "Enterprise Admins")

_WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Не в каждой схеме AD есть эти атрибуты — LAPS (ms-Mcs-AdmPwd) и
# msDS-SupportedEncryptionTypes требуют отдельного расширения схемы,
# которое не всегда установлено. Запрос неизвестного атрибута ldap3
# не игнорирует молча, а роняет весь search LDAPAttributeError'ом —
# поэтому при такой ошибке _entries() повторяет запрос без
# необязательных атрибутов (их отсутствие само по себе валидный факт,
# например для AN3 — LAPS не развёрнут).
_OPTIONAL_SCHEMA_ATTRS = {"ms-Mcs-AdmPwd", "msDS-SupportedEncryptionTypes", "ms-DS-MachineAccountQuota"}


def filetime_to_datetime(value) -> datetime | None:
    """Windows FILETIME (100-нс интервалы с 1601-01-01) -> datetime.
    0 и максимальное int64 — оба означают "никогда" (accountExpires=0
    или =0x7FFFFFFFFFFFFFFF), не реальная дата."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    try:
        return _WINDOWS_EPOCH + timedelta(microseconds=n / 10)
    except (OverflowError, ValueError):
        return None


def uac_has(uac: int | None, bit: int) -> bool:
    return bool((uac or 0) & bit)


def _connect(dc_host: str, port: int, use_ssl: bool, user: str, password: str) -> ldap3.Connection:
    tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
    server = ldap3.Server(dc_host, port=port, use_ssl=use_ssl, tls=tls, connect_timeout=5)
    return ldap3.Connection(server, user=user, password=password, auto_bind=True, receive_timeout=15)


def _entries(conn: ldap3.Connection, base_dn: str, filt: str, attrs: list[str], scope=ldap3.SUBTREE) -> list:
    try:
        conn.search(base_dn, filt, search_scope=scope, attributes=attrs)
    except ldap3.core.exceptions.LDAPException:
        safe_attrs = [a for a in attrs if a not in _OPTIONAL_SCHEMA_ATTRS]
        if safe_attrs == attrs:
            raise
        conn.search(base_dn, filt, search_scope=scope, attributes=safe_attrs)
    return list(conn.entries)


def _attr(entry, name, default=None):
    if name not in entry:
        return default
    val = entry[name].value
    return default if val is None else val


def _attr_list(entry, name) -> list:
    if name not in entry or not entry[name].value:
        return []
    val = entry[name].value
    return val if isinstance(val, list) else [val]


def collect_ad_facts(*, dc_host: str, port: int, use_ssl: bool, user: str, password: str, base_dn: str) -> dict:
    """Синхронная часть (ldap3 не asyncio-нативна) — вызывающая сторона
    оборачивает в asyncio.to_thread, см. run_domain_report."""
    conn = _connect(dc_host, port, use_ssl, user, password)
    now = datetime.now(timezone.utc)

    users = _entries(
        conn, base_dn, "(&(objectClass=user)(objectCategory=person))",
        ["sAMAccountName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
         "accountExpires", "memberOf", "servicePrincipalName", "adminCount",
         "objectSid", "msDS-SupportedEncryptionTypes"],
    )
    computers = _entries(
        conn, base_dn, "(objectClass=computer)",
        ["sAMAccountName", "userAccountControl", "lastLogonTimestamp",
         "operatingSystem", "primaryGroupID", "ms-Mcs-AdmPwd"],
    )
    groups = _entries(conn, base_dn, "(objectClass=group)", ["cn", "member"])
    trusts = _entries(
        conn, base_dn, "(objectClass=trustedDomain)",
        ["cn", "trustAttributes", "trustDirection", "trustType"],
    )
    krbtgt = _entries(conn, base_dn, "(sAMAccountName=krbtgt)", ["pwdLastSet"])

    domain_entries = _entries(
        conn, base_dn, "(objectClass=domain)",
        ["pwdProperties", "minPwdLength", "ms-DS-MachineAccountQuota"],
        scope=ldap3.BASE,
    )
    domain_obj = domain_entries[0] if domain_entries else None

    recycle_bin_entries = _entries(
        conn,
        f"CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{base_dn}",
        "(objectClass=*)", ["msDS-EnabledFeatureBL"], scope=ldap3.BASE,
    )
    recycle_bin_enabled = bool(recycle_bin_entries and _attr_list(recycle_bin_entries[0], "msDS-EnabledFeatureBL"))

    conn.unbind()

    # Привилегированные группы — прямые члены (member), без рекурсии
    # (тот же охват, что в NetOpsHub — вложенные группы внутри Domain
    # Admins реальны редко и добавляют сложность без явного запроса).
    # По группам отдельно (P1 — лимит на КАЖДУЮ группу) и общий набор
    # (P2/P4/P5/P7 — не важно, через какую именно группу привилегия).
    privileged_group_members: dict[str, set[str]] = {name: set() for name in PRIVILEGED_GROUP_NAMES}
    privileged_members: set[str] = set()
    for g in groups:
        cn = str(_attr(g, "cn", ""))
        if cn in PRIVILEGED_GROUP_NAMES:
            for dn in _attr_list(g, "member"):
                privileged_group_members[cn].add(str(dn))
                privileged_members.add(str(dn))

    stale_cutoff = now - timedelta(days=90)
    pwd_max_age_cutoff = now - timedelta(days=365)

    spn_owners: dict[str, list[str]] = {}
    for u in users:
        sam = str(_attr(u, "sAMAccountName", str(u.entry_dn)))
        for spn in _attr_list(u, "servicePrincipalName"):
            spn_owners.setdefault(str(spn), []).append(sam)

    return {
        "users": users,
        "computers": computers,
        "groups": groups,
        "trusts": trusts,
        "krbtgt": krbtgt[0] if krbtgt else None,
        "domain_obj": domain_obj,
        "recycle_bin_enabled": recycle_bin_enabled,
        "privileged_members": privileged_members,
        "privileged_group_members": privileged_group_members,
        "spn_owners": spn_owners,
        "now": now,
        "stale_cutoff": stale_cutoff,
        "pwd_max_age_cutoff": pwd_max_age_cutoff,
    }
