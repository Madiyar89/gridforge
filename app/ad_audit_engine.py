"""AD-аудит в духе PingCastle — категории проверок (привилегированные
аккаунты, аномалии UAC, риск Kerberoasting) те же, что в любом типовом
чеклисте гигиены AD (общеизвестные, не защищённая идея PingCastle), сама
реализация — с нуля на ldap3, ни строки чужого кода.

`ldap3` синхронна (нет asyncio-поддержки under the hood для python-ldap
биндингов) — запускается через asyncio.to_thread, чтобы не блокировать
event loop планировщика (тот же принцип, что для CPU-bound работы вообще)."""

from __future__ import annotations

import asyncio
import ssl

import ldap3
from sqlalchemy.orm import Session

from app.models import AdAuditRun, AdFinding, WatchSeverity

# Биты userAccountControl (RFC — задокументированы Microsoft, не чья-то ИС)
UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_PASSWD_NOTREQD = 0x0020

PRIVILEGED_GROUPS = {"Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"}


def _run_sync(server: str, port: int, bind_dn: str, bind_password: str, search_base: str) -> list[dict]:
    """Синхронная часть — вся работа с ldap3 (biblioteka не asyncio-нативна,
    см. docstring модуля). Возвращает список находок как простые dict, без
    зависимости от SQLAlchemy-сессии (та открывается только в вызывающем
    async-коде, см. run_ad_audit)."""
    tls = ldap3.Tls(validate=ssl.CERT_NONE)  # самоподписанные AD-сертификаты в лабораторных доменах — норма
    ldap_server = ldap3.Server(server, port=port, use_ssl=True, tls=tls)
    conn = ldap3.Connection(ldap_server, user=bind_dn, password=bind_password, auto_bind=True)

    findings: list[dict] = []

    conn.search(
        search_base,
        "(&(objectClass=user)(objectCategory=person))",
        attributes=["sAMAccountName", "userAccountControl", "memberOf", "servicePrincipalName"],
    )
    entries = list(conn.entries)

    for entry in entries:
        dn = str(entry.entry_dn)
        sam = str(entry.sAMAccountName) if "sAMAccountName" in entry else dn
        uac = int(entry.userAccountControl.value) if "userAccountControl" in entry and entry.userAccountControl.value is not None else 0
        member_of = [str(g) for g in entry.memberOf] if "memberOf" in entry and entry.memberOf.value else []
        disabled = bool(uac & UAC_ACCOUNTDISABLE)
        in_privileged_group = any(any(f"CN={pg}," in g or g.startswith(f"CN={pg}") for pg in PRIVILEGED_GROUPS) for g in member_of)

        # 1. Отключённый аккаунт, оставшийся в привилегированной группе —
        # классическая находка PingCastle-класса: уволенный/выведенный из
        # эксплуатации аккаунт с забытыми правами администратора домена.
        if disabled and in_privileged_group:
            findings.append(
                {
                    "check_name": "disabled_privileged_account",
                    "severity": WatchSeverity.critical,
                    "dn": dn,
                    "detail": f"{sam}: отключённая учётка остаётся в привилегированной группе ({', '.join(g.split(',')[0] for g in member_of if any(pg in g for pg in PRIVILEGED_GROUPS))})",
                }
            )

        # 2. Пароль не истекает — само по себе не критично для сервисных
        # аккаунтов, но critical, если это ЕЩЁ и привилегированный аккаунт.
        if uac & UAC_DONT_EXPIRE_PASSWORD and not disabled:
            findings.append(
                {
                    "check_name": "password_never_expires",
                    "severity": WatchSeverity.critical if in_privileged_group else WatchSeverity.warning,
                    "dn": dn,
                    "detail": f"{sam}: пароль никогда не истекает" + (" (привилегированная учётка!)" if in_privileged_group else ""),
                }
            )

        # 3. PASSWD_NOTREQD — учётка может иметь пустой пароль.
        if uac & UAC_PASSWD_NOTREQD and not disabled:
            findings.append(
                {
                    "check_name": "password_not_required",
                    "severity": WatchSeverity.critical,
                    "dn": dn,
                    "detail": f"{sam}: флаг PASSWD_NOTREQD — пароль не обязателен",
                }
            )

        # 4. SPN на обычной user-учётке — потенциальная цель Kerberoasting
        # (offline-перебор пароля по TGS-тикету, не требует прав в домене).
        if "servicePrincipalName" in entry and entry.servicePrincipalName.value and not disabled:
            spns = list(entry.servicePrincipalName)
            findings.append(
                {
                    "check_name": "kerberoastable_spn",
                    "severity": WatchSeverity.warning,
                    "dn": dn,
                    "detail": f"{sam}: SPN задан на пользовательской учётке ({', '.join(str(s) for s in spns)}) — цель для Kerberoasting",
                }
            )

    # 5. Больше одного действующего Domain Admin — не обязательно баг, но
    # находка "проверить, все ли обоснованы" (PingCastle делает так же —
    # не блокирует, информирует).
    enabled_domain_admins = [
        str(e.sAMAccountName) for e in entries
        if "sAMAccountName" in e
        and not (int(e.userAccountControl.value or 0) & UAC_ACCOUNTDISABLE)
        and any("CN=Domain Admins," in g or g.startswith("CN=Domain Admins") for g in ([str(x) for x in e.memberOf] if "memberOf" in e and e.memberOf.value else []))
    ]
    if len(enabled_domain_admins) > 1:
        findings.append(
            {
                "check_name": "multiple_domain_admins",
                "severity": WatchSeverity.info,
                "dn": search_base,
                "detail": f"{len(enabled_domain_admins)} действующих Domain Admins: {', '.join(enabled_domain_admins)} — проверить, все ли обоснованы",
            }
        )

    conn.unbind()
    return findings


async def run_ad_audit(db: Session, server: str, bind_dn: str, bind_password: str, search_base: str, port: int = 636) -> AdAuditRun:
    run = AdAuditRun(server=server, search_base=search_base)
    db.add(run)
    db.commit()
    db.refresh(run)

    try:
        raw_findings = await asyncio.to_thread(_run_sync, server, port, bind_dn, bind_password, search_base)
    except ldap3.core.exceptions.LDAPException as exc:
        run.ok = False
        run.error = str(exc) or exc.__class__.__name__
        db.commit()
        db.refresh(run)
        return run

    for f in raw_findings:
        db.add(AdFinding(run_id=run.id, **f))
    db.commit()
    db.refresh(run)
    return run
