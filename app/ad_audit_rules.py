"""Каталог правил AD-аудита — перенесено из NetOpsHub
(hub/backend/app/modules/ad_audit/rules.py), тот же список из 25 правил
по 4 категориям, та же логика проверок (в духе PingCastle — общеизвестный
набор проверок гигиены AD, не защищённый код самого PingCastle).

Не реализовано (осознанно, как и в NetOpsHub) — T3 (доверие фактически
не используется: нужны логи аутентификации, не атрибут LDAP), AN5-AN7
(анонимный bind / LDAP signing / SMB1 — сетевые проверки, не атрибуты
LDAP). Естественная точка расширения на будущее, не пропуск."""

from __future__ import annotations

from app.ad_audit_collector import _attr, _attr_list, filetime_to_datetime, uac_has
from app.risk_scoring import Rule

CATALOG_VERSION = "1.1"
CATALOG_UPDATED_AT = "2026-09-14"

CAT_STALE = "Устаревшие объекты"
CAT_PRIVILEGED = "Привилегированные учётки"
CAT_TRUSTS = "Доверительные отношения"
CAT_ANOMALIES = "Аномалии безопасности"

UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQUIRE_PREAUTH = 0x400000
MSDS_RC4 = 0x4
TRUST_ATTR_NON_TRANSITIVE = 0x1
TRUST_ATTR_FILTER_SIDS = 0x4
PRIVILEGED_GROUP_MAX_MEMBERS = 5


def _sam(entry) -> str:
    return str(_attr(entry, "sAMAccountName", str(entry.entry_dn)))


def _uac(entry) -> int:
    return int(_attr(entry, "userAccountControl", 0) or 0)


def _is_disabled(entry) -> bool:
    return uac_has(_uac(entry), UAC_ACCOUNTDISABLE)


# ============================== S — Устаревшие объекты ==============================

def _s1_check(facts: dict) -> bool:
    return not any(
        not _is_disabled(u)
        and (lt := filetime_to_datetime(_attr(u, "lastLogonTimestamp")))
        and lt < facts["stale_cutoff"]
        for u in facts["users"]
    )


def _s1_objects(facts: dict) -> list[str]:
    return [
        _sam(u) for u in facts["users"]
        if not _is_disabled(u)
        and (lt := filetime_to_datetime(_attr(u, "lastLogonTimestamp")))
        and lt < facts["stale_cutoff"]
    ]


def _s2_check(facts: dict) -> bool:
    return not any(
        not _is_disabled(c)
        and (lt := filetime_to_datetime(_attr(c, "lastLogonTimestamp")))
        and lt < facts["stale_cutoff"]
        for c in facts["computers"]
    )


def _s2_objects(facts: dict) -> list[str]:
    return [
        _sam(c) for c in facts["computers"]
        if not _is_disabled(c)
        and (lt := filetime_to_datetime(_attr(c, "lastLogonTimestamp")))
        and lt < facts["stale_cutoff"]
    ]


def _s3_check(facts: dict) -> bool:
    return not any(
        not uac_has(_uac(u), UAC_DONT_EXPIRE_PASSWORD)
        and (pw := filetime_to_datetime(_attr(u, "pwdLastSet")))
        and pw < facts["pwd_max_age_cutoff"]
        for u in facts["users"]
    )


def _s3_objects(facts: dict) -> list[str]:
    return [
        _sam(u) for u in facts["users"]
        if not uac_has(_uac(u), UAC_DONT_EXPIRE_PASSWORD)
        and (pw := filetime_to_datetime(_attr(u, "pwdLastSet")))
        and pw < facts["pwd_max_age_cutoff"]
    ]


def _s4_check(facts: dict) -> bool:
    return not any(
        not _is_disabled(u)
        and (exp := filetime_to_datetime(_attr(u, "accountExpires")))
        and exp < facts["now"]
        for u in facts["users"]
    )


def _s4_objects(facts: dict) -> list[str]:
    return [
        _sam(u) for u in facts["users"]
        if not _is_disabled(u)
        and (exp := filetime_to_datetime(_attr(u, "accountExpires")))
        and exp < facts["now"]
    ]


def _s5_check(facts: dict) -> bool:
    return not any(not _attr_list(g, "member") for g in facts["groups"])


def _s5_objects(facts: dict) -> list[str]:
    return [str(_attr(g, "cn", g.entry_dn)) for g in facts["groups"] if not _attr_list(g, "member")]


def _s6_check(facts: dict) -> bool:
    return not any(
        int(_attr(c, "primaryGroupID", 0) or 0) == 516
        and any(v in str(_attr(c, "operatingSystem", "")) for v in ("2008", "2012"))
        for c in facts["computers"]
    )


def _s6_objects(facts: dict) -> list[str]:
    return [
        _sam(c) for c in facts["computers"]
        if int(_attr(c, "primaryGroupID", 0) or 0) == 516
        and any(v in str(_attr(c, "operatingSystem", "")) for v in ("2008", "2012"))
    ]


def _s7_check(facts: dict) -> bool:
    return not any(len(owners) > 1 for owners in facts["spn_owners"].values())


def _s7_objects(facts: dict) -> list[str]:
    return [f"{spn} → {', '.join(owners)}" for spn, owners in facts["spn_owners"].items() if len(owners) > 1]


# ========================= P — Привилегированные учётки =========================

def _p1_check(facts: dict) -> bool:
    return not any(len(members) > PRIVILEGED_GROUP_MAX_MEMBERS for members in facts["privileged_group_members"].values())


def _p1_objects(facts: dict) -> list[str]:
    return [
        f"{name}: {len(members)} участников"
        for name, members in facts["privileged_group_members"].items()
        if len(members) > PRIVILEGED_GROUP_MAX_MEMBERS
    ]


def _priv_users(facts: dict) -> list:
    return [u for u in facts["users"] if str(u.entry_dn) in facts["privileged_members"]]


def _p2_check(facts: dict) -> bool:
    return not any(uac_has(_uac(u), UAC_DONT_EXPIRE_PASSWORD) for u in _priv_users(facts))


def _p2_objects(facts: dict) -> list[str]:
    return [_sam(u) for u in _priv_users(facts) if uac_has(_uac(u), UAC_DONT_EXPIRE_PASSWORD)]


def _p3_check(facts: dict) -> bool:
    krbtgt = facts["krbtgt"]
    if krbtgt is None:
        return True
    pw = filetime_to_datetime(_attr(krbtgt, "pwdLastSet"))
    return not (pw and pw < facts["pwd_max_age_cutoff"])


def _p4_check(facts: dict) -> bool:
    return not any(_attr_list(u, "servicePrincipalName") for u in _priv_users(facts))


def _p4_objects(facts: dict) -> list[str]:
    return [_sam(u) for u in _priv_users(facts) if _attr_list(u, "servicePrincipalName")]


def _p5_check(facts: dict) -> bool:
    for u in facts["users"]:
        sid = str(_attr(u, "objectSid", ""))
        if not sid.endswith("-500") or _is_disabled(u):
            continue
        lt = filetime_to_datetime(_attr(u, "lastLogonTimestamp"))
        if lt and lt >= facts["stale_cutoff"]:
            return False
    return True


def _p5_objects(facts: dict) -> list[str]:
    out = []
    for u in facts["users"]:
        sid = str(_attr(u, "objectSid", ""))
        if not sid.endswith("-500") or _is_disabled(u):
            continue
        lt = filetime_to_datetime(_attr(u, "lastLogonTimestamp"))
        if lt and lt >= facts["stale_cutoff"]:
            out.append(_sam(u))
    return out


def _p6_check(facts: dict) -> bool:
    return not any(uac_has(_uac(c), UAC_TRUSTED_FOR_DELEGATION) for c in facts["computers"])


def _p6_objects(facts: dict) -> list[str]:
    return [_sam(c) for c in facts["computers"] if uac_has(_uac(c), UAC_TRUSTED_FOR_DELEGATION)]


def _p7_check(facts: dict) -> bool:
    return not any(
        int(_attr(u, "adminCount", 0) or 0) == 1 and str(u.entry_dn) not in facts["privileged_members"]
        for u in facts["users"]
    )


def _p7_objects(facts: dict) -> list[str]:
    return [
        _sam(u) for u in facts["users"]
        if int(_attr(u, "adminCount", 0) or 0) == 1 and str(u.entry_dn) not in facts["privileged_members"]
    ]


# ========================= T — Доверительные отношения =========================

def _trust_name(t) -> str:
    return str(_attr(t, "cn", t.entry_dn))


def _t1_check(facts: dict) -> bool:
    return not any(
        int(_attr(t, "trustType", 0) or 0) in (1, 3) and not (int(_attr(t, "trustAttributes", 0) or 0) & TRUST_ATTR_FILTER_SIDS)
        for t in facts["trusts"]
    )


def _t1_objects(facts: dict) -> list[str]:
    return [
        _trust_name(t) for t in facts["trusts"]
        if int(_attr(t, "trustType", 0) or 0) in (1, 3) and not (int(_attr(t, "trustAttributes", 0) or 0) & TRUST_ATTR_FILTER_SIDS)
    ]


def _t2_check(facts: dict) -> bool:
    return not any(
        int(_attr(t, "trustType", 0) or 0) in (1, 3) and int(_attr(t, "trustDirection", 0) or 0) == 3
        for t in facts["trusts"]
    )


def _t2_objects(facts: dict) -> list[str]:
    return [
        _trust_name(t) for t in facts["trusts"]
        if int(_attr(t, "trustType", 0) or 0) in (1, 3) and int(_attr(t, "trustDirection", 0) or 0) == 3
    ]


def _t4_check(facts: dict) -> bool:
    return not any(not (int(_attr(t, "trustAttributes", 0) or 0) & TRUST_ATTR_NON_TRANSITIVE) for t in facts["trusts"])


def _t4_objects(facts: dict) -> list[str]:
    return [_trust_name(t) for t in facts["trusts"] if not (int(_attr(t, "trustAttributes", 0) or 0) & TRUST_ATTR_NON_TRANSITIVE)]


# ========================== AN — Аномалии безопасности ==========================

def _an1_check(facts: dict) -> bool:
    for u in facts["users"]:
        if not _attr_list(u, "servicePrincipalName"):
            continue
        enc = int(_attr(u, "msDS-SupportedEncryptionTypes", 0) or 0)
        if enc == 0 or (enc & MSDS_RC4):
            return False
    return True


def _an1_objects(facts: dict) -> list[str]:
    out = []
    for u in facts["users"]:
        if not _attr_list(u, "servicePrincipalName"):
            continue
        enc = int(_attr(u, "msDS-SupportedEncryptionTypes", 0) or 0)
        if enc == 0 or (enc & MSDS_RC4):
            out.append(_sam(u))
    return out


def _an2_check(facts: dict) -> bool:
    return not any(uac_has(_uac(u), UAC_DONT_REQUIRE_PREAUTH) for u in facts["users"])


def _an2_objects(facts: dict) -> list[str]:
    return [_sam(u) for u in facts["users"] if uac_has(_uac(u), UAC_DONT_REQUIRE_PREAUTH)]


def _an3_check(facts: dict) -> bool:
    return any(_attr(c, "ms-Mcs-AdmPwd") for c in facts["computers"])


def _an4_applies(facts: dict) -> bool:
    return facts["domain_obj"] is not None and _attr(facts["domain_obj"], "minPwdLength") is not None


def _an4_check(facts: dict) -> bool:
    return int(_attr(facts["domain_obj"], "minPwdLength", 0) or 0) >= 12


def _an4c_check(facts: dict) -> bool:
    return bool(int(_attr(facts["domain_obj"], "pwdProperties", 0) or 0) & 0x1) if facts["domain_obj"] else True


def _an8_check(facts: dict) -> bool:
    return facts["recycle_bin_enabled"]


def _an9_applies(facts: dict) -> bool:
    return facts["domain_obj"] is not None and _attr(facts["domain_obj"], "ms-DS-MachineAccountQuota") is not None


def _an9_check(facts: dict) -> bool:
    return int(_attr(facts["domain_obj"], "ms-DS-MachineAccountQuota", 0) or 0) == 0


RULES: list[Rule] = [
    Rule("S1", CAT_STALE, "high", "Неактивные, но включённые учётные записи",
         "Пользователи не заходили >90 дней, но учётка не отключена.",
         "Отключить неиспользуемые учётные записи (Disable Account), не удалять сразу.",
         _s1_check, _s1_objects),
    Rule("S2", CAT_STALE, "high", "Неактивные компьютерные объекты",
         "Компьютеры не заходили в домен >90 дней — возможно, списаны физически, но остались в AD.",
         "Отключить или удалить неиспользуемые компьютерные объекты.",
         _s2_check, _s2_objects),
    Rule("S3", CAT_STALE, "medium", "Пароль не менялся больше года",
         "Пароль учётки не менялся >365 дней (без флага 'не истекает').",
         "Принудительно сменить пароль или установить срок действия.",
         _s3_check, _s3_objects),
    Rule("S4", CAT_STALE, "medium", "Просроченная учётка не отключена",
         "Срок действия учётки (accountExpires) истёк, но учётка всё ещё активна.",
         "Отключить учётку или продлить срок действия осознанно.",
         _s4_check, _s4_objects),
    Rule("S5", CAT_STALE, "low", "Пустые группы безопасности",
         "Группы без единого участника — мусор в каталоге, усложняет аудит прав.",
         "Удалить неиспользуемые группы или задокументировать их назначение.",
         _s5_check, _s5_objects),
    Rule("S6", CAT_STALE, "critical", "Контроллер домена на устаревшей ОС",
         "DC работает на Windows Server 2008/2012 — вне поддержки, известные уязвимости не закрываются.",
         "Спланировать миграцию DC на поддерживаемую версию Windows Server.",
         _s6_check, _s6_objects),
    Rule("S7", CAT_STALE, "medium", "Дублирующиеся SPN",
         "Один SPN зарегистрирован на нескольких объектах — Kerberos-аутентификация станет непредсказуемой.",
         "Оставить SPN только на одном объекте, снять с остальных (setspn -X для поиска дублей).",
         _s7_check, _s7_objects),

    Rule("P1", CAT_PRIVILEGED, "high", "Слишком много членов в Domain/Enterprise Admins",
         f"В привилегированной группе больше {PRIVILEGED_GROUP_MAX_MEMBERS} участников — расширенная поверхность атаки.",
         "Пересмотреть членство, вывести лишних в обычные учётки с делегированием конкретных прав.",
         _p1_check, _p1_objects),
    Rule("P2", CAT_PRIVILEGED, "critical", "Пароль привилегированной учётки не истекает",
         "У учётки из Domain/Enterprise Admins стоит флаг 'пароль никогда не истекает'.",
         "Снять флаг DONT_EXPIRE_PASSWORD, установить обычную политику смены пароля.",
         _p2_check, _p2_objects),
    Rule("P3", CAT_PRIVILEGED, "critical", "Пароль krbtgt не менялся больше года",
         "krbtgt — ключевая учётка Kerberos, старый пароль облегчает атаку Golden Ticket.",
         "Сменить пароль krbtgt дважды подряд с интервалом (штатная процедура Microsoft).",
         _p3_check),
    Rule("P4", CAT_PRIVILEGED, "high", "Служебная учётка напрямую в привилегированной группе",
         "У участника Domain/Enterprise Admins задан SPN — похоже на служебную, а не персональную учётку.",
         "Вынести служебную учётку из привилегированной группы, выдать точечные права через делегирование.",
         _p4_check, _p4_objects),
    Rule("P5", CAT_PRIVILEGED, "medium", "Встроенная Administrator активно используется",
         "Встроенная учётка Administrator (RID 500) не отключена и заходила в последние 90 дней.",
         "Переключиться на именные привилегированные учётки, встроенный Administrator — только для восстановления.",
         _p5_check, _p5_objects),
    Rule("P6", CAT_PRIVILEGED, "critical", "Unconstrained Kerberos delegation на серверах",
         "Компьютер с TRUSTED_FOR_DELEGATION — компрометация этого сервера даёт билеты любого пользователя домена.",
         "Перейти на Constrained/Resource-Based Constrained Delegation.",
         _p6_check, _p6_objects),
    Rule("P7", CAT_PRIVILEGED, "medium", "adminCount=1 без реального членства (осиротевший ACL)",
         "У учётки остался защищённый ACL (adminCount=1) от прежнего членства в привилегированной группе — SDProp не восстанавливает наследование автоматически.",
         "Сбросить adminCount и восстановить наследование ACL (или оставить, если осознанно).",
         _p7_check, _p7_objects),

    Rule("T1", CAT_TRUSTS, "critical", "Внешнее доверие без SID-фильтрации",
         "Внешнее/forest-доверие без SID-квотирования — уязвимо к SID history injection из доверенного леса.",
         "Включить SID-фильтрацию (quarantine) на внешнем доверии.",
         _t1_check, _t1_objects),
    Rule("T2", CAT_TRUSTS, "high", "Двунаправленное доверие там, где нужен один вектор",
         "Доверие настроено в обе стороны — расширяет поверхность атаки сверх необходимого.",
         "Пересмотреть направление доверия, сделать однонаправленным, если обратный вектор не нужен.",
         _t2_check, _t2_objects),
    Rule("T4", CAT_TRUSTS, "high", "Транзитивное доверие там, где нужна изоляция",
         "Доверие транзитивно — компрометация соседнего домена в цепочке может затронуть и этот.",
         "Сделать доверие нетранзитивным, если оно не должно распространяться дальше напрямую связанного домена.",
         _t4_check, _t4_objects),

    Rule("AN1", CAT_ANOMALIES, "critical", "Kerberoasting: слабое шифрование на SPN пользователей",
         "У учётки с SPN разрешено RC4 (или тип шифрования не задан) — офлайн-перебор пароля по TGS-тикету намного проще.",
         "Разрешить только AES (msDS-SupportedEncryptionTypes), убрать RC4.",
         _an1_check, _an1_objects),
    Rule("AN2", CAT_ANOMALIES, "critical", "AS-REP Roasting: преаутентификация отключена",
         "У учётки снят флаг обязательной преаутентификации Kerberos — TGT можно получить без знания пароля и перебирать офлайн.",
         "Включить обратно 'Require Kerberos preauthentication' для учётки.",
         _an2_check, _an2_objects),
    Rule("AN3", CAT_ANOMALIES, "high", "LAPS не развёрнут",
         "Ни у одного компьютерного объекта нет атрибута ms-Mcs-AdmPwd — локальный пароль администратора не ротируется автоматически.",
         "Развернуть Local Administrator Password Solution (LAPS) на рабочих станциях и серверах.",
         _an3_check),
    Rule("AN4", CAT_ANOMALIES, "high", "Минимальная длина пароля домена < 12",
         "Политика домена допускает пароли короче 12 символов.",
         "Поднять minPwdLength до 12+ в default domain policy.",
         _an4_check, applies=_an4_applies),
    Rule("AN4C", CAT_ANOMALIES, "medium", "Требование сложности пароля отключено",
         "Флаг DOMAIN_PASSWORD_COMPLEX в pwdProperties не установлен — пароли могут не содержать разные классы символов.",
         "Включить требование сложности пароля в default domain policy.",
         _an4c_check),
    Rule("AN8", CAT_ANOMALIES, "low", "AD Recycle Bin не включён",
         "Корзина объектов AD выключена — случайно удалённые объекты восстанавливаются только через authoritative restore.",
         "Включить AD Recycle Bin (необратимо после включения, но того стоит).",
         _an8_check),
    Rule("AN9", CAT_ANOMALIES, "medium", "MachineAccountQuota > 0",
         "Любой аутентифицированный пользователь домена может присоединить компьютеры к домену (значение по умолчанию — 10).",
         "Установить ms-DS-MachineAccountQuota = 0, присоединять компьютеры через выделенную учётку/делегирование.",
         _an9_check, applies=_an9_applies),
]
