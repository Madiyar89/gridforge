"""Вход через Active Directory.

Пароль проверяется самим доменом: пробуем LDAP bind логином и паролем
пользователя. Удался — пароль верный. Никаких паролей AD у себя не
храним: для доменного пользователя локальный хеш не заводится вообще
(см. User.source), поэтому утечка базы GridForge не даёт доменных
учёток.

Настраивается переменными окружения — как и ретеншн, это параметр
развёртывания, а не то, что меняют из интерфейса на ходу:

  GRIDFORGE_AD_SERVER       контроллер домена (без него вход через AD выключен)
  GRIDFORGE_AD_PORT         636 по умолчанию (LDAPS)
  GRIDFORGE_AD_DOMAIN       домен для UPN: вход «petrov» → «petrov@corp.local»
  GRIDFORGE_AD_DEFAULT_ROLE роль при первом входе (viewer по умолчанию)
  GRIDFORGE_AD_VERIFY_CERT  проверять сертификат контроллера (по умолчанию да)

Про сертификат отдельно. В ad_audit_engine проверка отключена — там
читаются атрибуты лабораторного домена с самоподписанным сертификатом.
Здесь по той же сети идёт ПАРОЛЬ пользователя, и подмена контроллера
означает кражу доменной учётки, поэтому по умолчанию сертификат
проверяется. Отключать (GRIDFORGE_AD_VERIFY_CERT=0) осознанно и только
в лаборатории.
"""

from __future__ import annotations

import logging
import os
import ssl

import ldap3
from sqlalchemy.orm import Session

from app.models import ApiKeyRole, User, _now

logger = logging.getLogger("gridforge.ad_auth")


def ad_enabled() -> bool:
    return bool(os.environ.get("GRIDFORGE_AD_SERVER"))


def _default_role() -> ApiKeyRole:
    raw = (os.environ.get("GRIDFORGE_AD_DEFAULT_ROLE") or "viewer").strip().lower()
    try:
        return ApiKeyRole(raw)
    except ValueError:
        # Опечатка в настройке не должна выдавать лишние права — падаем в
        # самую слабую роль, а не в ту, что «похоже имелась в виду».
        logger.warning("GRIDFORGE_AD_DEFAULT_ROLE=%r не роль — беру viewer", raw)
        return ApiKeyRole.viewer


def _verify_cert() -> bool:
    return (os.environ.get("GRIDFORGE_AD_VERIFY_CERT") or "1").strip().lower() not in {"0", "false", "no"}


def check_ad_credentials(username: str, password: str) -> bool:
    """Проверка логина и пароля в домене через LDAP bind.

    Пустой пароль отвергается ДО обращения к серверу: LDAP bind с пустым
    паролем многие каталоги принимают как анонимный и отвечают успехом —
    это классический способ войти любым логином, не зная пароля.
    """
    if not password or not username:
        return False
    if not ad_enabled():
        return False

    server_host = os.environ["GRIDFORGE_AD_SERVER"]
    port = int(os.environ.get("GRIDFORGE_AD_PORT", 636))
    domain = os.environ.get("GRIDFORGE_AD_DOMAIN")
    # AD принимает UPN (user@domain) — не требует знать структуру OU, в
    # отличие от полного DN.
    bind_user = f"{username}@{domain}" if domain and "@" not in username else username

    validate = ssl.CERT_REQUIRED if _verify_cert() else ssl.CERT_NONE
    tls = ldap3.Tls(validate=validate)
    server = ldap3.Server(server_host, port=port, use_ssl=True, tls=tls)
    try:
        conn = ldap3.Connection(server, user=bind_user, password=password, auto_bind=True)
    except ldap3.core.exceptions.LDAPException as exc:
        # Неверный пароль и недоступный контроллер выглядят здесь
        # одинаково (оба — исключение), и это правильно для ответа
        # пользователю; в лог пишем подробность, чтобы отличать.
        logger.info("AD-вход не удался для %s: %s", username, exc)
        return False
    conn.unbind()
    return True


def sync_ad_user(db: Session, username: str) -> User:
    """Локальная запись доменного пользователя: роль и область группы
    хранятся у нас (в AD их взять неоткуда), пароль — нет.

    При первом входе заводится с ролью по умолчанию; дальше её меняет
    администратор GridForge, и повторный вход её НЕ перезатирает."""
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        user = User(
            username=username,
            password_hash="",  # пароль живёт в домене, локального хеша нет
            role=_default_role(),
            source="ad",
        )
        db.add(user)
    user.last_login_at = _now()
    db.commit()
    db.refresh(user)
    return user
