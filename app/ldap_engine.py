"""Хранение и проверка LDAP-подключений для AD-аудита — своя версия
LdapCredentialSet из NetOpsHub (2026-09-21, по прямому запросу
пользователя), но пароль зашифрован тем же Fernet-механизмом, что уже
защищает Credential.password/Integration.api_token (secrets_crypto.py),
не отдельным файлом на диск.

Bind-логин — UPN (f"{username}@{domain}"), не DN: работает без знания
точного расположения объекта учётки в дереве каталога, тот же приём,
что в NetOpsHub."""

from __future__ import annotations

import ssl

import ldap3

from app.models import LdapConnection
from app.secrets_crypto import decrypt_secret, encrypt_secret


class LdapTestError(Exception):
    pass


def encrypt_password(password: str) -> str:
    return encrypt_secret(password)


def decrypt_password(password: str) -> str:
    return decrypt_secret(password)


def bind_kwargs(conn: LdapConnection, password: str) -> dict:
    return {
        "dc_host": conn.dc_host,
        "port": conn.port,
        "user": f"{conn.username}@{conn.domain}",
        "password": password,
        "use_ssl": conn.use_ssl,
    }


def test_bind(*, dc_host: str, port: int, domain: str, username: str, password: str, use_ssl: bool) -> None:
    """Лёгкая проверка при сохранении — тот же принцип, что у Credential/
    Integration: подключение реально пробуется один раз, чтобы опечатка в
    домене/пароле не всплыла только при первом настоящем аудите."""
    tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None  # самоподписанные AD-сертификаты — норма в лабораторных доменах
    server = ldap3.Server(dc_host, port=port, use_ssl=use_ssl, tls=tls, connect_timeout=5)
    try:
        conn = ldap3.Connection(
            server,
            user=f"{username}@{domain}",
            password=password,
            auto_bind=True,
            receive_timeout=10,
        )
        conn.unbind()
    except ldap3.core.exceptions.LDAPException as exc:
        raise LdapTestError(str(exc) or exc.__class__.__name__) from exc


def mask_connection(conn: LdapConnection) -> dict:
    return {
        "id": conn.id,
        "label": conn.label,
        "dc_host": conn.dc_host,
        "port": conn.port,
        "domain": conn.domain,
        "base_dn": conn.base_dn,
        "username": conn.username,
        "use_ssl": conn.use_ssl,
    }
