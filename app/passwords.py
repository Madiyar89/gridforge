"""Хеширование паролей людей.

Здесь СОЗНАТЕЛЬНО не тот подход, что у API-ключей (см. auth.py). Ключ —
это 32 случайных байта, его перебирать бессмысленно, поэтому там быстрый
SHA-256. Пароль человека короткий и предсказуемый, его подбирают по
словарю, и защита — в том, чтобы каждая попытка стоила дорого. Отсюда
scrypt с солью на каждый пароль.

scrypt взят из стандартной библиотеки (hashlib): bcrypt/argon2 дали бы
внешнюю зависимость с бинарной сборкой, а выигрыш для этой задачи
несущественный. Параметры ниже — рекомендованные для интерактивного
входа: около 100 мс на проверку, что незаметно человеку и мучительно для
перебора.

Формат хранения: scrypt$<n>$<r>$<p>$<соль hex>$<хеш hex>. Параметры лежат
рядом с хешем, чтобы их можно было поднять со временем, не ломая уже
сохранённые пароли.
"""

from __future__ import annotations

import hashlib
import secrets

_N = 2**14  # cost — основной параметр сложности
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16
_PREFIX = "scrypt"

MIN_PASSWORD_LENGTH = 10

# Встроенная учётка первого входа — тот же подход, что у Zabbix с его
# общеизвестным Admin/zabbix: войти можно сразу, ничего не выясняя из
# логов. Плата за удобство та же самая — пароль знает кто угодно,
# поэтому система обязана явно требовать его смены (см. is_default_password
# ниже, /api/whoami и предупреждение в интерфейсе), а не молча оставлять
# дверь открытой.
DEFAULT_ADMIN_USERNAME = "Admin"
DEFAULT_ADMIN_PASSWORD = "gridforge"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"{_PREFIX}${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Сравнение постоянного времени: обычное == выдавало бы по времени
    ответа, насколько совпал префикс хеша."""
    try:
        prefix, n_raw, r_raw, p_raw, salt_hex, digest_hex = stored.split("$")
        if prefix != _PREFIX:
            return False
        n, r, p = int(n_raw), int(r_raw), int(p_raw)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        # Повреждённая или чужая строка хеша — это «не совпало», а не
        # исключение: иначе кривая запись в БД роняла бы вход целиком.
        return False

    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
    return secrets.compare_digest(candidate, expected)


def is_default_password(stored_hash: str) -> bool:
    """Всё ещё стоит встроенный пароль? Проверяется по самому хешу, а не
    по флагу в БД: флаг можно забыть выставить или сбросить руками, а
    хеш — источник правды. Используется, чтобы интерфейс и логи не
    переставали напоминать о смене, пока она не произошла."""
    return verify_password(DEFAULT_ADMIN_PASSWORD, stored_hash)


def password_problem(password: str) -> str | None:
    """Минимальная проверка при заведении пароля. Возвращает текст
    проблемы или None. Длина важнее «сложности символов»: требование
    цифр и спецсимволов гонит людей к «Password1!», который подбирается
    словарём, а длинная фраза — нет."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"пароль короче {MIN_PASSWORD_LENGTH} символов"
    if password.lower() in {"password", "пароль", "1234567890", "qwertyuiop", "gridforge1"}:
        return "слишком очевидный пароль"
    return None
