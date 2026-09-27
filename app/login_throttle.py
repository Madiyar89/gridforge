"""Троттлинг /api/login — защита от перебора пароля и от использования
эндпоинта как усилителя LDAP-bind против контроллера домена (каждая
попытка логина AD-пользователя реально бьёт в DC, см. ad_auth.py).

In-memory, не БД: GridForge — один инстанс на площадку (см. CLAUDE.md),
рестарт сервиса — редкое явление и обнуление счётчика при нём не
проблема безопасности (тот же принцип, что уже применён для кэша
NetFlow-шаблонов в netflow_server.py — простое состояние в памяти без
лишней инфраструктуры, если инстанс один).

Ключ — (IP, логин в нижнем регистре), не только IP: не наказывать всю
NAT-сеть офиса за одного пользователя с опечаткой в пароле, но и не
позволять перебор одного логина с разных IP оставаться незамеченным по
отдельности (второй счётчик, только по логину).
"""

from __future__ import annotations

import threading
import time

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300  # 5 минут
LOCKOUT_SECONDS = 300  # ещё 5 минут после исчерпания лимита

_lock = threading.Lock()
# key -> (список timestamp'ов неудачных попыток, until-времени блокировки или 0)
_failures: dict[str, list[float]] = {}
_locked_until: dict[str, float] = {}


def _prune(key: str, now: float) -> None:
    attempts = _failures.get(key)
    if not attempts:
        return
    _failures[key] = [t for t in attempts if now - t < WINDOW_SECONDS]
    if not _failures[key]:
        del _failures[key]


def check_locked(*keys: str) -> float | None:
    """Возвращает оставшиеся секунды блокировки, если хоть один из ключей
    (обычно (ip,login) и login отдельно) заблокирован, иначе None."""
    now = time.time()
    with _lock:
        remaining = None
        for key in keys:
            until = _locked_until.get(key)
            if until is None:
                continue
            if until <= now:
                del _locked_until[key]
                continue
            remaining = max(remaining or 0, until - now)
        return remaining


def record_failure(*keys: str) -> None:
    now = time.time()
    with _lock:
        for key in keys:
            _prune(key, now)
            _failures.setdefault(key, []).append(now)
            if len(_failures[key]) >= MAX_ATTEMPTS:
                _locked_until[key] = now + LOCKOUT_SECONDS
                _failures[key] = []


def record_success(*keys: str) -> None:
    with _lock:
        for key in keys:
            _failures.pop(key, None)
            _locked_until.pop(key, None)
