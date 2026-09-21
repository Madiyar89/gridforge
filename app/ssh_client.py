"""Общий SSH-исполнитель одной команды — используется и `probes.py`
(`ssh_command` Probe), и `actions.py` (SSH-действие по Incident). Вынесен
в отдельный модуль, чтобы не дублировать код (и его баги — см.
`asyncio.TimeoutError` в probes.py: `str()` от него — пустая строка) между
двумя местами, где нужен ровно один и тот же SSH-вызов."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh
from asyncssh.encryption import get_default_encryption_algs
from asyncssh.kex import get_default_kex_algs

# Часть парка — старые коммутаторы (реальный случай, LAB-7/LAB-11:
# "No matching key exchange algorithm found... received
# diffie-hellman-group1-sha1"), их SSH-стек не предлагает ни один
# kex/шифр из современного дефолтного списка asyncssh (сознательно не
# включает устаревшие как небезопасные). Тот же приём, что уже
# использует NetOpsHub для paramiko (hub/backend/app/live_poll.py) —
# дописываем legacy-алгоритмы В КОНЕЦ дефолтного списка asyncssh, а не
# заменяем его: современные устройства как согласовывали свежие
# алгоритмы, так и продолжат, старые получат шанс на устаревший, раз
# другого у них нет.
_LEGACY_KEX = (b"diffie-hellman-group1-sha1", b"diffie-hellman-group-exchange-sha1")
_LEGACY_CIPHERS = (b"aes128-cbc", b"aes256-cbc", b"3des-cbc")
KEX_ALGS = list(get_default_kex_algs()) + [a for a in _LEGACY_KEX if a not in get_default_kex_algs()]
ENCRYPTION_ALGS = list(get_default_encryption_algs()) + [
    a for a in _LEGACY_CIPHERS if a not in get_default_encryption_algs()
]


@dataclass
class SshResult:
    ok: bool
    exit_status: int | None
    stdout: str
    error: str | None  # заполнено только при ok=False


async def run_ssh_command(
    *,
    host: str,
    port: int,
    username: str,
    command: str,
    timeout_seconds: float,
    key_path: str | None = None,
    password: str | None = None,
    known_hosts: str | None = None,
) -> SshResult:
    connect_kwargs: dict = {
        "host": host,
        "port": port,
        "username": username,
        "known_hosts": known_hosts,  # None => host key не проверяется
        "connect_timeout": timeout_seconds,
        "kex_algs": KEX_ALGS,
        "encryption_algs": ENCRYPTION_ALGS,
    }
    if key_path:
        connect_kwargs["client_keys"] = [key_path]
    elif password:
        connect_kwargs["password"] = password
        connect_kwargs["client_keys"] = None
    else:
        return SshResult(ok=False, exit_status=None, stdout="", error="нужен key_path или password")

    try:
        async with asyncssh.connect(**connect_kwargs) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return SshResult(ok=False, exit_status=None, stdout="", error="timeout")
    except (asyncssh.Error, OSError) as exc:
        return SshResult(ok=False, exit_status=None, stdout="", error=str(exc) or exc.__class__.__name__)

    stdout = (result.stdout or "").strip()
    if result.exit_status != 0:
        return SshResult(ok=False, exit_status=result.exit_status, stdout=stdout, error=f"exit={result.exit_status}")
    return SshResult(ok=True, exit_status=result.exit_status, stdout=stdout, error=None)
