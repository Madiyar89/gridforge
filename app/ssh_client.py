"""Общий SSH-исполнитель одной команды — используется и `probes.py`
(`ssh_command` Probe), и `actions.py` (SSH-действие по Incident). Вынесен
в отдельный модуль, чтобы не дублировать код (и его баги — см.
`asyncio.TimeoutError` в probes.py: `str()` от него — пустая строка) между
двумя местами, где нужен ровно один и тот же SSH-вызов."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh


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
