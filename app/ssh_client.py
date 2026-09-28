"""Общий SSH-исполнитель одной команды — используется и `probes.py`
(`ssh_command` Probe), и `actions.py` (SSH-действие по Incident). Вынесен
в отдельный модуль, чтобы не дублировать код (и его баги — см.
`asyncio.TimeoutError` в probes.py: `str()` от него — пустая строка) между
двумя местами, где нужен ровно один и тот же SSH-вызов.

Также единая точка установления SSH-соединения (`open_ssh_connection`) —
её использует и `console_ws.py` (интерактивная SSH-консоль в браузере),
чтобы TOFU-проверка host key (см. ниже) жила в одном месте, а не была
продублирована между exec-командами и консолью."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable

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
_LEGACY_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1")
_LEGACY_CIPHERS = ("aes128-cbc", "aes256-cbc", "3des-cbc")
# get_default_kex_algs()/get_default_encryption_algs() отдают bytes (это
# внутреннее представление asyncssh) — но connect(kex_algs=..., ...)
# ожидает СТРОКИ и сам делает .encode('ascii') (см. connection.py
# _select_algs) — реальный баг на боевом сервере (2026-09-21): передача
# bytes напрямую роняла КАЖДОЕ подключение с AttributeError ещё до
# попытки соединения, silently проглоченным asyncio.gather(...,
# return_exceptions=True) в sweep_engine/scenarios_engine — прогоны
# молча зависали на 0 из N без единой ошибки в интерфейсе.
_default_kex = [a.decode("ascii") for a in get_default_kex_algs()]
_default_ciphers = [a.decode("ascii") for a in get_default_encryption_algs()]
KEX_ALGS = _default_kex + [a for a in _LEGACY_KEX if a not in _default_kex]
ENCRYPTION_ALGS = _default_ciphers + [a for a in _LEGACY_CIPHERS if a not in _default_ciphers]


# --- Trust-on-first-use (TOFU) проверка SSH host key ------------------
#
# Раньше `known_hosts=None` передавался прямо в asyncssh.connect() везде
# (probes.py/actions_engine.py/console_ws.py) — host key вообще не
# проверялся, MITM неотличим от легитимного узла. Решение по итогам
# аудита (2026-09-28): TOFU — при первом подключении к узлу запоминаем
# fingerprint предъявленного ключа (Node.ssh_key_fingerprint), при
# всех следующих сверяем и обрываем соединение при несовпадении.
#
# Важный факт об asyncssh, без знания которого это не работает: при
# known_hosts=None asyncssh вообще не спрашивает validate_host_public_key
# у SSHClient — см. asyncssh/connection.py: `if self._known_hosts is
# None: self._trusted_host_keys = None`, а дальше `_validate_host_key`
# зовёт `_owner.validate_host_public_key(...)` только когда
# `self._trusted_host_keys is not None`. Поэтому для TOFU-режима
# передаём known_hosts=[] (пустой список — валиден, не None) — тогда
# _trusted_host_keys становится пустым set(), ни один ключ туда
# заранее не попадает, и validate_host_public_key вызывается ВСЕГДА,
# что и даёт нужную точку контроля.


class HostKeyRejected(Exception):
    """SSH host key узла не совпал с сохранённым TOFU-fingerprint —
    возможен MITM либо переустановка устройства. Не путать с обычными
    `asyncssh.Error` (сетевые/протокольные проблемы) — это осознанный
    отказ по соображениям безопасности."""


@dataclass
class HostKeyDecision:
    allow: bool
    fingerprint: str  # SHA256-fingerprint предъявленного ключа
    is_new: bool  # True => это первое подключение, fingerprint нужно сохранить
    error: str | None = None


def evaluate_host_key(stored_fingerprint: str | None, presented_fingerprint: str) -> HostKeyDecision:
    """Чистая функция сравнения — без сети и без БД, поэтому легко
    тестируется без реального SSH-сервера (см. tests/test_ssh_tofu.py).

    Три исхода:
      - fingerprint ещё не сохранён (первое подключение) — разрешить,
        пометить, что нужно сохранить presented_fingerprint.
      - совпадает с сохранённым — разрешить, ничего сохранять не нужно.
      - не совпадает — отклонить с понятным сообщением."""
    if not stored_fingerprint:
        return HostKeyDecision(allow=True, fingerprint=presented_fingerprint, is_new=True)
    if stored_fingerprint == presented_fingerprint:
        return HostKeyDecision(allow=True, fingerprint=presented_fingerprint, is_new=False)
    return HostKeyDecision(
        allow=False,
        fingerprint=presented_fingerprint,
        is_new=False,
        error=(
            "host key устройства изменился — возможен MITM либо переустановка "
            "устройства; сбросьте сохранённый fingerprint в Настройки → Узел, "
            "если замена ожидаема"
        ),
    )


class _TofuSSHClient(asyncssh.SSHClient):
    """Тонкая обёртка над официальным механизмом asyncssh для этого
    (задокументирован в docstring `SSHClient.validate_host_public_key`
    как рекомендуемый способ сделать собственную проверку host key
    вместо/вместе с обычным known_hosts-файлом). Вся логика сравнения —
    в evaluate_host_key(), здесь только мост к API asyncssh."""

    def __init__(
        self,
        get_fingerprint: Callable[[], str | None] | None,
        store_fingerprint: Callable[[str], None] | None,
    ) -> None:
        self._get_fingerprint = get_fingerprint
        self._store_fingerprint = store_fingerprint
        self.error: str | None = None

    def validate_host_public_key(self, host: str, addr: str, port: int, key: "asyncssh.SSHKey") -> bool:
        presented = key.get_fingerprint("sha256")
        stored = self._get_fingerprint() if self._get_fingerprint else None
        decision = evaluate_host_key(stored, presented)
        if not decision.allow:
            self.error = decision.error
            return False
        if decision.is_new and self._store_fingerprint:
            self._store_fingerprint(decision.fingerprint)
        return True


async def open_ssh_connection(
    *,
    host: str,
    port: int,
    username: str,
    timeout_seconds: float,
    key_path: str | None = None,
    password: str | None = None,
    known_hosts: str | None = None,
    host_key_fingerprint_getter: Callable[[], str | None] | None = None,
    host_key_fingerprint_setter: Callable[[str], None] | None = None,
    kex_algs: list[str] | None = None,
    encryption_algs: list[str] | None = None,
) -> asyncssh.SSHClientConnection:
    """Единая точка asyncssh.connect() — и для run_ssh_command/
    run_ssh_config_lines (одна команда/конфигурирующий блок), и для
    интерактивной SSH-консоли (console_ws.py).

    known_hosts явно заданный (например путь к настоящему known_hosts-
    файлу из params) — старое, полноценное поведение asyncssh, TOFU не
    участвует, приоритет у явного known_hosts.

    known_hosts не задан (None) и переданы host_key_fingerprint_getter/
    _setter — TOFU-режим (см. evaluate_host_key выше).

    known_hosts не задан и TOFU-callback'и тоже не переданы — старое
    поведение (host key вообще не проверяется), сохранено для мест,
    которые ещё не перевели на TOFU (см. HANDOFF/отчёт по этой правке).

    Поднимает HostKeyRejected при несовпадении fingerprint — отдельно от
    asyncssh.Error, чтобы вызывающий код мог показать понятное сообщение
    вместо общего "Host key is not trusted" от asyncssh."""
    connect_kwargs: dict = {
        "host": host,
        "port": port,
        "username": username,
        "connect_timeout": timeout_seconds,
        "kex_algs": kex_algs if kex_algs is not None else KEX_ALGS,
        "encryption_algs": encryption_algs if encryption_algs is not None else ENCRYPTION_ALGS,
    }
    if key_path:
        connect_kwargs["client_keys"] = [key_path]
    elif password:
        connect_kwargs["password"] = password
        connect_kwargs["client_keys"] = None

    use_tofu = known_hosts is None and (
        host_key_fingerprint_getter is not None or host_key_fingerprint_setter is not None
    )
    if not use_tofu:
        connect_kwargs["known_hosts"] = known_hosts  # None => не проверяется (старое поведение)
        return await asyncssh.connect(**connect_kwargs)

    holder: list[_TofuSSHClient] = []

    def _client_factory() -> _TofuSSHClient:
        client = _TofuSSHClient(host_key_fingerprint_getter, host_key_fingerprint_setter)
        holder.append(client)
        return client

    connect_kwargs["known_hosts"] = []  # пусто, НЕ None — см. комментарий выше
    connect_kwargs["server_host_key_algs"] = "default"
    connect_kwargs["client_factory"] = _client_factory

    try:
        return await asyncssh.connect(**connect_kwargs)
    except asyncssh.Error as exc:
        if holder and holder[0].error:
            raise HostKeyRejected(holder[0].error) from exc
        raise


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
    host_key_fingerprint_getter: Callable[[], str | None] | None = None,
    host_key_fingerprint_setter: Callable[[str], None] | None = None,
) -> SshResult:
    if not key_path and not password:
        return SshResult(ok=False, exit_status=None, stdout="", error="нужен key_path или password")

    try:
        async with await open_ssh_connection(
            host=host,
            port=port,
            username=username,
            timeout_seconds=timeout_seconds,
            key_path=key_path,
            password=password,
            known_hosts=known_hosts,
            host_key_fingerprint_getter=host_key_fingerprint_getter,
            host_key_fingerprint_setter=host_key_fingerprint_setter,
        ) as conn:
            result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return SshResult(ok=False, exit_status=None, stdout="", error="timeout")
    except (asyncssh.Error, OSError, HostKeyRejected) as exc:
        return SshResult(ok=False, exit_status=None, stdout="", error=str(exc) or exc.__class__.__name__)

    stdout = (result.stdout or "").strip()
    if result.exit_status != 0:
        return SshResult(ok=False, exit_status=result.exit_status, stdout=stdout, error=f"exit={result.exit_status}")
    return SshResult(ok=True, exit_status=result.exit_status, stdout=stdout, error=None)


async def run_ssh_config_lines(
    *,
    host: str,
    port: int,
    username: str,
    lines: list[str],
    timeout_seconds: float,
    key_path: str | None = None,
    password: str | None = None,
    known_hosts: str | None = None,
    host_key_fingerprint_getter: Callable[[], str | None] | None = None,
    host_key_fingerprint_setter: Callable[[str], None] | None = None,
    line_delay: float = 0.4,
    settle_seconds: float = 2.0,
) -> SshResult:
    """Многострочные конфигурирующие команды (configure terminal/...,
    set .../commit) нельзя отправить одним conn.run() — реальный баг на
    боевом сервере (2026-09-21): и Cisco IOS ("Line has invalid
    autocommand"), и Junos ("syntax error, expecting <command>: set")
    воспринимают весь текст с переводами строк как ОДНУ команду вместо
    последовательности. run_ssh_command (один exec-запрос) отлично
    работает для одиночных read-only команд (show .../ping — Probe,
    Sweep), но не для этого.

    Вместо exec — интерактивная PTY-сессия, та же техника, что уже
    работает в SSH-консоли (console_ws.py): построчно пишем в stdin с
    паузой между строками, как будто человек вставляет текст в
    терминал, читаем весь вывод целиком."""
    if not key_path and not password:
        return SshResult(ok=False, exit_status=None, stdout="", error="нужен key_path или password")

    output_chunks: list[str] = []

    async def _run() -> None:
        async with await open_ssh_connection(
            host=host,
            port=port,
            username=username,
            timeout_seconds=timeout_seconds,
            key_path=key_path,
            password=password,
            known_hosts=known_hosts,
            host_key_fingerprint_getter=host_key_fingerprint_getter,
            host_key_fingerprint_setter=host_key_fingerprint_setter,
        ) as conn:
            async with conn.create_process(term_type="vt100", term_size=(200, 24)) as process:
                async def _reader() -> None:
                    try:
                        while True:
                            chunk = await process.stdout.read(4096)
                            if not chunk:
                                break
                            output_chunks.append(chunk)
                    except asyncssh.Error:
                        pass

                reader_task = asyncio.create_task(_reader())
                await asyncio.sleep(0.3)  # дать приглашению/баннеру появиться
                for line in lines:
                    process.stdin.write(line + "\n")
                    await asyncio.sleep(line_delay)
                await asyncio.sleep(settle_seconds)
                process.stdin.write_eof()
                try:
                    await asyncio.wait_for(reader_task, timeout=2)
                except asyncio.TimeoutError:
                    reader_task.cancel()

    try:
        await asyncio.wait_for(_run(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        return SshResult(ok=False, exit_status=None, stdout="".join(output_chunks).strip(), error="timeout")
    except (asyncssh.Error, OSError, HostKeyRejected) as exc:
        return SshResult(
            ok=False, exit_status=None, stdout="".join(output_chunks).strip(),
            error=str(exc) or exc.__class__.__name__,
        )

    return SshResult(ok=True, exit_status=0, stdout="".join(output_chunks).strip(), error=None)


def node_fingerprint_callbacks(node_id: int) -> tuple[Callable[[], str | None], Callable[[str], None]]:
    """Геттер/сеттер TOFU-fingerprint по Node.id — для вызывающего кода,
    у которого нет под рукой живого Node/Session (probes.py: исполнитель
    Probe получает только адрес узла и параметры проверки, не саму ORM-
    сущность). Каждый вызов открывает свою короткую сессию — тот же
    компромисс, что и у resolve_credential в других местах: probes.py
    (`ProbeExecutor`) сознательно не тащит SQLAlchemy Session через весь
    реестр исполнителей, чтобы не связывать все ProbeKind (включая
    icmp_ping/snmp_*, которым БД вообще не нужна) с жизненным циклом
    сессии планировщика.

    Там, где Node/Session уже есть в скоупе (actions_engine.py,
    console_ws.py) — эта функция не нужна, дешевле замкнуться прямо на
    имеющийся объект."""
    from app.db import get_session
    from app.models import Node

    def _get() -> str | None:
        db = get_session()
        try:
            node = db.get(Node, node_id)
            return node.ssh_key_fingerprint if node is not None else None
        finally:
            db.close()

    def _set(fingerprint: str) -> None:
        db = get_session()
        try:
            node = db.get(Node, node_id)
            if node is not None:
                node.ssh_key_fingerprint = fingerprint
                db.commit()
        finally:
            db.close()

    return _get, _set
