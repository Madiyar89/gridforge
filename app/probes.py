"""Исполнители проверок. Реестр по ProbeKind — новый тип проверки
добавляется регистрацией функции, не веткой if/elif в одном месте (в
отличие от разбора item key строкой в Zabbix)."""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from app.secrets_crypto import decrypt_secret
from app.ssh_client import run_ssh_command
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoPrivProtocol,
    walk_cmd,
)

from app.models import ProbeKind

PING_PACKET_LOSS_DETAIL = "no reply"


@dataclass
class ProbeOutcome:
    ok: bool
    value: float | None
    detail: str | None = None


ProbeExecutor = Callable[[str, dict, float], Awaitable[ProbeOutcome]]

_REGISTRY: dict[ProbeKind, ProbeExecutor] = {}


def register(kind: ProbeKind) -> Callable[[ProbeExecutor], ProbeExecutor]:
    def decorator(fn: ProbeExecutor) -> ProbeExecutor:
        _REGISTRY[kind] = fn
        return fn

    return decorator


async def run_probe(kind: ProbeKind, address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    executor = _REGISTRY.get(kind)
    if executor is None:
        return ProbeOutcome(ok=False, value=None, detail=f"нет исполнителя для {kind}")
    try:
        return await executor(address, params, timeout_seconds)
    except Exception as exc:  # исполнитель не должен уронить планировщик
        return ProbeOutcome(ok=False, value=None, detail=f"ошибка проверки: {exc}")


@register(ProbeKind.icmp_ping)
async def _icmp_ping(address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    """Без прав на сырой ICMP-сокет (обычно нужен root) — используем
    системную утилиту `ping`, замеряем RTT сами по времени вызова, если
    утилита не отдаёт его в парсибельном виде. Не завязываемся на локаль
    вывода ping — только код возврата и общее время."""
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), address,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_seconds + 1)
    except asyncio.TimeoutError:
        proc.kill()
        return ProbeOutcome(ok=False, value=None, detail="timeout")
    elapsed_ms = (time.monotonic() - started) * 1000
    if proc.returncode == 0:
        return ProbeOutcome(ok=True, value=round(elapsed_ms, 1))
    return ProbeOutcome(ok=False, value=None, detail=PING_PACKET_LOSS_DETAIL)


@register(ProbeKind.tcp_port)
async def _tcp_port(address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    port = params.get("port")
    if port is None:
        return ProbeOutcome(ok=False, value=None, detail="params.port не задан")
    started = time.monotonic()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, int(port)), timeout=timeout_seconds
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except asyncio.TimeoutError:
        # str(asyncio.TimeoutError()) == "" — falsy, ломает любой код вида
        # `detail or value` дальше по цепочке (см. watch_engine.py,
        # static/app.js) молчаливым провалом в "неверный" фолбэк вместо
        # честного "timeout". Найдено на реальном скриншоте дашборда —
        # недоступный порт показывал зелёную подпись "ok" вместо ошибки.
        return ProbeOutcome(ok=False, value=None, detail="timeout")
    except (OSError, socket.gaierror) as exc:
        return ProbeOutcome(ok=False, value=None, detail=str(exc) or exc.__class__.__name__)
    elapsed_ms = (time.monotonic() - started) * 1000
    return ProbeOutcome(ok=True, value=round(elapsed_ms, 1))


@register(ProbeKind.ssh_command)
async def _ssh_command(address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    """Подключается по SSH, выполняет одну команду, интерпретирует вывод.

    params:
      port (int, default 22)
      username (str, обязателен)
      key_path (str) — предпочтительный способ авторизации, ключ на диске
      password (str) — запасной вариант; шифруется при сохранении
        (secrets_crypto, ключ в data/secret.key вне БД) и расшифровывается
        здесь перед подключением.
      command (str, обязательна) — выполняется одна команда, без shell-сессии
      expect_numeric (bool, default false) — распарсить первую строку stdout
        как float и положить в Sample.value (аналог числового item в
        Zabbix); при false Sample.value остаётся пустым, ok = exit_status==0
      known_hosts (str|None) — путь к known_hosts; не задан => host key
        вообще не проверяется (client_keys=None, known_hosts=None) —
        приемлемо для лабораторного полигона, ОПАСНО для боевой сети,
        задать явно перед использованием вне теста
    """
    username = params.get("username")
    command = params.get("command")
    if not username or not command:
        return ProbeOutcome(ok=False, value=None, detail="params.username и params.command обязательны")

    expect_numeric = bool(params.get("expect_numeric", False))

    result = await run_ssh_command(
        host=address,
        port=int(params.get("port", 22)),
        username=username,
        command=command,
        timeout_seconds=timeout_seconds,
        key_path=params.get("key_path"),
        password=decrypt_secret(params["password"]) if params.get("password") else None,
        known_hosts=params.get("known_hosts"),
    )
    if not result.ok:
        detail = result.error
        if result.stdout:
            detail = f"{detail}: {result.stdout[:200]}"
        return ProbeOutcome(ok=False, value=None, detail=detail)

    if not expect_numeric:
        return ProbeOutcome(ok=True, value=None, detail=result.stdout[:200] or None)

    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    try:
        return ProbeOutcome(ok=True, value=float(first_line))
    except ValueError:
        return ProbeOutcome(ok=False, value=None, detail=f"вывод не число: {first_line[:100]!r}")


_SNMP_AUTH_PROTOCOLS = {
    "md5": usmHMACMD5AuthProtocol,
    "sha": usmHMACSHAAuthProtocol,
    "sha224": usmHMAC128SHA224AuthProtocol,
    "sha256": usmHMAC192SHA256AuthProtocol,
}
_SNMP_PRIV_PROTOCOLS = {
    "des": usmDESPrivProtocol,
    "aes": usmAesCfb128Protocol,
    "aes128": usmAesCfb128Protocol,
}


def _build_snmp_v3_auth(params: dict) -> UsmUserData | str:
    """Возвращает UsmUserData или текст ошибки (str) при некорректных
    params — вызывающая сторона отличает по типу."""
    username = params.get("username")
    if not username:
        return "params.username обязателен для version=3"

    auth_password = params.get("auth_password")
    auth_password = decrypt_secret(auth_password) if auth_password else None
    priv_password = params.get("priv_password")
    priv_password = decrypt_secret(priv_password) if priv_password else None

    auth_protocol = None
    if auth_password:
        proto_name = str(params.get("auth_protocol", "sha")).lower()
        auth_protocol = _SNMP_AUTH_PROTOCOLS.get(proto_name)
        if auth_protocol is None:
            return f"params.auth_protocol={proto_name!r} — допустимо: {', '.join(_SNMP_AUTH_PROTOCOLS)}"

    priv_protocol = usmNoPrivProtocol
    if priv_password:
        proto_name = str(params.get("priv_protocol", "aes")).lower()
        priv_protocol = _SNMP_PRIV_PROTOCOLS.get(proto_name)
        if priv_protocol is None:
            return f"params.priv_protocol={proto_name!r} — допустимо: {', '.join(_SNMP_PRIV_PROTOCOLS)}"

    return UsmUserData(
        username,
        authKey=auth_password,
        privKey=priv_password if priv_password else None,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol,
    )


def _build_snmp_auth(params: dict) -> tuple[CommunityData | UsmUserData | None, str | None]:
    """Общая для всех SNMP-проверок сборка учётных данных.

    Возвращает (auth, ошибка) — ровно одно из двух не None."""
    version = str(params.get("version", "2c"))
    if version == "3":
        auth = _build_snmp_v3_auth(params)
        if isinstance(auth, str):
            return None, auth
        return auth, None
    community = params.get("community", "public")
    mp_model = 0 if version == "1" else 1  # 0=SNMPv1, 1=SNMPv2c
    return CommunityData(community, mpModel=mp_model), None


def _close_engine(engine: SnmpEngine) -> None:
    if hasattr(engine, "close_dispatcher"):
        engine.close_dispatcher()


@register(ProbeKind.snmp_get)
async def _snmp_get(address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    """GET одного OID. OID — открытые данные вендора (см. MIB/документацию
    Cisco/Juniper/H3C/PA-450), не тащим их из чужих Zabbix-шаблонов — см.
    GridForge Rewrite Ledger, раздел «Шаблоны мониторинга».

    params (v1/v2c):
      oid, community (default "public"), version ("1"|"2c", default "2c"), port
    params (v3, version="3") — USM, авторизация + опционально шифрование:
      oid, username (обязателен), auth_password (опц. — noAuthNoPriv, если
      не задан), auth_protocol ("sha"|"sha224"|"sha256"|"md5", default sha),
      priv_password (опц. — authNoPriv, если не задан), priv_protocol
      ("aes"|"des", default aes), port
    """
    oid = params.get("oid")
    if not oid:
        return ProbeOutcome(ok=False, value=None, detail="params.oid обязателен")

    port = int(params.get("port", 161))
    auth, auth_error = _build_snmp_auth(params)
    if auth_error:
        return ProbeOutcome(ok=False, value=None, detail=auth_error)

    engine = SnmpEngine()
    try:
        error_indication, error_status, _error_index, var_binds = await asyncio.wait_for(
            get_cmd(
                engine,
                auth,
                await UdpTransportTarget.create((address, port), timeout=timeout_seconds, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            ),
            timeout=timeout_seconds + 1,
        )
    except asyncio.TimeoutError:
        return ProbeOutcome(ok=False, value=None, detail="timeout")
    finally:
        _close_engine(engine)

    if error_indication:
        return ProbeOutcome(ok=False, value=None, detail=str(error_indication))
    if error_status:
        return ProbeOutcome(ok=False, value=None, detail=str(error_status.prettyPrint()))

    _oid_out, value_obj = var_binds[0]
    raw = value_obj.prettyPrint()
    try:
        return ProbeOutcome(ok=True, value=float(raw))
    except ValueError:
        return ProbeOutcome(ok=True, value=None, detail=raw[:200])


_WALK_AGGREGATES = {
    "count": len,
    "sum": sum,
    "max": max,
    "min": min,
    "avg": lambda values: sum(values) / len(values),
}


@register(ProbeKind.snmp_walk)
async def _snmp_walk(address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    """Обход поддерева OID со сверткой в одно число.

    Watch сравнивает ровно одно число, поэтому walk возвращает не список,
    а агрегат по поддереву: сколько строк в таблице (count), суммарный
    трафик по всем интерфейсам (sum), самый загруженный (max) и т.п.
    Сырой список в Sample не пишем — это история на каждый опрос, она
    разрослась бы быстрее всего остального вместе взятого.

    params: oid (корень поддерева), aggregate ("count"|"sum"|"max"|"min"|
    "avg", по умолчанию count), max_rows (защита от обхода всего дерева,
    по умолчанию 500) + те же параметры версии/доступа, что у snmp_get.

    Для v2c/v3 используется bulk (GETBULK — заметно меньше пакетов), для
    v1 — обычный обход: GETBULK в SNMPv1 не существует.
    """
    oid = params.get("oid")
    if not oid:
        return ProbeOutcome(ok=False, value=None, detail="params.oid обязателен")

    aggregate_name = str(params.get("aggregate", "count")).lower()
    aggregate = _WALK_AGGREGATES.get(aggregate_name)
    if aggregate is None:
        return ProbeOutcome(
            ok=False, value=None,
            detail=f"params.aggregate={aggregate_name!r} — допустимо: {', '.join(_WALK_AGGREGATES)}",
        )

    version = str(params.get("version", "2c"))
    port = int(params.get("port", 161))
    max_rows = int(params.get("max_rows", 500))
    auth, auth_error = _build_snmp_auth(params)
    if auth_error:
        return ProbeOutcome(ok=False, value=None, detail=auth_error)

    engine = SnmpEngine()
    values: list[float] = []
    non_numeric = 0
    try:
        target = await UdpTransportTarget.create((address, port), timeout=timeout_seconds, retries=0)
        # lexicographicMode=False — иначе обход НЕ останавливается на
        # границе запрошенного поддерева и идёт дальше по всему MIB
        # устройства (умолчание pysnmp — True). Поймано живой проверкой:
        # count по таблице ifIndex возвращал ровно max_rows, то есть
        # упирался в лимит строк, а не в конец таблицы, и агрегат считался
        # по значениям из посторонних веток.
        walk_options = {"lexicographicMode": False, "maxRows": max_rows}
        if version == "1":
            stream = walk_cmd(
                engine, auth, target, ContextData(), ObjectType(ObjectIdentity(oid)), **walk_options
            )
        else:
            stream = bulk_walk_cmd(
                engine, auth, target, ContextData(), 0, 25, ObjectType(ObjectIdentity(oid)), **walk_options
            )

        async def collect() -> str | None:
            nonlocal non_numeric
            async for error_indication, error_status, _idx, var_binds in stream:
                if error_indication:
                    return str(error_indication)
                if error_status:
                    return str(error_status.prettyPrint())
                for _oid_out, value_obj in var_binds:
                    try:
                        values.append(float(value_obj.prettyPrint()))
                    except ValueError:
                        # Строковые колонки (имена интерфейсов и т.п.) в
                        # числовой агрегат не годятся — считаем их отдельно
                        # и учитываем только в count.
                        non_numeric += 1
                if len(values) + non_numeric >= max_rows:
                    return None
            return None

        error = await asyncio.wait_for(collect(), timeout=timeout_seconds + 1)
    except asyncio.TimeoutError:
        return ProbeOutcome(ok=False, value=None, detail="timeout")
    finally:
        _close_engine(engine)

    if error:
        return ProbeOutcome(ok=False, value=None, detail=error)

    total_rows = len(values) + non_numeric
    if total_rows == 0:
        return ProbeOutcome(ok=True, value=0.0, detail="поддерево пустое")
    if aggregate_name == "count":
        return ProbeOutcome(ok=True, value=float(total_rows))
    if not values:
        return ProbeOutcome(
            ok=True, value=None,
            detail=f"{total_rows} строк, но ни одного числового значения — для {aggregate_name} нужны числа",
        )
    return ProbeOutcome(ok=True, value=float(aggregate(values)))


@register(ProbeKind.snmp_counter_rate)
async def _snmp_counter_rate(address: str, params: dict, timeout_seconds: float) -> ProbeOutcome:
    """Читает SNMP-счётчик как есть. Скорость из него вычисляет
    rate_engine при сохранении Sample — здесь нет доступа к предыдущему
    измерению, а без него «скорость» посчитать не из чего.

    Возвращает сырое показание в value; планировщик перекладывает его в
    Sample.raw_value и заменяет value на вычисленную скорость.

    params: те же, что у snmp_get (oid, версия, доступ), плюс
    counter_bits (32|64, по умолчанию 32) — используется в rate_engine
    для корректной обработки переполнения.
    """
    return await _snmp_get(address, params, timeout_seconds)
