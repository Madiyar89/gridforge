"""Батчинг db-записи для syslog_server.py/netflow_server.py (доработка по
итогам аудита — раньше один db.commit() на КАЖДОЕ входящее UDP-сообщение/
пакет). Проверяем: (a) N сообщений в буфере дают намного меньше commit'ов,
чем N (bulk_insert_mappings + один commit на batch), (b) периодический
flush по таймеру реально случается (без size-триггера), (c) node_id
разрешается пачкой на весь batch. Стиль — тот же db-фикстура/пересоздание
схемы из conftest.py, что у остальных тестов (см. test_syslog_pri_parser.py
для соглашений этой области); event-based ожидание там, где возможно
(см. tests/test_action_dispatch.py/tests/test_scheduler_shutdown.py),
короткий реальный sleep допустим только там, где сам факт периодического
таймера и есть предмет проверки — тот же приём, что в
test_shutdown_periodic_tasks_lets_fast_task_finish_within_grace_window."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.orm import Session

from app.models import FlowRecord, Node, SyslogMessage


def _tracking_get_session(monkeypatch, module, commit_calls: dict) -> None:
    """Подменяет module.get_session() на версию, оборачивающую
    session.commit() счётчиком — те же реальные session/engine (тестовая
    SQLite из conftest.py), просто с подсчётом фактических commit()."""
    from app.db import SessionLocal

    def _wrapped() -> Session:
        session = SessionLocal()
        original_commit = session.commit

        def _commit():
            commit_calls["n"] += 1
            return original_commit()

        session.commit = _commit
        return session

    monkeypatch.setattr(module, "get_session", _wrapped)


# --------------------------------------------------------------------------
# SyslogBatcher
# --------------------------------------------------------------------------


def test_syslog_batch_flush_uses_one_commit_per_batch_not_per_message(monkeypatch):
    import app.syslog_server as syslog_server

    commit_calls = {"n": 0}
    _tracking_get_session(monkeypatch, syslog_server, commit_calls)

    batcher = syslog_server.SyslogBatcher(batch_size=200)
    for i in range(1000):
        batcher.add(f"10.0.0.{i % 5}", 16, 6, f"сообщение {i}")
    batcher.flush()  # досбросить неполный остаток, если он есть

    # 1000 сообщений при batch_size=200 -> ровно 5 срабатываний по размеру,
    # НЕ 1000 отдельных commit'ов (было бы 1000 до этой доработки).
    assert commit_calls["n"] == 5
    assert commit_calls["n"] < 1000


def test_syslog_batch_does_not_flush_before_size_threshold(monkeypatch, db):
    import app.syslog_server as syslog_server

    commit_calls = {"n": 0}
    _tracking_get_session(monkeypatch, syslog_server, commit_calls)

    batcher = syslog_server.SyslogBatcher(batch_size=10)
    for i in range(9):
        batcher.add("10.0.0.1", None, None, f"msg {i}")

    assert len(batcher) == 9
    assert commit_calls["n"] == 0
    assert db.query(SyslogMessage).count() == 0


def test_syslog_batch_resolves_node_id_in_bulk_at_flush_time(monkeypatch, db):
    import app.syslog_server as syslog_server

    node = Node(name="floor-1", address="10.0.0.1")
    db.add(node)
    db.commit()
    db.refresh(node)

    _tracking_get_session(monkeypatch, syslog_server, {"n": 0})

    batcher = syslog_server.SyslogBatcher(batch_size=100)
    batcher.add("10.0.0.1", 16, 6, "known node")
    batcher.add("10.0.0.99", 16, 6, "unknown node")
    batcher.flush()

    rows = {row.source_ip: row.node_id for row in db.query(SyslogMessage).all()}
    assert rows["10.0.0.1"] == node.id
    assert rows["10.0.0.99"] is None


@pytest.mark.parametrize("env_value", ["3"])
def test_syslog_batch_size_env_var_override(monkeypatch, env_value):
    monkeypatch.setenv("GRIDFORGE_SYSLOG_BATCH_SIZE", env_value)
    import importlib

    import app.syslog_server as syslog_server

    importlib.reload(syslog_server)
    try:
        assert syslog_server.SYSLOG_BATCH_SIZE == int(env_value)
    finally:
        monkeypatch.undo()
        importlib.reload(syslog_server)


def test_syslog_periodic_flush_triggers_on_timer_not_just_size(monkeypatch, db):
    """Меньше сообщений, чем batch_size — единственный способ их
    сохранить это дождаться таймера. Короткий interval + короткий
    реальный sleep — сам факт периодического срабатывания и есть предмет
    теста (тот же приём, что в test_scheduler_shutdown.py для "быстрой"
    задачи)."""
    import app.syslog_server as syslog_server

    _tracking_get_session(monkeypatch, syslog_server, {"n": 0})

    batcher = syslog_server.SyslogBatcher(batch_size=1000)
    batcher.add("10.0.0.1", None, None, "не хватает до size-порога")
    assert len(batcher) == 1

    async def _run() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(syslog_server._periodic_flush(batcher, stop, interval=0.05))
        await asyncio.sleep(0.12)  # даём таймеру сработать хотя бы раз
        stop.set()
        await task

    asyncio.run(_run())

    assert len(batcher) == 0
    assert db.query(SyslogMessage).count() == 1


def test_syslog_periodic_flush_does_final_flush_on_stop_even_before_first_tick(monkeypatch, db):
    """Финальный flush() на остановке — последний неполный batch не
    должен теряться, даже если stop.set() происходит раньше первого
    тика таймера."""
    import app.syslog_server as syslog_server

    _tracking_get_session(monkeypatch, syslog_server, {"n": 0})

    batcher = syslog_server.SyslogBatcher(batch_size=1000)
    batcher.add("10.0.0.1", None, None, "должно быть сохранено при остановке")

    async def _run() -> None:
        stop = asyncio.Event()
        stop.set()  # уже остановлен до первого тика
        await syslog_server._periodic_flush(batcher, stop, interval=60.0)

    asyncio.run(_run())

    assert len(batcher) == 0
    assert db.query(SyslogMessage).count() == 1


# --------------------------------------------------------------------------
# FlowBatcher
# --------------------------------------------------------------------------


def _flow_record(i: int) -> dict:
    return {
        "exporter_ip": "192.0.2.1",
        "src_addr": f"10.0.0.{i % 5}",
        "dst_addr": "10.0.0.254",
        "src_port": 1234,
        "dst_port": 443,
        "protocol": 6,
        "byte_count": 100,
        "packet_count": 1,
    }


def test_netflow_batch_flush_uses_one_commit_per_batch_not_per_record(monkeypatch):
    import app.netflow_server as netflow_server

    commit_calls = {"n": 0}
    _tracking_get_session(monkeypatch, netflow_server, commit_calls)

    batcher = netflow_server.FlowBatcher(batch_size=500)
    for i in range(2000):
        batcher.add_many([_flow_record(i)])
    batcher.flush()

    # 2000 записей при batch_size=500 -> ровно 4 срабатывания по размеру.
    assert commit_calls["n"] == 4
    assert commit_calls["n"] < 2000


def test_netflow_batch_does_not_flush_before_size_threshold(monkeypatch, db):
    import app.netflow_server as netflow_server

    commit_calls = {"n": 0}
    _tracking_get_session(monkeypatch, netflow_server, commit_calls)

    batcher = netflow_server.FlowBatcher(batch_size=50)
    batcher.add_many([_flow_record(i) for i in range(49)])

    assert len(batcher) == 49
    assert commit_calls["n"] == 0
    assert db.query(FlowRecord).count() == 0


def test_netflow_periodic_flush_triggers_on_timer_not_just_size(monkeypatch, db):
    import app.netflow_server as netflow_server

    _tracking_get_session(monkeypatch, netflow_server, {"n": 0})

    batcher = netflow_server.FlowBatcher(batch_size=1000)
    batcher.add_many([_flow_record(0)])
    assert len(batcher) == 1

    async def _run() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(netflow_server._periodic_flush(batcher, stop, interval=0.05))
        await asyncio.sleep(0.12)
        stop.set()
        await task

    asyncio.run(_run())

    assert len(batcher) == 0
    assert db.query(FlowRecord).count() == 1


@pytest.mark.parametrize("env_value", ["7"])
def test_netflow_batch_size_env_var_override(monkeypatch, env_value):
    monkeypatch.setenv("GRIDFORGE_NETFLOW_BATCH_SIZE", env_value)
    import importlib

    import app.netflow_server as netflow_server

    importlib.reload(netflow_server)
    try:
        assert netflow_server.NETFLOW_BATCH_SIZE == int(env_value)
    finally:
        monkeypatch.undo()
        importlib.reload(netflow_server)


# --------------------------------------------------------------------------
# Rate limiting integrated into the protocol (datagram_received drops early)
# --------------------------------------------------------------------------


def test_syslog_protocol_drops_over_limit_without_buffering(monkeypatch):
    """datagram_received должен не только не сохранять, но и вообще не
    парсить/буферизовать датаграмму, если RateLimiter её отклонил —
    отброшенное сообщение не должно попадать в SyslogBatcher."""
    import app.syslog_server as syslog_server

    batcher = syslog_server.SyslogBatcher(batch_size=1000)
    rate_limiter = syslog_server.RateLimiter(per_source_limit=2, global_limit=1000)
    protocol = syslog_server.SyslogProtocol(batcher, rate_limiter)

    for _ in range(5):
        protocol.datagram_received(b"<134>flood message", ("10.0.0.1", 5140))

    # Лимит 2/с на source_ip — из 5 датаграмм должно остаться ровно 2.
    assert len(batcher) == 2


def test_netflow_protocol_drops_over_limit_without_buffering(monkeypatch):
    import app.netflow_server as netflow_server
    import struct

    batcher = netflow_server.FlowBatcher(batch_size=1000)
    rate_limiter = netflow_server.RateLimiter(per_source_limit=1, global_limit=1000)
    protocol = netflow_server.NetflowProtocol(batcher, rate_limiter)

    # Пакет без валидных FlowSet (версия != 9) — сам парсинг вернёт [],
    # здесь достаточно убедиться, что после превышения лимита пакет даже
    # не пытается быть распарсен повторно (косвенно — не растёт буфер,
    # т.к. записей и так нет; реальная проверка отбрасывания — по факту,
    # что второй/третий вызов не должен приводить к попытке parse при
    # выключенном лимите пропуска).
    bogus_v9_header = struct.pack(">HHIIII", 9, 0, 0, 0, 0, 0)
    for _ in range(3):
        protocol.datagram_received(bogus_v9_header, ("192.0.2.1", 2055))

    # count=0 flowsets -> records всегда пустой список независимо от
    # rate-limit, поэтому здесь проверяем непосредственно rate_limiter:
    assert rate_limiter.allow("192.0.2.1") is False  # лимит уже исчерпан
