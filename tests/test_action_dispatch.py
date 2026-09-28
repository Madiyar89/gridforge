"""Action dispatch должен выполняться в фоне (asyncio.create_task), не
блокируя scheduler._run_due() — см. app/scheduler.py/_dispatch_actions_safe
и app/actions_engine.py. Три проверки по задаче аудита:

  (a) фоновая Action-задача не блокирует обработку остальных Probe в этом
      же тике _run_due() — доказываем детерминированно через asyncio.Event,
      который держит мок run_ssh_command "зависшим" до явного set(),
      без sleep-based тайминга;
  (b) ActionRun всё равно пишется в БД, когда фоновая задача завершается;
  (c) исключение внутри фоновой Action-задачи не вылетает наружу и не
      останавливает scheduler (перехватывается в _dispatch_actions_safe).
"""

from __future__ import annotations

import asyncio

import pytest

from app import actions_engine
from app.models import (
    Action,
    ActionKind,
    ActionRun,
    Node,
    Probe,
    ProbeKind,
    Watch,
    WatchOperator,
    WatchSeverity,
)
from app.probes import ProbeOutcome
from app.scheduler import Scheduler


def _make_probe_with_action(db, *, node_name="node-a") -> Probe:
    """Watch с probe_failed/streak_required=1 — первая же "неудачная"
    выборка сразу открывает Incident, без накопления серии."""
    node = Node(name=node_name, address="10.0.0.1")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping, interval_seconds=60, timeout_seconds=5)
    db.add(probe)
    db.commit()
    watch = Watch(
        probe_id=probe.id,
        operator=WatchOperator.probe_failed,
        streak_required=1,
        severity=WatchSeverity.critical,
        label="down",
    )
    db.add(watch)
    db.commit()
    action = Action(
        watch_id=watch.id,
        kind=ActionKind.ssh_command,
        config={"username": "admin", "password": "***", "command": "reboot"},
    )
    db.add(action)
    db.commit()
    db.refresh(probe)
    return probe


def _make_plain_probe(db, *, node_name="node-b") -> Probe:
    """Probe без Watch/Action — просто второй узел, чей опрос не должен
    задерживаться Action'ом, сработавшим на первом узле."""
    node = Node(name=node_name, address="10.0.0.2")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping, interval_seconds=60, timeout_seconds=5)
    db.add(probe)
    db.commit()
    db.refresh(probe)
    return probe


async def _drain(scheduler: Scheduler) -> None:
    """Дождаться завершения всех фоновых Action-задач, отслеживаемых
    scheduler._action_tasks — детерминированная альтернатива sleep()."""
    if scheduler._action_tasks:
        await asyncio.wait(list(scheduler._action_tasks))


def test_action_dispatch_does_not_block_other_probes_in_same_tick(db, monkeypatch):
    probe_a = _make_probe_with_action(db)
    probe_b = _make_plain_probe(db)

    hold = asyncio.Event()  # никогда не .set() в этом тесте — держит SSH "зависшим"
    calls: list[str] = []

    async def _hanging_run_ssh_command(**kwargs):
        calls.append("started")
        await hold.wait()  # если _run_due когда-либо будет await'ить это напрямую — тест зависнет
        calls.append("finished")
        from app.ssh_client import SshResult

        return SshResult(ok=True, exit_status=0, stdout="ok", error=None)

    monkeypatch.setattr(actions_engine, "run_ssh_command", _hanging_run_ssh_command)

    async def _fake_run_probe(kind, address, params, timeout_seconds, node_id=None):
        return ProbeOutcome(ok=False, value=None, detail="узел не отвечает")

    monkeypatch.setattr("app.scheduler.run_probe", _fake_run_probe)

    scheduler = Scheduler()
    scheduler._known_probe_ids.update({probe_a.id, probe_b.id})
    import heapq
    import time

    now = time.monotonic()
    heapq.heappush(scheduler._heap, (now, probe_a.id))
    heapq.heappush(scheduler._heap, (now, probe_b.id))  # оба due в одном тике, probe_a первым в куче (id меньше)

    async def _run() -> None:
        await scheduler._run_due()

    asyncio.run(_run())

    # probe_a запустил Action (SSH висит на hold.wait(), не завершился) —
    # если бы dispatch() был await'нут синхронно, как раньше, _run_due()
    # не дошёл бы до обработки probe_b пока SSH не отвечает. Раз Sample
    # для probe_b всё равно записан — значит Action не блокировал цикл.
    assert calls == ["started"]
    from app.models import Sample

    assert db.query(Sample).filter(Sample.probe_id == probe_b.id).count() == 1
    assert db.query(ActionRun).count() == 0  # SSH ещё не завершился — ActionRun не мог быть записан


def test_action_run_still_written_after_background_task_completes(db, monkeypatch):
    probe = _make_probe_with_action(db)

    async def _ok_run_ssh_command(**kwargs):
        from app.ssh_client import SshResult

        return SshResult(ok=True, exit_status=0, stdout="reboot ok", error=None)

    monkeypatch.setattr(actions_engine, "run_ssh_command", _ok_run_ssh_command)

    async def _fake_run_probe(kind, address, params, timeout_seconds, node_id=None):
        return ProbeOutcome(ok=False, value=None, detail="узел не отвечает")

    monkeypatch.setattr("app.scheduler.run_probe", _fake_run_probe)

    scheduler = Scheduler()
    scheduler._known_probe_ids.add(probe.id)
    import heapq
    import time

    heapq.heappush(scheduler._heap, (time.monotonic(), probe.id))

    async def _run() -> None:
        await scheduler._run_due()
        assert db.query(ActionRun).count() == 0  # фоновая задача ещё не выполнилась
        await _drain(scheduler)

    asyncio.run(_run())

    runs = db.query(ActionRun).all()
    assert len(runs) == 1
    assert runs[0].ok is True
    assert "reboot ok" in (runs[0].output or "")


def test_exception_in_background_action_task_is_swallowed_and_logged(db, monkeypatch, caplog):
    probe = _make_probe_with_action(db)

    async def _boom_run_ssh_command(**kwargs):
        raise RuntimeError("сеть недоступна")

    monkeypatch.setattr(actions_engine, "run_ssh_command", _boom_run_ssh_command)

    async def _fake_run_probe(kind, address, params, timeout_seconds, node_id=None):
        return ProbeOutcome(ok=False, value=None, detail="узел не отвечает")

    monkeypatch.setattr("app.scheduler.run_probe", _fake_run_probe)

    scheduler = Scheduler()
    scheduler._known_probe_ids.add(probe.id)
    import heapq
    import time

    heapq.heappush(scheduler._heap, (time.monotonic(), probe.id))

    async def _run() -> None:
        await scheduler._run_due()  # не должно бросить исключение наружу
        await _drain(scheduler)

    import logging

    with caplog.at_level(logging.ERROR, logger="gridforge.scheduler"):
        asyncio.run(_run())  # если исключение не перехвачено — asyncio.run бросит его здесь

    assert any("Action" in r.message for r in caplog.records)
    # Само исключение не должно попасть в ActionRun как обычная запись —
    # dispatch() не успел дойти до db.add(ActionRun(...)) для этого action.
    assert db.query(ActionRun).count() == 0
