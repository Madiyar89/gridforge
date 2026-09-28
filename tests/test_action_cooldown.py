"""Cooldown для Action (Action.cooldown_seconds) — защита от риска,
описанного в исходном handoff-документе: "мигающий Watch может
перезапускать сервис по кругу". Проверяем actions_engine.dispatch()
напрямую (без scheduler/фоновых задач — это тестируется отдельно в
test_action_dispatch.py), поэтому фикстуры/структура ниже следуют тому же
стилю _make_probe_with_action, что и там."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app import actions_engine
from app.models import (
    Action,
    ActionKind,
    ActionRun,
    Incident,
    Node,
    Probe,
    ProbeKind,
    Watch,
    WatchOperator,
    WatchSeverity,
)


def _make_watch_with_action(db, *, cooldown_seconds: int) -> tuple[Watch, Action]:
    node = Node(name="node-a", address="10.0.0.1")
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
        cooldown_seconds=cooldown_seconds,
    )
    db.add(action)
    db.commit()
    return watch, action


def _open_incident(db, watch: Watch) -> Incident:
    incident = Incident(watch_id=watch.id, detail="узел не отвечает")
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


async def _ok_run_ssh_command(**kwargs):
    from app.ssh_client import SshResult

    return SshResult(ok=True, exit_status=0, stdout="reboot ok", error=None)


def test_action_fires_when_no_prior_run(db, monkeypatch):
    """(a) Без единого ActionRun в истории Action должен выполниться."""
    monkeypatch.setattr(actions_engine, "run_ssh_command", _ok_run_ssh_command)
    watch, action = _make_watch_with_action(db, cooldown_seconds=300)
    incident = _open_incident(db, watch)

    asyncio.run(actions_engine.dispatch(db, [incident]))

    runs = db.query(ActionRun).filter(ActionRun.action_id == action.id).all()
    assert len(runs) == 1
    assert runs[0].ok is True
    assert runs[0].skipped is False


def test_action_skipped_within_cooldown_window(db, monkeypatch, caplog):
    """(b) Последний запуск был недавно (внутри cooldown) — новый Incident
    по тому же Watch не должен вызвать повторное SSH-выполнение, только
    отмеченную skipped=True запись ActionRun (флаппинг-защита)."""
    run_calls: list[str] = []

    async def _tracking_run_ssh_command(**kwargs):
        run_calls.append("called")
        return await _ok_run_ssh_command(**kwargs)

    monkeypatch.setattr(actions_engine, "run_ssh_command", _tracking_run_ssh_command)
    watch, action = _make_watch_with_action(db, cooldown_seconds=300)
    first_incident = _open_incident(db, watch)

    # Первое срабатывание — реальный запуск, cooldown ещё не тратился.
    asyncio.run(actions_engine.dispatch(db, [first_incident]))
    assert run_calls == ["called"]

    # Watch "мигнул": Incident закрылся и переоткрылся почти сразу же —
    # даём отдельный Incident, как это реально происходит в watch_engine.
    second_incident = _open_incident(db, watch)

    import logging

    with caplog.at_level(logging.INFO, logger="gridforge.actions"):
        asyncio.run(actions_engine.dispatch(db, [second_incident]))

    # Ни одного нового реального SSH-вызова — cooldown погасил повтор.
    assert run_calls == ["called"]
    runs = (
        db.query(ActionRun)
        .filter(ActionRun.action_id == action.id, ActionRun.incident_id == second_incident.id)
        .all()
    )
    assert len(runs) == 1
    assert runs[0].skipped is True
    assert runs[0].ok is False
    assert any("cooldown" in r.message for r in caplog.records)


def test_action_fires_again_after_cooldown_elapsed(db, monkeypatch):
    """(c) Последний ActionRun был раньше, чем cooldown_seconds назад —
    Action обязан сработать снова."""
    monkeypatch.setattr(actions_engine, "run_ssh_command", _ok_run_ssh_command)
    watch, action = _make_watch_with_action(db, cooldown_seconds=300)
    incident = _open_incident(db, watch)

    # Симулируем "старый" запуск, случившийся 10 минут назад — старше
    # cooldown_seconds=300 (5 минут).
    old_run = ActionRun(
        action_id=action.id,
        incident_id=incident.id,
        started_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        ok=True,
        output="reboot ok (старый прогон)",
    )
    db.add(old_run)
    db.commit()

    second_incident = _open_incident(db, watch)
    asyncio.run(actions_engine.dispatch(db, [second_incident]))

    runs = (
        db.query(ActionRun)
        .filter(ActionRun.action_id == action.id, ActionRun.incident_id == second_incident.id)
        .all()
    )
    assert len(runs) == 1
    assert runs[0].skipped is False
    assert runs[0].ok is True


def test_cooldown_zero_means_always_fire(db, monkeypatch):
    """(d) cooldown_seconds=0 — явный opt-out, срабатывает каждый раз,
    даже с ActionRun секунду назад."""
    call_count = {"n": 0}

    async def _counting_run_ssh_command(**kwargs):
        call_count["n"] += 1
        return await _ok_run_ssh_command(**kwargs)

    monkeypatch.setattr(actions_engine, "run_ssh_command", _counting_run_ssh_command)
    watch, action = _make_watch_with_action(db, cooldown_seconds=0)
    first_incident = _open_incident(db, watch)
    asyncio.run(actions_engine.dispatch(db, [first_incident]))
    assert call_count["n"] == 1

    second_incident = _open_incident(db, watch)
    asyncio.run(actions_engine.dispatch(db, [second_incident]))
    assert call_count["n"] == 2

    runs = db.query(ActionRun).filter(ActionRun.action_id == action.id).all()
    assert len(runs) == 2
    assert all(r.skipped is False for r in runs)
