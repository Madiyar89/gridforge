import asyncio
from datetime import timedelta

import httpx

from app.escalation_engine import run_escalations
from app.models import (
    Channel,
    ChannelKind,
    EscalationStep,
    Incident,
    Node,
    Probe,
    ProbeKind,
    Watch,
    WatchOperator,
    WatchSeverity,
    _now,
)


class _RecordingClient:
    def __init__(self):
        self.calls = []

    async def post(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        return httpx.Response(200)


def _make_open_incident(db, *, opened_minutes_ago: float) -> Incident:
    node = Node(name="esc-node", address="10.0.0.9")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="down")
    db.add(watch)
    db.commit()
    incident = Incident(
        watch_id=watch.id,
        detail="узел недоступен",
        opened_at=_now() - timedelta(minutes=opened_minutes_ago),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def test_no_steps_configured_does_nothing(db):
    incident = _make_open_incident(db, opened_minutes_ago=999)
    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert client.calls == []
    assert incident.last_escalated_minutes == 0


def test_step_not_due_yet_does_not_fire(db):
    incident = _make_open_incident(db, opened_minutes_ago=5)
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=15, channel_id=channel.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert client.calls == []
    db.refresh(incident)
    assert incident.last_escalated_minutes == 0


def test_due_step_fires_and_marks_incident(db):
    incident = _make_open_incident(db, opened_minutes_ago=20)
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=15, channel_id=channel.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert len(client.calls) == 1
    db.refresh(incident)
    assert incident.last_escalated_minutes == 15


def test_already_fired_step_does_not_refire(db):
    incident = _make_open_incident(db, opened_minutes_ago=20)
    incident.last_escalated_minutes = 15
    db.commit()
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=15, channel_id=channel.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert client.calls == []  # шаг на 15 минут уже был отправлен раньше


def test_multiple_due_steps_fire_in_order_up_to_the_latest(db):
    incident = _make_open_incident(db, opened_minutes_ago=40)
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=10, channel_id=channel.id))
    db.add(EscalationStep(delay_minutes=30, channel_id=channel.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert len(client.calls) == 2  # оба шага (10 и 30 минут) должны отправиться
    db.refresh(incident)
    assert incident.last_escalated_minutes == 30


def test_resolved_incident_is_not_escalated(db):
    incident = _make_open_incident(db, opened_minutes_ago=20)
    incident.resolved_at = _now()
    db.commit()
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=15, channel_id=channel.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert client.calls == []


def test_disabled_step_is_skipped(db):
    incident = _make_open_incident(db, opened_minutes_ago=20)
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=15, channel_id=channel.id, enabled=False))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert client.calls == []


def test_channel_node_scope_still_respected_during_escalation(db):
    incident = _make_open_incident(db, opened_minutes_ago=20)
    other_node = Node(name="other-node", address="10.0.0.10")
    db.add(other_node)
    db.commit()
    channel = Channel(kind=ChannelKind.webhook, config={"url": "http://x"}, node_id=other_node.id)
    db.add(channel)
    db.commit()
    db.add(EscalationStep(delay_minutes=15, channel_id=channel.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_escalations(client, db))
    assert client.calls == []  # канал сужен на другой узел — эскалация не должна его обойти
