import asyncio

import httpx

from app.models import Channel, ChannelKind, Incident, Node, Probe, ProbeKind, Watch, WatchOperator, WatchSeverity
from app.signal import dispatch


def _make_incident(db, *, node_name="node-a") -> Incident:
    node = Node(name=node_name, address="10.0.0.1")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, threshold=0, severity=WatchSeverity.critical, label="down")
    db.add(watch)
    db.commit()
    incident = Incident(watch_id=watch.id, detail="узел не отвечает")
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


class _RecordingClient:
    def __init__(self):
        self.calls = []

    async def post(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        return httpx.Response(200)


def test_global_channel_receives_incident_from_any_node(db):
    incident = _make_incident(db, node_name="node-a")
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident]))
    assert len(client.calls) == 1


def test_node_scoped_channel_ignores_other_nodes(db):
    incident_a = _make_incident(db, node_name="node-a")
    node_b_incident = _make_incident(db, node_name="node-b")

    other_node_id = node_b_incident.watch.probe.node_id
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}, node_id=other_node_id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident_a]))
    assert client.calls == []  # канал привязан к node-b, incident_a — с node-a


def test_node_scoped_channel_receives_matching_node_incident(db):
    incident = _make_incident(db, node_name="node-a")
    node_id = incident.watch.probe.node_id
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}, node_id=node_id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident]))
    assert len(client.calls) == 1


def test_watch_scoped_channel_ignores_other_watches_on_same_node(db):
    node = Node(name="shared-node", address="10.0.0.2")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch_a = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="a")
    watch_b = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="b")
    db.add_all([watch_a, watch_b])
    db.commit()
    incident_b = Incident(watch_id=watch_b.id, detail="b сработал")
    db.add(incident_b)
    db.commit()
    db.refresh(incident_b)

    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}, watch_id=watch_a.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident_b]))
    assert client.calls == []  # канал привязан к watch_a, инцидент — от watch_b на том же узле


def test_severity_threshold_still_applies_with_node_scope(db):
    incident = _make_incident(db, node_name="node-a")  # critical
    node_id = incident.watch.probe.node_id
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://x"}, node_id=node_id, min_severity=WatchSeverity.info))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident]))
    assert len(client.calls) == 1
