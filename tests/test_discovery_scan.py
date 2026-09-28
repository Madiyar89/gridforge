"""Плановый скан сети с оповещением о новых устройствах (docs/
landscape-report.md, п.4.1) — app/scan_engine.py (new_hosts_in_scan,
run_scan_and_notify, run_due_discovery_schedules) и
app/signal.py (notify_new_devices). Реальный nmap не запускается — тот
же приём, что в test_vuln_scan.py: подмена asyncio.create_subprocess_exec
на канн-XML."""

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Channel, ChannelKind, DiscoveryScanSchedule, Node, Scan, ScanStatus
from app.scan_engine import new_hosts_in_scan, run_due_discovery_schedules, run_scan_and_notify
from app.signal import notify_new_devices

SCAN_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="known-sw"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
  </ports>
</host>
<host>
  <status state="up"/>
  <address addr="10.0.0.99" addrtype="ipv4"/>
  <hostnames></hostnames>
  <ports>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
  </ports>
</host>
</nmaprun>
"""


class _FakeProc:
    def __init__(self, stdout: bytes):
        self._stdout = stdout
        self.returncode = 0

    async def communicate(self):
        return self._stdout, b""

    def kill(self):
        pass


@pytest.fixture(autouse=True)
def fake_nmap(monkeypatch):
    async def fake_exec(*args, **kwargs):
        return _FakeProc(SCAN_XML.encode())

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)


class _RecordingClient:
    def __init__(self):
        self.calls = []

    async def post(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        return httpx.Response(200)


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="дежурный", role=ApiKeyRole.operator)


def _h(key):
    return {"X-API-Key": key}


# --- new_hosts_in_scan / run_scan_and_notify ---


def test_new_hosts_in_scan_excludes_known_nodes(db):
    db.add(Node(name="known-sw", address="10.0.0.5"))
    db.commit()

    scan = asyncio.run(run_scan_and_notify(db, _RecordingClient(), "10.0.0.0/24"))
    assert scan.status == ScanStatus.done

    new_hosts = new_hosts_in_scan(db, scan)
    assert len(new_hosts) == 1
    assert new_hosts[0]["address"] == "10.0.0.99"


def test_run_scan_and_notify_sends_to_unscoped_channel_only(db):
    db.add(Node(name="known-sw", address="10.0.0.5"))
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}))
    db.commit()

    client = _RecordingClient()
    scan = asyncio.run(run_scan_and_notify(db, client, "10.0.0.0/24"))
    assert scan.status == ScanStatus.done
    assert len(client.calls) == 1
    assert "10.0.0.99" in client.calls[0][1]["message"]
    assert "10.0.0.5" not in client.calls[0][1]["message"]  # известный узел не попадает в оповещение


def test_run_scan_and_notify_no_new_hosts_no_notification(db):
    db.add(Node(name="known-sw", address="10.0.0.5"))
    db.add(Node(name="other", address="10.0.0.99"))
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}))
    db.commit()

    client = _RecordingClient()
    asyncio.run(run_scan_and_notify(db, client, "10.0.0.0/24"))
    assert client.calls == []


def test_notify_new_devices_ignores_node_scoped_channel(db):
    node = Node(name="n1", address="10.0.0.1")
    db.add(node)
    db.commit()
    db.refresh(node)
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://example.test/hook"}, node_id=node.id))
    db.commit()

    client = _RecordingClient()
    asyncio.run(notify_new_devices(client, db, [{"address": "10.0.0.99", "hostname": None}]))
    assert client.calls == []  # оповещение о новых устройствах — только для по-настоящему общих каналов


# --- Расписание планового скана ---


def test_create_and_list_discovery_schedule(client, operator_key):
    resp = client.post(
        "/api/discovery-schedules",
        json={"cidr": "10.0.0.0/24", "weekday": 0, "start_time": "02:00"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    sched_id = resp.json()["id"]

    rows = client.get("/api/discovery-schedules", headers=_h(operator_key)).json()
    assert len(rows) == 1
    assert rows[0]["id"] == sched_id
    assert rows[0]["cidr"] == "10.0.0.0/24"
    assert rows[0]["enabled"] is True


def test_create_discovery_schedule_rejects_bad_cidr(client, operator_key):
    resp = client.post(
        "/api/discovery-schedules",
        json={"cidr": "not-a-cidr", "weekday": 0, "start_time": "02:00"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_update_and_delete_discovery_schedule(client, operator_key):
    sched_id = client.post(
        "/api/discovery-schedules",
        json={"cidr": "10.0.0.0/24", "weekday": 0, "start_time": "02:00"},
        headers=_h(operator_key),
    ).json()["id"]

    resp = client.patch(
        f"/api/discovery-schedules/{sched_id}",
        json={"cidr": "10.0.0.0/24", "weekday": 3, "start_time": "05:00", "enabled": False},
        headers=_h(operator_key),
    )
    assert resp.status_code == 200
    rows = client.get("/api/discovery-schedules", headers=_h(operator_key)).json()
    assert rows[0]["weekday"] == 3
    assert rows[0]["enabled"] is False

    resp = client.delete(f"/api/discovery-schedules/{sched_id}", headers=_h(operator_key))
    assert resp.status_code == 204
    assert client.get("/api/discovery-schedules", headers=_h(operator_key)).json() == []


def test_run_due_discovery_schedules_triggers_and_guards_same_day(db):
    import datetime as dt

    from app.db import SessionLocal

    now = dt.datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    past_hm = (now - dt.timedelta(minutes=5)).strftime("%H:%M")

    due = DiscoveryScanSchedule(cidr="10.0.0.0/24", weekday=now.weekday(), start_time=past_hm)
    already_ran = DiscoveryScanSchedule(
        cidr="10.0.0.0/24", weekday=now.weekday(), start_time=past_hm, last_triggered_on=today_str,
    )
    db.add_all([due, already_ran])
    db.commit()

    asyncio.run(run_due_discovery_schedules(SessionLocal, _RecordingClient()))

    db.refresh(due)
    db.refresh(already_ran)
    assert due.last_triggered_on == today_str
    assert already_ran.last_triggered_on == today_str  # не переписалось повторно

    scans = db.query(Scan).filter(Scan.cidr == "10.0.0.0/24").all()
    assert len(scans) == 1  # только "due" реально отсканировал
