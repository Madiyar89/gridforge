"""Автоопрос транковых кабельных соединений через CDP —
app/cable_discovery_engine.py. Парсер проверяется на синтетике,
discover_trunk_cable_links — с моком run_device_command (как
fake_device в test_api_sweeps.py подменяет SSH), реальный nmap/CDP на
устройство не ходит."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.cable_discovery_engine import discover_trunk_cable_links, parse_cdp_neighbors_detail
from app.device_client import DeviceResult
from app.main import app
from app.models import ApiKeyRole, CableLink, Group, Node, PortSnapshot, Vendor

CDP_OUTPUT = """Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
-------------------------
Device ID: sw-core-2.domain.local
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco WS-C2960X-48FPD-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/24,  Port ID (outgoing port): GigabitEthernet0/1
Holdtime : 123 sec
-------------------------
Device ID: ap-floor3
Entry address(es):
  IP address: 10.0.0.50
Platform: cisco AIR-AP,  Capabilities: Trans-Bridge
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): GigabitEthernet0
Holdtime : 150 sec
"""


def test_parse_cdp_neighbors_detail():
    neighbors = parse_cdp_neighbors_detail(CDP_OUTPUT)
    assert len(neighbors) == 2
    assert neighbors[0] == {
        "local_port": "GigabitEthernet1/0/24",
        "remote_device": "sw-core-2",
        "remote_port": "GigabitEthernet0/1",
    }
    assert neighbors[1]["remote_device"] == "ap-floor3"


def test_parse_cdp_neighbors_detail_ignores_incomplete_blocks():
    broken = "-------------------------\nDevice ID: only-device\n"
    assert parse_cdp_neighbors_detail(broken) == []


@pytest.fixture()
def group_with_trunk_node(db):
    group = Group(name="Тест-Группа")
    db.add(group)
    db.commit()
    db.refresh(group)
    node = Node(name="sw1", address="10.0.0.5", group_id=group.id, vendor=Vendor.cisco_ios)
    db.add(node)
    db.commit()
    db.refresh(node)
    snap = PortSnapshot(
        node_id=node.id,
        command="show interfaces status",
        ok=True,
        # Сокращённые имена, как в реальном выводе `show interfaces status`
        # ("Gi1/0/24") — а не "GigabitEthernet1/0/24", как отдаёт CDP.
        # Регрессия 2026-09-24: сравнение строк без нормализации давало
        # 0 совпадений на живом парке при полностью рабочей логике.
        ports=[
            {"name": "Gi1/0/24", "state": "up", "description": "", "vlan": "trunk", "speed": "1G", "is_trunk": True},
            {"name": "Gi1/0/5", "state": "up", "description": "", "vlan": "10", "speed": "1G", "is_trunk": False},
        ],
    )
    db.add(snap)
    db.commit()
    return group, node


def test_discover_trunk_cable_links_creates_only_for_trunk_ports(monkeypatch, db, group_with_trunk_node):
    group, node = group_with_trunk_node

    async def fake_run(*, vendor, host, command, username, password=None, key_path=None, port=None, timeout_seconds=None):
        return DeviceResult(True, 0, CDP_OUTPUT, None, "ssh")

    monkeypatch.setattr("app.device_client.run_device_command", fake_run)

    def fake_resolve(db, node):
        return {"username": "admin", "password": "x", "key_path": None}

    result = asyncio.run(discover_trunk_cable_links(db, group.id, resolve_credential=fake_resolve))
    assert result["created"] == 1  # только транковый GigabitEthernet1/0/24 — второй сосед не на транке
    assert result["checked_nodes"] == 1

    links = db.query(CableLink).filter(CableLink.group_id == group.id).all()
    assert len(links) == 1
    assert links[0].port_name == "Gi1/0/24"  # каноническое имя из снимка, не полное из CDP
    assert links[0].source == "cdp"
    assert "sw-core-2" in links[0].other_label


def test_discover_trunk_cable_links_updates_existing_cdp_row_not_duplicates(monkeypatch, db, group_with_trunk_node):
    group, node = group_with_trunk_node

    async def fake_run(*, vendor, host, command, username, password=None, key_path=None, port=None, timeout_seconds=None):
        return DeviceResult(True, 0, CDP_OUTPUT, None, "ssh")

    monkeypatch.setattr("app.device_client.run_device_command", fake_run)

    def fake_resolve(db, node):
        return {"username": "admin", "password": "x", "key_path": None}

    asyncio.run(discover_trunk_cable_links(db, group.id, resolve_credential=fake_resolve))
    result2 = asyncio.run(discover_trunk_cable_links(db, group.id, resolve_credential=fake_resolve))
    assert result2["created"] == 0
    assert result2["updated"] == 0  # label не изменился — обновлять нечего

    links = db.query(CableLink).filter(CableLink.group_id == group.id).all()
    assert len(links) == 1  # не задвоилось


def test_discover_trunk_cable_links_leaves_manual_entries_untouched(monkeypatch, db, group_with_trunk_node):
    group, node = group_with_trunk_node
    manual = CableLink(
        group_id=group.id, node_id=node.id, port_name="Gi1/0/24",
        other_label="каб. 305, розетка 2", source="manual",
    )
    db.add(manual)
    db.commit()

    async def fake_run(*, vendor, host, command, username, password=None, key_path=None, port=None, timeout_seconds=None):
        return DeviceResult(True, 0, CDP_OUTPUT, None, "ssh")

    monkeypatch.setattr("app.device_client.run_device_command", fake_run)

    def fake_resolve(db, node):
        return {"username": "admin", "password": "x", "key_path": None}

    asyncio.run(discover_trunk_cable_links(db, group.id, resolve_credential=fake_resolve))

    links = db.query(CableLink).filter(CableLink.group_id == group.id).all()
    assert len(links) == 2  # ручная запись осталась, плюс новая авто
    manual_row = next(l for l in links if l.source == "manual")
    assert manual_row.other_label == "каб. 305, розетка 2"


def test_discover_trunk_cable_links_skips_node_without_credential(db, group_with_trunk_node):
    group, node = group_with_trunk_node

    result = asyncio.run(discover_trunk_cable_links(db, group.id, resolve_credential=lambda db, node: None))
    assert result["created"] == 0
    assert any("учётки" in s for s in result["skipped"])


def _h(key):
    return {"X-API-Key": key}


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="дежурный", role=ApiKeyRole.operator)


def test_discover_trunks_endpoint(client, monkeypatch, operator_key, group_with_trunk_node):
    group, node = group_with_trunk_node

    async def fake_run(*, vendor, host, command, username, password=None, key_path=None, port=None, timeout_seconds=None):
        return DeviceResult(True, 0, CDP_OUTPUT, None, "ssh")

    monkeypatch.setattr("app.device_client.run_device_command", fake_run)
    monkeypatch.setattr("app.main.resolve_credential", lambda db, node: {"username": "admin", "password": "x", "key_path": None})

    resp = client.post(f"/api/groups/{group.id}/cable-links/discover-trunks", headers=_h(operator_key))
    assert resp.status_code == 200
    body = resp.json()
    assert body["created"] == 1

    rows = client.get(f"/api/groups/{group.id}/cable-links", headers=_h(operator_key)).json()
    assert len(rows) == 1
    assert rows[0]["source"] == "cdp"


def test_viewer_cannot_trigger_discover_trunks(client, db, group_with_trunk_node):
    group, node = group_with_trunk_node
    viewer_key = generate_key(db, label="смотритель", role=ApiKeyRole.viewer)
    resp = client.post(f"/api/groups/{group.id}/cable-links/discover-trunks", headers=_h(viewer_key))
    assert resp.status_code == 403


# --- Расписание автоопроса ---


def test_create_and_list_cable_schedule(client, operator_key, group_with_trunk_node):
    group, node = group_with_trunk_node
    resp = client.post(
        f"/api/groups/{group.id}/cable-schedules",
        json={"weekday": 0, "start_time": "03:00"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    sched_id = resp.json()["id"]

    rows = client.get(f"/api/groups/{group.id}/cable-schedules", headers=_h(operator_key)).json()
    assert len(rows) == 1
    assert rows[0]["id"] == sched_id
    assert rows[0]["weekday"] == 0
    assert rows[0]["start_time"] == "03:00"
    assert rows[0]["enabled"] is True


def test_update_and_delete_cable_schedule(client, operator_key, group_with_trunk_node):
    group, node = group_with_trunk_node
    sched_id = client.post(
        f"/api/groups/{group.id}/cable-schedules",
        json={"weekday": 0, "start_time": "03:00"},
        headers=_h(operator_key),
    ).json()["id"]

    resp = client.patch(
        f"/api/cable-schedules/{sched_id}",
        json={"weekday": 2, "start_time": "04:30", "enabled": False},
        headers=_h(operator_key),
    )
    assert resp.status_code == 200
    rows = client.get(f"/api/groups/{group.id}/cable-schedules", headers=_h(operator_key)).json()
    assert rows[0]["weekday"] == 2
    assert rows[0]["enabled"] is False

    resp = client.delete(f"/api/cable-schedules/{sched_id}", headers=_h(operator_key))
    assert resp.status_code == 204
    rows = client.get(f"/api/groups/{group.id}/cable-schedules", headers=_h(operator_key)).json()
    assert rows == []


def test_run_due_cable_discovery_schedules_triggers_and_guards_same_day(monkeypatch, db, group_with_trunk_node):
    import datetime as dt

    from app.cable_discovery_engine import run_due_cable_discovery_schedules
    from app.db import SessionLocal
    from app.models import CableDiscoverySchedule

    group, node = group_with_trunk_node
    now = dt.datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    past_hm = (now - dt.timedelta(minutes=5)).strftime("%H:%M")

    due = CableDiscoverySchedule(group_id=group.id, weekday=now.weekday(), start_time=past_hm)
    already_ran = CableDiscoverySchedule(
        group_id=group.id, weekday=now.weekday(), start_time=past_hm, last_triggered_on=today_str,
    )
    db.add_all([due, already_ran])
    db.commit()

    async def fake_run(*, vendor, host, command, username, password=None, key_path=None, port=None, timeout_seconds=None):
        return DeviceResult(True, 0, CDP_OUTPUT, None, "ssh")

    monkeypatch.setattr("app.device_client.run_device_command", fake_run)
    monkeypatch.setattr(
        "app.credentials_engine.resolve_credential",
        lambda db, node: {"username": "admin", "password": "x", "key_path": None},
    )

    asyncio.run(run_due_cable_discovery_schedules(SessionLocal))

    db.refresh(due)
    db.refresh(already_ran)
    assert due.last_triggered_on == today_str
    assert already_ran.last_triggered_on == today_str  # не переписалось повторно (было и осталось)

    links = db.query(CableLink).filter(CableLink.group_id == group.id).all()
    assert len(links) == 1
