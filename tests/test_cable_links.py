"""Журнал учёта кабельных соединений — гибридная схема: один конец всегда
реальный Node+порт GridForge (сверяется с последним снимком портов узла),
другой — свободный текст (розетка/патч-панель/ПК)."""

from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Group, Node, PortSnapshot

client_app = app


def _h(key):
    return {"X-API-Key": key}


import pytest


@pytest.fixture()
def client():
    with TestClient(client_app) as c:
        yield c


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="дежурный", role=ApiKeyRole.operator)


@pytest.fixture()
def group_with_node(db):
    group = Group(name="Тест-Группа")
    db.add(group)
    db.commit()
    db.refresh(group)
    node = Node(name="sw1", address="10.0.0.5", group_id=group.id)
    db.add(node)
    db.commit()
    db.refresh(node)
    return group, node


@pytest.fixture()
def group_with_snapshot(db, group_with_node):
    group, node = group_with_node
    snap = PortSnapshot(
        node_id=node.id,
        command="show interfaces status",
        ok=True,
        ports=[
            {"name": "Gi1/0/1", "state": "up", "description": "", "vlan": "10", "speed": "1G", "is_trunk": False},
            {"name": "Gi1/0/2", "state": "down", "description": "", "vlan": "10", "speed": "", "is_trunk": False},
        ],
    )
    db.add(snap)
    db.commit()
    return group, node


def test_create_and_list_cable_link_without_snapshot(client, operator_key, group_with_node):
    group, node = group_with_node
    resp = client.post(
        f"/api/groups/{group.id}/cable-links",
        json={
            "node_id": node.id,
            "port_name": "Gi1/0/1",
            "other_label": "каб. 305, розетка 2",
            "cable_type": "UTP cat6",
            "length_m": 12.5,
            "status": "active",
            "responsible": "Иванов И.И.",
            "laid_on": "2026-09-24",
        },
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    link_id = resp.json()["id"]

    rows = client.get(f"/api/groups/{group.id}/cable-links", headers=_h(operator_key)).json()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == link_id
    assert row["node_name"] == "sw1"
    assert row["port_name"] == "Gi1/0/1"
    assert row["other_label"] == "каб. 305, розетка 2"
    assert row["status"] == "active"
    assert row["status_label"] == "в работе"
    assert row["length_m"] == 12.5


def test_create_cable_link_validates_port_against_snapshot(client, operator_key, group_with_snapshot):
    group, node = group_with_snapshot
    resp = client.post(
        f"/api/groups/{group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi9/9/9", "other_label": "куда-то"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400

    resp_ok = client.post(
        f"/api/groups/{group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi1/0/2", "other_label": "куда-то"},
        headers=_h(operator_key),
    )
    assert resp_ok.status_code == 201


def test_create_cable_link_rejects_wrong_group_node(client, operator_key, db, group_with_node):
    group, node = group_with_node
    other_group = Group(name="Другая группа")
    db.add(other_group)
    db.commit()
    db.refresh(other_group)
    resp = client.post(
        f"/api/groups/{other_group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi1/0/1", "other_label": "куда-то"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_update_and_delete_cable_link(client, operator_key, group_with_node):
    group, node = group_with_node
    link_id = client.post(
        f"/api/groups/{group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi1/0/1", "other_label": "каб. 305"},
        headers=_h(operator_key),
    ).json()["id"]

    resp = client.patch(
        f"/api/cable-links/{link_id}",
        json={"node_id": node.id, "port_name": "Gi1/0/1", "other_label": "каб. 305", "status": "damaged"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 200
    rows = client.get(f"/api/groups/{group.id}/cable-links", headers=_h(operator_key)).json()
    assert rows[0]["status"] == "damaged"

    resp = client.delete(f"/api/cable-links/{link_id}", headers=_h(operator_key))
    assert resp.status_code == 204
    rows = client.get(f"/api/groups/{group.id}/cable-links", headers=_h(operator_key)).json()
    assert rows == []


def test_viewer_cannot_create_cable_link(client, db, group_with_node):
    group, node = group_with_node
    viewer_key = generate_key(db, label="смотритель", role=ApiKeyRole.viewer)
    resp = client.post(
        f"/api/groups/{group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi1/0/1", "other_label": "куда-то"},
        headers=_h(viewer_key),
    )
    assert resp.status_code == 403


def test_group_scoped_key_cannot_create_in_other_group(client, db, group_with_node):
    group, node = group_with_node
    other_group = Group(name="Другая группа")
    db.add(other_group)
    db.commit()
    db.refresh(other_group)
    scoped_key = generate_key(db, label="ограниченный", role=ApiKeyRole.operator, group_id=other_group.id)
    resp = client.post(
        f"/api/groups/{group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi1/0/1", "other_label": "куда-то"},
        headers=_h(scoped_key),
    )
    assert resp.status_code == 403


def test_download_cable_links_xlsx(client, operator_key, group_with_node):
    group, node = group_with_node
    client.post(
        f"/api/groups/{group.id}/cable-links",
        json={"node_id": node.id, "port_name": "Gi1/0/1", "other_label": "каб. 305"},
        headers=_h(operator_key),
    )
    resp = client.get(f"/api/groups/{group.id}/cable-links.xlsx", headers=_h(operator_key))
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert len(resp.content) > 0
