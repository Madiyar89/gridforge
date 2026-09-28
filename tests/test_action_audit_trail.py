"""Аудит-трейл Action (created_by/updated_by/updated_at, см. models.py) —
проверка на API-уровне (POST/PATCH /api/actions), в отличие от
test_action_dispatch.py/test_action_cooldown.py, которые бьют по
actions_engine.dispatch() напрямую. Фикстуры/стиль TestClient —
как в test_api_sweeps.py."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import Action, ApiKeyRole, Node, Probe, ProbeKind, Watch, WatchOperator, WatchSeverity


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="admin-один", role=ApiKeyRole.admin)


@pytest.fixture()
def other_admin_key(db):
    return generate_key(db, label="admin-два", role=ApiKeyRole.admin)


@pytest.fixture()
def watch(db):
    node = Node(name="node-a", address="10.0.0.1")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping, interval_seconds=60, timeout_seconds=5)
    db.add(probe)
    db.commit()
    w = Watch(
        probe_id=probe.id,
        operator=WatchOperator.probe_failed,
        streak_required=1,
        severity=WatchSeverity.critical,
        label="down",
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return w


def _h(key):
    return {"X-API-Key": key}


def _create_action(client, key, watch_id, **overrides):
    payload = {
        "watch_id": watch_id,
        "kind": "ssh_command",
        "config": {"username": "admin", "password": "x", "command": "show version"},
    }
    payload.update(overrides)
    return client.post("/api/actions", json=payload, headers=_h(key))


def test_creating_action_records_creator(client, admin_key, watch, db):
    """(a) Создание Action фиксирует, какой админ его завёл."""
    resp = _create_action(client, admin_key, watch.id)
    assert resp.status_code == 201
    action_id = resp.json()["id"]

    action = db.get(Action, action_id)
    assert action.created_by == "admin-один"
    assert action.updated_by is None
    assert action.updated_at is None


def test_updating_action_records_editor_and_refreshes_updated_at(client, admin_key, watch, db):
    """(b) PATCH фиксирует, кто редактировал, и проставляет updated_at."""
    action_id = _create_action(client, admin_key, watch.id).json()["id"]

    resp = client.patch(
        f"/api/actions/{action_id}",
        json={"cooldown_seconds": 120},
        headers=_h(admin_key),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["updated_by"] == "admin-один"
    assert body["updated_at"] is not None

    action = db.get(Action, action_id)
    assert action.updated_by == "admin-один"
    assert action.updated_at is not None


def test_get_actions_exposes_audit_fields(client, admin_key, watch):
    """(c) GET /api/actions отдаёт created_by/created_at/updated_by/updated_at,
    не только записывает их молча в БД."""
    _create_action(client, admin_key, watch.id)

    rows = client.get("/api/actions", headers=_h(admin_key)).json()
    assert len(rows) == 1
    row = rows[0]
    assert row["created_by"] == "admin-один"
    assert row["created_at"] is not None
    assert row["updated_by"] is None
    assert row["updated_at"] is None


def test_last_editor_differs_from_original_creator(client, admin_key, other_admin_key, watch, db):
    """(d) Создали одним админом, отредактировали другим — GET должен
    показывать ВТОРОГО как последнего редактора, при этом created_by
    остаётся первым (это и есть суть фичи)."""
    action_id = _create_action(client, admin_key, watch.id).json()["id"]

    resp = client.patch(
        f"/api/actions/{action_id}",
        json={"enabled": False},
        headers=_h(other_admin_key),
    )
    assert resp.status_code == 200

    rows = client.get("/api/actions", headers=_h(admin_key)).json()
    row = next(r for r in rows if r["id"] == action_id)
    assert row["created_by"] == "admin-один"
    assert row["updated_by"] == "admin-два"

    action = db.get(Action, action_id)
    assert action.created_by == "admin-один"
    assert action.updated_by == "admin-два"


def test_patch_without_changes_does_not_set_updated_by(client, admin_key, watch, db):
    """PATCH без реальных полей — не должен подделывать историю, будто
    кто-то что-то отредактировал."""
    action_id = _create_action(client, admin_key, watch.id).json()["id"]

    resp = client.patch(f"/api/actions/{action_id}", json={}, headers=_h(admin_key))
    assert resp.status_code == 200

    action = db.get(Action, action_id)
    assert action.updated_by is None
    assert action.updated_at is None
