import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Node


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


def _headers(key):
    return {"X-API-Key": key}


def test_create_global_channel_has_null_scope(client, admin_key):
    resp = client.post(
        "/api/channels",
        json={"kind": "webhook", "config": {"url": "http://x"}, "min_severity": "info"},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 201
    listed = client.get("/api/channels", headers=_headers(admin_key)).json()
    channel = next(c for c in listed if c["id"] == resp.json()["id"])
    assert channel["node_id"] is None
    assert channel["watch_id"] is None


def test_create_node_scoped_channel_returns_that_node_id(client, admin_key, db):
    node = Node(name="scoped-node", address="10.0.0.5")
    db.add(node)
    db.commit()

    resp = client.post(
        "/api/channels",
        json={"kind": "webhook", "config": {"url": "http://x"}, "node_id": node.id},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 201
    listed = client.get("/api/channels", headers=_headers(admin_key)).json()
    channel = next(c for c in listed if c["id"] == resp.json()["id"])
    assert channel["node_id"] == node.id


def test_create_channel_with_unknown_node_id_rejected(client, admin_key):
    resp = client.post(
        "/api/channels",
        json={"kind": "webhook", "config": {"url": "http://x"}, "node_id": 999999},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 404


def test_create_channel_with_unknown_watch_id_rejected(client, admin_key):
    resp = client.post(
        "/api/channels",
        json={"kind": "webhook", "config": {"url": "http://x"}, "watch_id": 999999},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 404
