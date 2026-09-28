import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Channel, ChannelKind


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


def _headers(key):
    return {"X-API-Key": key}


@pytest.fixture()
def channel(db):
    c = Channel(kind=ChannelKind.webhook, config={"url": "http://x"})
    db.add(c)
    db.commit()
    return c


def test_create_and_list_escalation_step(client, admin_key, channel):
    resp = client.post(
        "/api/escalation-steps",
        json={"delay_minutes": 15, "channel_id": channel.id},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 201
    listed = client.get("/api/escalation-steps", headers=_headers(admin_key)).json()
    assert len(listed) == 1
    assert listed[0]["delay_minutes"] == 15
    assert listed[0]["channel_id"] == channel.id


def test_create_with_unknown_channel_rejected(client, admin_key):
    resp = client.post(
        "/api/escalation-steps",
        json={"delay_minutes": 15, "channel_id": 999999},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 404


def test_create_with_zero_or_negative_delay_rejected(client, admin_key, channel):
    resp = client.post(
        "/api/escalation-steps",
        json={"delay_minutes": 0, "channel_id": channel.id},
        headers=_headers(admin_key),
    )
    assert resp.status_code == 422


def test_delete_escalation_step(client, admin_key, channel):
    step_id = client.post(
        "/api/escalation-steps",
        json={"delay_minutes": 10, "channel_id": channel.id},
        headers=_headers(admin_key),
    ).json()["id"]

    resp = client.delete(f"/api/escalation-steps/{step_id}", headers=_headers(admin_key))
    assert resp.status_code == 204
    assert client.get("/api/escalation-steps", headers=_headers(admin_key)).json() == []


def test_delete_unknown_step_404(client, admin_key):
    resp = client.delete("/api/escalation-steps/999999", headers=_headers(admin_key))
    assert resp.status_code == 404
