import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


@pytest.fixture()
def viewer_key(db):
    return generate_key(db, label="test-viewer", role=ApiKeyRole.viewer)


def test_no_key_header_rejected_with_401(client):
    resp = client.get("/api/groups")
    assert resp.status_code == 401


def test_garbage_key_rejected_with_401(client):
    resp = client.get("/api/groups", headers={"X-API-Key": "not-a-real-key"})
    assert resp.status_code == 401


def test_viewer_key_can_read(client, viewer_key):
    resp = client.get("/api/groups", headers={"X-API-Key": viewer_key})
    assert resp.status_code == 200


def test_admin_key_can_read(client, admin_key):
    resp = client.get("/api/groups", headers={"X-API-Key": admin_key})
    assert resp.status_code == 200


def test_viewer_key_cannot_write_gets_403_not_401(client, viewer_key):
    # ключ валиден (не 401), просто прав не хватает (403) — разные вещи,
    # см. комментарий в require_admin_key.
    resp = client.post("/api/groups", json={"name": "test-group"}, headers={"X-API-Key": viewer_key})
    assert resp.status_code == 403


def test_admin_key_can_write(client, admin_key):
    resp = client.post("/api/groups", json={"name": "test-group"}, headers={"X-API-Key": admin_key})
    assert resp.status_code == 201


def test_revoked_key_rejected(client, db, admin_key):
    from app.models import ApiKey

    key_row = db.query(ApiKey).filter_by(label="test-admin").one()
    key_row.revoked = True
    db.commit()

    resp = client.get("/api/groups", headers={"X-API-Key": admin_key})
    assert resp.status_code == 401


def test_admin_only_list_api_keys_rejects_viewer(client, viewer_key):
    resp = client.get("/api/api-keys", headers={"X-API-Key": viewer_key})
    assert resp.status_code == 403
