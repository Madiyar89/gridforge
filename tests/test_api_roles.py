"""Разделение прав по функциям: viewer < operator < admin (см. auth.ROLE_RANK).

Проверяется именно граница между ролями, а не каждый эндпоинт: что
operator может запускать операции на оборудовании, но не может менять
конфигурацию GridForge и выдавать ключи.
"""

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
def viewer_key(db):
    return generate_key(db, label="test-viewer", role=ApiKeyRole.viewer)


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="test-operator", role=ApiKeyRole.operator)


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


@pytest.fixture()
def node(db):
    n = Node(name="role-test-node", address="10.0.0.77")
    db.add(n)
    db.commit()
    return n


def _h(key):
    return {"X-API-Key": key}


def test_whoami_reports_each_role_honestly(client, viewer_key, operator_key, admin_key):
    assert client.get("/api/whoami", headers=_h(viewer_key)).json()["role"] == "viewer"
    assert client.get("/api/whoami", headers=_h(operator_key)).json()["role"] == "operator"
    assert client.get("/api/whoami", headers=_h(admin_key)).json()["role"] == "admin"


def test_operator_can_read(client, operator_key):
    assert client.get("/api/nodes", headers=_h(operator_key)).status_code == 200


def test_operator_can_run_audit_on_node(client, operator_key, node):
    # Аудит без бэкапа возвращает честную находку "нет бэкапа", а не ошибку
    # доступа — нам здесь важно именно что это НЕ 403.
    resp = client.post(f"/api/nodes/{node.id}/audit", headers=_h(operator_key))
    assert resp.status_code != 403


def test_viewer_cannot_run_audit_on_node(client, viewer_key, node):
    resp = client.post(f"/api/nodes/{node.id}/audit", headers=_h(viewer_key))
    assert resp.status_code == 403


def test_viewer_cannot_start_scan(client, viewer_key):
    resp = client.post("/api/scans", json={"cidr": "10.0.0.0/30"}, headers=_h(viewer_key))
    assert resp.status_code == 403


def test_operator_cannot_change_inventory(client, operator_key):
    resp = client.post("/api/nodes", json={"name": "x", "address": "10.0.0.1"}, headers=_h(operator_key))
    assert resp.status_code == 403


def test_operator_cannot_create_channel(client, operator_key):
    resp = client.post(
        "/api/channels",
        json={"kind": "webhook", "config": {"url": "http://x"}},
        headers=_h(operator_key),
    )
    assert resp.status_code == 403


def test_operator_cannot_issue_api_keys(client, operator_key):
    """Самое важное разграничение: иначе operator выписал бы себе admin-ключ
    и разделение ролей не значило бы ничего."""
    resp = client.post("/api/api-keys", json={"label": "self-promo", "role": "admin"}, headers=_h(operator_key))
    assert resp.status_code == 403


def test_operator_cannot_list_api_keys(client, operator_key):
    assert client.get("/api/api-keys", headers=_h(operator_key)).status_code == 403


def test_admin_still_can_do_everything(client, admin_key, node):
    assert client.post("/api/nodes", json={"name": "y", "address": "10.0.0.2"}, headers=_h(admin_key)).status_code == 201
    assert client.post(f"/api/nodes/{node.id}/audit", headers=_h(admin_key)).status_code != 403
    assert client.get("/api/api-keys", headers=_h(admin_key)).status_code == 200
