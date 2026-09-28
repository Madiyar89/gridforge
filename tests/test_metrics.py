"""/metrics — экспорт в формате Prometheus (docs/landscape-report.md,
п.4.3). Использует ту же RBAC-область видимости, что и /api/dashboard
(build_dashboard) — см. tests/test_dashboard.py."""

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Group, Incident, Node, Probe, ProbeKind, Watch, WatchOperator, WatchSeverity


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="admin", role=ApiKeyRole.admin)


def _h(key):
    return {"X-API-Key": key}


def test_metrics_requires_key(client):
    resp = client.get("/metrics")
    assert resp.status_code == 401


def test_metrics_empty_installation(client, admin_key):
    resp = client.get("/metrics", headers=_h(admin_key))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "gridforge_nodes_total 0" in body
    assert "gridforge_incidents_open 0" in body
    assert "# HELP gridforge_nodes_total" in body
    assert "# TYPE gridforge_nodes_total gauge" in body


def test_metrics_reflects_real_state(client, admin_key, db):
    group = Group(name="Тест-Группа")
    db.add(group)
    db.commit()
    db.refresh(group)
    node = Node(name="sw1", address="10.0.0.5", group_id=group.id)
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping, enabled=True)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="упал")
    db.add(watch)
    db.commit()
    db.add(Incident(watch_id=watch.id, detail="не отвечает"))
    db.commit()

    body = client.get("/metrics", headers=_h(admin_key)).text
    assert "gridforge_nodes_total 1" in body
    assert "gridforge_probes_enabled 1" in body
    assert "gridforge_incidents_open 1" in body
    assert "gridforge_incidents_open_critical 1" in body


def test_metrics_scoped_key_sees_only_own_group(client, db):
    group_a = Group(name="Группа А")
    group_b = Group(name="Группа Б")
    db.add_all([group_a, group_b])
    db.commit()
    db.refresh(group_a)
    db.refresh(group_b)
    db.add(Node(name="a1", address="10.0.0.1", group_id=group_a.id))
    db.add(Node(name="b1", address="10.0.0.2", group_id=group_b.id))
    db.commit()

    scoped_key = generate_key(db, label="ограниченный", role=ApiKeyRole.viewer, group_id=group_a.id)
    body = client.get("/metrics", headers=_h(scoped_key)).text
    assert "gridforge_nodes_total 1" in body  # видит только свою группу, не обе
