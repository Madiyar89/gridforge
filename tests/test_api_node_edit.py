import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Group, Node, Probe, ProbeKind, Watch, WatchOperator


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="admin", role=ApiKeyRole.admin)


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="operator", role=ApiKeyRole.operator)


@pytest.fixture()
def node(db):
    n = Node(name="узел", address="10.0.0.1")
    db.add(n)
    db.commit()
    return n


def _h(key):
    return {"X-API-Key": key}


def test_rename_node(client, admin_key, node, db):
    resp = client.patch(f"/api/nodes/{node.id}", json={"name": "переименованный"}, headers=_h(admin_key))
    assert resp.status_code == 200
    db.refresh(node)
    assert node.name == "переименованный"
    assert node.address == "10.0.0.1"  # не тронуто


def test_patch_only_changes_sent_fields(client, admin_key, node, db):
    """Частичное обновление: неприсланные поля не должны сбрасываться в
    значения по умолчанию."""
    node.tags = "важный"
    db.commit()

    client.patch(f"/api/nodes/{node.id}", json={"address": "10.0.0.9"}, headers=_h(admin_key))
    db.refresh(node)
    assert node.address == "10.0.0.9"
    assert node.tags == "важный"


def test_explicit_null_clears_field(client, admin_key, db):
    """null — осмысленное значение (убрать из группы), его надо отличать
    от «поле не прислали»."""
    group = Group(name="группа")
    db.add(group)
    db.commit()
    node = Node(name="в-группе", address="10.0.0.2", group_id=group.id)
    db.add(node)
    db.commit()

    client.patch(f"/api/nodes/{node.id}", json={"group_id": None}, headers=_h(admin_key))
    db.refresh(node)
    assert node.group_id is None


def test_deactivate_node(client, admin_key, node, db):
    client.patch(f"/api/nodes/{node.id}", json={"active": False}, headers=_h(admin_key))
    db.refresh(node)
    assert node.active is False


def test_patch_unknown_group_rejected(client, admin_key, node):
    resp = client.patch(f"/api/nodes/{node.id}", json={"group_id": 999999}, headers=_h(admin_key))
    assert resp.status_code == 404


def test_scoped_key_cannot_move_node_out_of_its_group(client, db):
    """Перенос узла в невидимую ключу группу увёл бы узел из-под
    собственного доступа — вернуть его было бы уже нечем."""
    own = Group(name="своя")
    other = Group(name="чужая")
    db.add_all([own, other])
    db.commit()
    node = Node(name="узел", address="10.0.0.3", group_id=own.id)
    db.add(node)
    db.commit()
    scoped = generate_key(db, label="scoped", role=ApiKeyRole.admin, group_id=own.id)

    resp = client.patch(f"/api/nodes/{node.id}", json={"group_id": other.id}, headers=_h(scoped))
    assert resp.status_code == 403


def test_operator_cannot_delete_node(client, operator_key, node):
    assert client.delete(f"/api/nodes/{node.id}", headers=_h(operator_key)).status_code == 403


def test_operator_cannot_patch_node(client, operator_key, node):
    resp = client.patch(f"/api/nodes/{node.id}", json={"name": "x"}, headers=_h(operator_key))
    assert resp.status_code == 403


def test_delete_node_via_api_returns_summary(client, admin_key, node):
    resp = client.delete(f"/api/nodes/{node.id}", headers=_h(admin_key))
    assert resp.status_code == 200
    assert resp.json()["probes"] == 0


def test_delete_foreign_node_reads_as_absent(client, db):
    own = Group(name="своя")
    other = Group(name="чужая")
    db.add_all([own, other])
    db.commit()
    foreign = Node(name="чужой", address="10.0.0.4", group_id=other.id)
    db.add(foreign)
    db.commit()
    scoped = generate_key(db, label="scoped", role=ApiKeyRole.admin, group_id=own.id)

    assert client.delete(f"/api/nodes/{foreign.id}", headers=_h(scoped)).status_code == 404


def test_delete_probe_and_watch(client, admin_key, node, db):
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, label="x")
    db.add(watch)
    db.commit()

    assert client.delete(f"/api/watches/{watch.id}", headers=_h(admin_key)).status_code == 204
    assert client.delete(f"/api/probes/{probe.id}", headers=_h(admin_key)).status_code == 204
    assert db.query(Probe).count() == 0


def test_admin_can_reset_ssh_host_key(client, admin_key, node, db):
    """Легитимная замена устройства: сбросить сохранённый TOFU-fingerprint
    (см. app/ssh_client.py), чтобы новый host key был принят и снова
    запомнен при следующем подключении."""
    node.ssh_key_fingerprint = "SHA256:aaaa"
    db.commit()

    resp = client.delete(f"/api/nodes/{node.id}/ssh-key", headers=_h(admin_key))
    assert resp.status_code == 204
    db.refresh(node)
    assert node.ssh_key_fingerprint is None


def test_operator_cannot_reset_ssh_host_key(client, operator_key, node, db):
    node.ssh_key_fingerprint = "SHA256:aaaa"
    db.commit()

    resp = client.delete(f"/api/nodes/{node.id}/ssh-key", headers=_h(operator_key))
    assert resp.status_code == 403
    db.refresh(node)
    assert node.ssh_key_fingerprint == "SHA256:aaaa"
