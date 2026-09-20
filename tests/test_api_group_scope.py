"""Вторая ось прав: ключ, ограниченный группой, не видит чужие узлы.

Ключевой тест здесь — test_every_node_scoped_get_route_is_isolated: он
обходит ВСЕ маршруты с {node_id}/{probe_id}/{backup_id} из OpenAPI-схемы
приложения, а не заранее выписанный список. Если кто-то добавит новый
эндпоинт по узлу и забудет проверку доступа — тест упадёт сам, без
необходимости вспоминать про него.
"""

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import (
    ApiKeyRole,
    Backup,
    Group,
    Incident,
    Node,
    Probe,
    ProbeKind,
    Watch,
    WatchOperator,
    WatchSeverity,
)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def two_groups(db):
    """Две группы с узлом в каждой + полная цепочка Probe→Watch→Incident
    и бэкап, чтобы проверять доступ по любому из идентификаторов."""
    own = Group(name="своя")
    other = Group(name="чужая")
    db.add_all([own, other])
    db.commit()

    made = {}
    for tag, group in (("own", own), ("other", other)):
        node = Node(name=f"{tag}-node", address="10.0.0.1", group_id=group.id)
        db.add(node)
        db.commit()
        probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
        db.add(probe)
        db.commit()
        watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label=tag)
        db.add(watch)
        db.commit()
        db.add(Incident(watch_id=watch.id, detail=f"инцидент {tag}"))
        backup = Backup(node_id=node.id, content=f"конфиг {tag}", changed=True)
        db.add(backup)
        db.commit()
        made[tag] = {"group": group, "node": node, "probe": probe, "watch": watch, "backup": backup}
    return made


@pytest.fixture()
def scoped_key(db, two_groups):
    """admin-ключ, но ограниченный группой «своя» — роль высокая, область узкая."""
    return generate_key(db, label="scoped", role=ApiKeyRole.admin, group_id=two_groups["own"]["group"].id)


@pytest.fixture()
def global_key(db):
    return generate_key(db, label="global", role=ApiKeyRole.admin)


def _h(key):
    return {"X-API-Key": key}


def test_node_list_shows_only_own_group(client, scoped_key, two_groups):
    names = [n["name"] for n in client.get("/api/nodes", headers=_h(scoped_key)).json()]
    assert names == ["own-node"]


def test_global_key_still_sees_everything(client, global_key, two_groups):
    names = sorted(n["name"] for n in client.get("/api/nodes", headers=_h(global_key)).json())
    assert names == ["other-node", "own-node"]


def test_own_node_is_reachable(client, scoped_key, two_groups):
    own_id = two_groups["own"]["node"].id
    assert client.get(f"/api/nodes/{own_id}/probes", headers=_h(scoped_key)).status_code == 200


def test_foreign_node_reads_as_absent_not_forbidden(client, scoped_key, two_groups):
    """404, а не 403: 403 подтвердил бы, что узел существует, и по перебору
    node_id можно было бы составить карту чужих групп."""
    other_id = two_groups["other"]["node"].id
    resp = client.get(f"/api/nodes/{other_id}/probes", headers=_h(scoped_key))
    assert resp.status_code == 404


def test_incidents_of_foreign_group_are_hidden(client, scoped_key):
    details = [i["detail"] for i in client.get("/api/incidents", headers=_h(scoped_key)).json()]
    assert details == ["инцидент own"]


def test_foreign_backup_content_is_not_readable(client, scoped_key, two_groups):
    """Бэкап — это конфиг устройства, самое чувствительное в системе."""
    other_backup_id = two_groups["other"]["backup"].id
    assert client.get(f"/api/backups/{other_backup_id}", headers=_h(scoped_key)).status_code == 404


def test_cannot_run_audit_on_foreign_node(client, scoped_key, two_groups):
    other_id = two_groups["other"]["node"].id
    assert client.post(f"/api/nodes/{other_id}/audit", headers=_h(scoped_key)).status_code == 404


def test_cannot_create_node_in_foreign_group(client, scoped_key, two_groups):
    other_group_id = two_groups["other"]["group"].id
    resp = client.post(
        "/api/nodes",
        json={"name": "подкидыш", "address": "10.0.0.5", "group_id": other_group_id},
        headers=_h(scoped_key),
    )
    assert resp.status_code == 403


def test_cannot_create_node_without_group_when_scoped(client, scoped_key):
    """Узел без группы для ограниченного ключа тоже вне области — иначе
    «ничья» группа стала бы дырой в изоляции."""
    resp = client.post("/api/nodes", json={"name": "ничей", "address": "10.0.0.6"}, headers=_h(scoped_key))
    assert resp.status_code == 403


def test_cannot_attach_probe_to_foreign_node(client, scoped_key, two_groups):
    other_id = two_groups["other"]["node"].id
    resp = client.post(
        "/api/probes",
        json={"node_id": other_id, "kind": "icmp_ping", "params": {}},
        headers=_h(scoped_key),
    )
    assert resp.status_code == 404


def test_cannot_read_samples_of_foreign_probe(client, scoped_key, two_groups):
    other_probe_id = two_groups["other"]["probe"].id
    assert client.get(f"/api/probes/{other_probe_id}/samples", headers=_h(scoped_key)).status_code == 404


def test_every_node_scoped_get_route_is_isolated(client, scoped_key, two_groups):
    """Сторож: обходит все GET-маршруты, адресующие узел/проверку/бэкап,
    и требует 404 для чужих. Список берётся из OpenAPI-схемы, поэтому
    новый забытый эндпоинт попадёт сюда автоматически."""
    ids = {
        "node_id": two_groups["other"]["node"].id,
        "probe_id": two_groups["other"]["probe"].id,
        "backup_id": two_groups["other"]["backup"].id,
    }
    checked = []
    for path, operations in app.openapi()["paths"].items():
        if "get" not in operations:
            continue
        if not any(f"{{{name}}}" in path for name in ids):
            continue
        url = path
        for name, value in ids.items():
            url = url.replace(f"{{{name}}}", str(value))
        resp = client.get(url, headers=_h(scoped_key))
        checked.append((url, resp.status_code))

    assert checked, "маршруты по узлу не найдены — сторож проверял бы пустоту"
    leaked = [(url, code) for url, code in checked if code != 404]
    assert not leaked, f"эти маршруты отдают чужие данные вместо 404: {leaked}"
