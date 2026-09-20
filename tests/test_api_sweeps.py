"""API массового прогона (Рубка).

Реальные SSH-подключения подменяются: настоящих коммутаторов в тестах
нет. Проверяется то, что от них не зависит — права, изоляция по группам,
выбор команды по вендору и невозможность протащить произвольную строку.
"""

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Group, Node, Sweep, SweepResult, Vendor
from app.ssh_client import SshResult


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def fake_ssh(monkeypatch):
    """Вместо настоящего SSH — успешный ответ с эхом команды: так видно,
    какая именно строка ушла бы на устройство."""
    async def fake_run(*, host, port, username, command, timeout_seconds, key_path=None, password=None, known_hosts=None):
        return SshResult(ok=True, exit_status=0, stdout=f"[{host}] {command}", error=None)

    monkeypatch.setattr("app.sweep_engine.run_ssh_command", fake_run)


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="дежурный", role=ApiKeyRole.operator)


@pytest.fixture()
def viewer_key(db):
    return generate_key(db, label="смотритель", role=ApiKeyRole.viewer)


@pytest.fixture()
def nodes(db):
    cisco = Node(name="LAB-1", address="10.0.0.1", vendor=Vendor.cisco_ios)
    junos = Node(name="LAB-2", address="10.0.0.2", vendor=Vendor.junos)
    db.add_all([cisco, junos])
    db.commit()
    return {"cisco": cisco, "junos": junos}


def _h(key):
    return {"X-API-Key": key}


def _sweep(client, key, **overrides):
    payload = {"node_ids": [], "preset_key": "version", "username": "monitor", "password": "x"}
    payload.update(overrides)
    return client.post("/api/sweeps", json=payload, headers=_h(key))


def test_presets_are_listed_without_raw_commands(client, viewer_key):
    presets = client.get("/api/sweep-presets", headers=_h(viewer_key)).json()
    assert any(p["key"] == "mac_table" for p in presets)
    assert "show mac address-table" not in str(presets)


def test_viewer_cannot_run_sweep(client, viewer_key, nodes):
    """Команда лезет на боевое оборудование — viewer'у нельзя."""
    resp = _sweep(client, viewer_key, node_ids=[nodes["cisco"].id])
    assert resp.status_code == 403


def test_operator_can_run_sweep(client, operator_key, nodes):
    resp = _sweep(client, operator_key, node_ids=[nodes["cisco"].id])
    assert resp.status_code == 201
    assert resp.json()["nodes"] == 1


def test_command_is_chosen_per_vendor(client, operator_key, nodes, db):
    """Одна кнопка — разные команды: у Cisco и Juniper MAC-таблица
    называется по-разному."""
    resp = _sweep(client, operator_key, node_ids=[nodes["cisco"].id, nodes["junos"].id], preset_key="mac_table")
    sweep_id = resp.json()["id"]

    commands = {r.node.name: r.command for r in db.query(SweepResult).filter_by(sweep_id=sweep_id).all()}
    assert commands["LAB-1"] == "show mac address-table"
    assert commands["LAB-2"] == "show ethernet-switching table"


def test_custom_command_must_pass_whitelist(client, operator_key, nodes):
    resp = _sweep(client, operator_key, node_ids=[nodes["cisco"].id], preset_key=None, command="reload")
    assert resp.status_code == 422
    assert "начинаться" in resp.json()["detail"]


def test_appended_command_rejected_at_api_level(client, operator_key, nodes, db):
    """Ключевая проверка: белый список должен срабатывать и здесь, а не
    только в модуле — иначе массовый запуск стал бы обходным путём."""
    resp = _sweep(client, operator_key, node_ids=[nodes["cisco"].id], preset_key=None, command="show version; reload")
    assert resp.status_code == 422
    assert db.query(Sweep).count() == 0  # прогон вообще не заводится


def test_either_preset_or_command_but_not_both(client, operator_key, nodes):
    both = _sweep(client, operator_key, node_ids=[nodes["cisco"].id], command="show version")
    assert both.status_code == 422

    neither = _sweep(client, operator_key, node_ids=[nodes["cisco"].id], preset_key=None)
    assert neither.status_code == 422


def test_empty_node_list_rejected(client, operator_key):
    assert _sweep(client, operator_key, node_ids=[]).status_code == 422


def test_unknown_preset_rejected(client, operator_key, nodes):
    resp = _sweep(client, operator_key, node_ids=[nodes["cisco"].id], preset_key="wipe_everything")
    assert resp.status_code == 422


def test_foreign_node_cannot_be_swept(client, db, nodes):
    """Массовый запуск не должен обходить ограничение по группам: каждый
    узел проверяется отдельно."""
    own = Group(name="своя")
    other = Group(name="чужая")
    db.add_all([own, other])
    db.commit()
    foreign = Node(name="чужой", address="10.0.0.9", group_id=other.id)
    db.add(foreign)
    db.commit()
    scoped = generate_key(db, label="ограниченный", role=ApiKeyRole.operator, group_id=own.id)

    resp = _sweep(client, scoped, node_ids=[foreign.id])
    assert resp.status_code == 404


def test_results_are_visible_after_run(client, operator_key, nodes):
    sweep_id = _sweep(client, operator_key, node_ids=[nodes["cisco"].id]).json()["id"]
    data = client.get(f"/api/sweeps/{sweep_id}", headers=_h(operator_key)).json()
    assert data["label"] == "Версия"
    assert data["results"][0]["node_name"] == "LAB-1"
    assert data["results"][0]["command"] == "show version"


def test_sweep_records_who_started_it(client, operator_key, nodes):
    """В боевой сети важно, чей это был прогон."""
    sweep_id = _sweep(client, operator_key, node_ids=[nodes["cisco"].id]).json()["id"]
    assert client.get(f"/api/sweeps/{sweep_id}", headers=_h(operator_key)).json()["started_by"] == "дежурный"


def test_sweep_list_shows_progress_fields(client, operator_key, nodes):
    _sweep(client, operator_key, node_ids=[nodes["cisco"].id, nodes["junos"].id])
    row = client.get("/api/sweeps", headers=_h(operator_key)).json()[0]
    assert row["total"] == 2
    assert {"done", "failed", "pending"} <= set(row)
