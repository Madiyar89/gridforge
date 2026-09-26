"""Проверка SMB-учётки на узлах группы (docs/landscape-report.md,
доразбор security-инструментов, третий после Nuclei/Feroxbuster) —
сознательно узкий срез: только успех/отказ логина, без выполнения
команд. Реальный SMB-логин уже проверен вживую (2026-09-25, реальный
Samba-сервер, три сценария: верный пароль/неверный пароль/недоступный
порт — все три отработали верно). Здесь — мок на границе
_check_smb_login_sync, тот же приём, что и для подпроцессов nmap/
nuclei/feroxbuster в других тестах: не бить по сети, но и не
дублировать то, что уже подтверждено живым запуском."""

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, CredentialCheckRun, Group, Node, Scan, ScanHost, Vlan

import app.credential_check_engine as cce


@pytest.fixture()
def client():
    with TestClient(app) as c:
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
    node = Node(name="ws1", address="10.0.0.5", group_id=group.id)
    db.add(node)
    db.commit()
    return group


def _h(key):
    return {"X-API-Key": key}


# --- app/credential_check_engine.py напрямую ---


def test_run_credential_check_success(monkeypatch, db, group_with_node):
    from app.db import SessionLocal

    def fake_login_ok(address, username, password, domain):
        return None  # успех — ничего не бросает

    monkeypatch.setattr(cce, "_check_smb_login_sync", fake_login_ok)

    run = CredentialCheckRun(group_id=group_with_node.id, username="admin", triggered_by="тест")
    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.run(cce.run_credential_check(run.id, ["10.0.0.5"], "admin", "pass123", None, SessionLocal))

    db.refresh(run)
    assert run.status.value == "done"
    assert len(run.targets) == 1
    assert run.targets[0].ok is True
    assert run.targets[0].error is None


def test_run_credential_check_bad_password(monkeypatch, db, group_with_node):
    from app.db import SessionLocal

    def fake_login_fail(address, username, password, domain):
        raise Exception(
            "SMB SessionError: code: 0xc000006d - STATUS_LOGON_FAILURE - "
            "The attempted logon is invalid."
        )

    monkeypatch.setattr(cce, "_check_smb_login_sync", fake_login_fail)

    run = CredentialCheckRun(group_id=group_with_node.id, username="admin", triggered_by="тест")
    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.run(cce.run_credential_check(run.id, ["10.0.0.5"], "admin", "wrong", None, SessionLocal))

    db.refresh(run)
    assert run.status.value == "done"  # прогон завершился штатно - "не подошло" не ошибка прогона
    assert run.targets[0].ok is False
    assert "STATUS_LOGON_FAILURE" in run.targets[0].error


def test_run_credential_check_never_persists_password(monkeypatch, db, group_with_node):
    """Пароль не должен осесть НИГДЕ в БД - ни в CredentialCheckRun, ни в
    CredentialCheckTarget."""
    from app.db import SessionLocal

    monkeypatch.setattr(cce, "_check_smb_login_sync", lambda *a, **k: None)

    run = CredentialCheckRun(group_id=group_with_node.id, username="admin", triggered_by="тест")
    db.add(run)
    db.commit()
    db.refresh(run)

    asyncio.run(cce.run_credential_check(run.id, ["10.0.0.5"], "admin", "SuperSecret123!", None, SessionLocal))

    db.refresh(run)
    row_dump = str(run.__dict__) + str([t.__dict__ for t in run.targets])
    assert "SuperSecret123!" not in row_dump


# --- API ---


def _wait_run_done(client, key, group_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        runs = client.get(f"/api/groups/{group_id}/credential-checks", headers=_h(key)).json()
        if runs and runs[0]["status"] != "running":
            return runs[0]
        time.sleep(0.05)
    raise AssertionError("проверка не завершилась за отведённое время")


def test_create_credential_check_requires_consent(client, operator_key, group_with_node):
    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": False},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_create_credential_check_rejects_empty_group(client, operator_key, db):
    group = Group(name="Пустая группа")
    db.add(group)
    db.commit()
    db.refresh(group)
    resp = client.post(
        f"/api/groups/{group.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": True},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_create_and_complete_credential_check_via_api(monkeypatch, client, operator_key, group_with_node):
    monkeypatch.setattr(cce, "_check_smb_login_sync", lambda *a, **k: None)

    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "domain": "CORP", "consent_confirmed": True},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    assert resp.json()["targets"] == 1

    run = _wait_run_done(client, operator_key, group_with_node.id)
    assert run["status"] == "done"
    assert run["username"] == "admin"
    assert run["domain"] == "CORP"
    assert run["triggered_by"] == "дежурный"
    assert run["success_count"] == 1
    assert run["target_count"] == 1
    assert "password" not in run and "x" not in str(run.values())

    targets = client.get(f"/api/credential-checks/{run['id']}/targets", headers=_h(operator_key)).json()
    assert targets == [{"address": "10.0.0.5", "ok": True, "error": None}]


def test_viewer_cannot_run_credential_check(client, db, group_with_node):
    viewer_key = generate_key(db, label="смотритель", role=ApiKeyRole.viewer)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": True},
        headers=_h(viewer_key),
    )
    assert resp.status_code == 403


# --- проверка по VLAN (цели = живые хосты последнего скана подсети) ---


def test_create_credential_check_rejects_vlan_without_scan(client, operator_key, db, group_with_node):
    vlan = Vlan(name="Пользователи", cidr="10.0.1.0/24", group_id=group_with_node.id)
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": True, "vlan_id": vlan.id},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_create_credential_check_rejects_vlan_from_other_group(client, operator_key, db, group_with_node):
    other_group = Group(name="Другая группа")
    db.add(other_group)
    db.commit()
    db.refresh(other_group)
    vlan = Vlan(name="Чужой VLAN", cidr="10.0.2.0/24", group_id=other_group.id)
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": True, "vlan_id": vlan.id},
        headers=_h(operator_key),
    )
    assert resp.status_code == 404


def test_create_and_complete_credential_check_by_vlan(monkeypatch, client, operator_key, db, group_with_node):
    """VLAN выбран — цели должны браться из последнего скана VLAN (живые
    пользовательские хосты подсети), а не из узла-коммутатора группы."""
    monkeypatch.setattr(cce, "_check_smb_login_sync", lambda *a, **k: None)

    vlan = Vlan(name="Пользователи", cidr="10.0.1.0/24", group_id=group_with_node.id)
    db.add(vlan)
    db.commit()
    db.refresh(vlan)
    scan = Scan(cidr=vlan.cidr, vlan_id=vlan.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.add(ScanHost(scan_id=scan.id, address="10.0.1.42", hostname="pc-42"))
    db.commit()

    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": True, "vlan_id": vlan.id},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    assert resp.json()["targets"] == 1

    run = _wait_run_done(client, operator_key, group_with_node.id)
    assert run["success_count"] == 1
    assert run["vlan_id"] == vlan.id
    assert run["vlan_name"] == "Пользователи"

    targets = client.get(f"/api/credential-checks/{run['id']}/targets", headers=_h(operator_key)).json()
    assert targets == [{"address": "10.0.1.42", "ok": True, "error": None}]


def test_group_scoped_key_cannot_run_in_other_group(client, db, group_with_node):
    other_group = Group(name="Другая группа")
    db.add(other_group)
    db.commit()
    db.refresh(other_group)
    scoped_key = generate_key(db, label="ограниченный", role=ApiKeyRole.operator, group_id=other_group.id)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/credential-checks",
        json={"username": "admin", "password": "x", "consent_confirmed": True},
        headers=_h(scoped_key),
    )
    assert resp.status_code == 403
