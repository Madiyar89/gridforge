"""VLAN/подсеть как отдельная сущность в Инвентаре (docs/landscape-
report.md, запрос пользователя 2026-09-25 — "не только узлы
коммутаторов проверять"): app/vlan_engine.py + app/main.py (/api/vlans*).
Проверка на VLAN = доступность шлюза (icmp_ping, тот же исполнитель, что
у Probe) + скан подсети (переиспользует nmap-скан из scan_engine).
Реальный nmap/ping не запускаются — общий фейковый subprocess,
различающий команду по args[0] (тот же приём, что в
test_discovery_scan.py/test_vuln_scan.py для nmap, плюс ветка для ping,
которую использует check_vlan_gateway)."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Group, Vlan

SCAN_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
  <status state="up"/>
  <address addr="198.51.100.5" addrtype="ipv4"/>
  <hostnames><hostname name="ws1"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
  </ports>
</host>
<host>
  <status state="up"/>
  <address addr="198.51.100.6" addrtype="ipv4"/>
  <hostnames></hostnames>
  <ports></ports>
</host>
</nmaprun>
"""


class _FakeProc:
    def __init__(self, stdout: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, b""

    async def wait(self):
        return self.returncode

    def kill(self):
        pass


@pytest.fixture(autouse=True)
def fake_subprocess(monkeypatch):
    async def fake_exec(*args, **kwargs):
        if args[0] == "nmap":
            return _FakeProc(stdout=SCAN_XML.encode())
        if args[0] == "ping":
            # Адрес — последний позиционный аргумент ping.
            address = args[-1]
            ok = address == "198.51.100.1"  # "живой" шлюз в тестах — именно этот адрес
            return _FakeProc(returncode=0 if ok else 1)
        raise AssertionError(f"неожиданная команда в тесте: {args}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="дежурный", role=ApiKeyRole.operator)


def _h(key):
    return {"X-API-Key": key}


# --- CRUD ---


def test_create_vlan_rejects_bad_cidr(client, operator_key):
    resp = client.post(
        "/api/vlans",
        json={"name": "Тест", "cidr": "не-подсеть"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_create_vlan_rejects_bad_gateway(client, operator_key):
    resp = client.post(
        "/api/vlans",
        json={"name": "Тест", "cidr": "198.51.100.0/24", "gateway": "не-ip"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_create_and_list_vlan(client, operator_key):
    resp = client.post(
        "/api/vlans",
        json={"name": "Серверная", "vlan_id": 100, "cidr": "198.51.100.0/24", "gateway": "198.51.100.1"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    vlan_id = resp.json()["id"]

    vlans = client.get("/api/vlans", headers=_h(operator_key)).json()
    assert len(vlans) == 1
    row = vlans[0]
    assert row["id"] == vlan_id
    assert row["vlan_id"] == 100
    assert row["cidr"] == "198.51.100.0/24"
    assert row["gateway_ok"] is None  # ещё не проверялся
    assert row["host_count"] is None  # ещё не сканировался
    assert row["usable_addresses"] == 254


def test_delete_vlan(client, db):
    # Удаление — admin-only, тот же уровень, что у DELETE /api/nodes/{id}.
    admin_key = generate_key(db, label="админ", role=ApiKeyRole.admin)
    vlan = Vlan(name="Удаляемый", cidr="10.200.0.0/30")
    db.add(vlan)
    db.commit()
    db.refresh(vlan)

    resp = client.delete(f"/api/vlans/{vlan.id}", headers=_h(admin_key))
    assert resp.status_code == 204
    assert db.query(Vlan).filter(Vlan.id == vlan.id).count() == 0


# --- проверка (шлюз + скан) ---


def test_check_vlan_gateway_ok_and_hosts_found(client, operator_key, db):
    vlan = Vlan(name="Серверная", cidr="198.51.100.0/24", gateway="198.51.100.1")
    db.add(vlan)
    db.commit()
    db.refresh(vlan)

    resp = client.post(f"/api/vlans/{vlan.id}/check", headers=_h(operator_key))
    assert resp.status_code == 201
    body = resp.json()
    assert body["gateway_ok"] is True
    assert body["gateway_checked_at"] is not None
    assert body["host_count"] == 2  # из SCAN_XML
    assert body["utilization_pct"] == round(100 * 2 / 254, 1)
    assert body["last_scan_id"] is not None

    hosts = client.get(f"/api/vlans/{vlan.id}/scan-hosts", headers=_h(operator_key)).json()
    assert {h["address"] for h in hosts} == {"198.51.100.5", "198.51.100.6"}


def test_check_vlan_gateway_down(client, operator_key, db):
    vlan = Vlan(name="Серверная", cidr="198.51.100.0/24", gateway="198.51.100.254")  # "мёртвый" в фейке
    db.add(vlan)
    db.commit()
    db.refresh(vlan)

    resp = client.post(f"/api/vlans/{vlan.id}/check", headers=_h(operator_key))
    assert resp.status_code == 201
    body = resp.json()
    assert body["gateway_ok"] is False


def test_check_vlan_without_gateway_skips_ping(client, operator_key, db):
    vlan = Vlan(name="Без шлюза", cidr="198.51.100.0/24")
    db.add(vlan)
    db.commit()
    db.refresh(vlan)

    resp = client.post(f"/api/vlans/{vlan.id}/check", headers=_h(operator_key))
    assert resp.status_code == 201
    body = resp.json()
    assert body["gateway_ok"] is None
    assert body["host_count"] == 2  # скан подсети всё равно выполняется


# --- права ---


def test_viewer_cannot_create_vlan(client, db):
    viewer_key = generate_key(db, label="смотритель", role=ApiKeyRole.viewer)
    resp = client.post(
        "/api/vlans",
        json={"name": "Тест", "cidr": "198.51.100.0/24"},
        headers=_h(viewer_key),
    )
    assert resp.status_code == 403


def test_group_scoped_key_cannot_create_vlan_in_other_group(client, db):
    own_group = Group(name="Своя группа")
    other_group = Group(name="Чужая группа")
    db.add_all([own_group, other_group])
    db.commit()
    db.refresh(own_group)
    db.refresh(other_group)
    scoped_key = generate_key(db, label="ограниченный", role=ApiKeyRole.operator, group_id=own_group.id)

    resp = client.post(
        "/api/vlans",
        json={"name": "Тест", "cidr": "198.51.100.0/24", "group_id": other_group.id},
        headers=_h(scoped_key),
    )
    assert resp.status_code == 403


def test_group_scoped_key_only_sees_own_vlans(client, db):
    own_group = Group(name="Своя группа 2")
    other_group = Group(name="Чужая группа 2")
    db.add_all([own_group, other_group])
    db.commit()
    db.refresh(own_group)
    db.refresh(other_group)
    db.add_all(
        [
            Vlan(name="Своя сеть", cidr="198.51.100.0/24", group_id=own_group.id),
            Vlan(name="Чужая сеть", cidr="10.200.0.0/24", group_id=other_group.id),
        ]
    )
    db.commit()
    scoped_key = generate_key(db, label="ограниченный-2", role=ApiKeyRole.operator, group_id=own_group.id)

    vlans = client.get("/api/vlans", headers=_h(scoped_key)).json()
    assert [v["name"] for v in vlans] == ["Своя сеть"]
