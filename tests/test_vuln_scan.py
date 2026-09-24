"""Проверка на уязвимости — перенос функции NetOpsHub (nmap-профили +
накопительный .xlsx-отчёт под гос-бланк). parse_nmap_xml проверяется
напрямую на синтетике (severity/CVE), API — через мок nmap-подпроцесса,
чтобы тесты не зависели от реально установленного nmap и не били по
сети."""

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Group, Node
from app.vuln_scan_engine import parse_nmap_xml

VULN_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <hostnames><hostname name="sw1"/></hostnames>
  <ports>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https"/>
      <script id="http-slowloris" output="VULNERABLE:&#10;State: VULNERABLE&#10;  DoS via Slowloris. Refs: CVE-2023-1234"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http"/>
      <script id="http-something" output="VULNERABLE:&#10;State: LIKELY VULNERABLE&#10;  maybe affected"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh"/>
      <script id="sshv1" output="State: UNKNOWN&#10;  could not determine"/>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="open"/>
      <service name="http-proxy"/>
      <script id="broken-script" output="ERROR: script failed to run"/>
    </port>
  </ports>
</host>
<host>
  <status state="down"/>
  <address addr="10.0.0.6" addrtype="ipv4"/>
</host>
</nmaprun>
"""


def test_parse_nmap_xml_severity_and_cves():
    hosts = parse_nmap_xml(VULN_XML)
    assert len(hosts) == 2

    up_host = hosts[0]
    assert up_host["address"] == "10.0.0.5"
    assert up_host["hostname"] == "sw1"
    assert up_host["state"] == "up"

    by_id = {f["script_id"]: f for f in up_host["findings"]}
    assert by_id["http-slowloris"]["severity"] == "vulnerable"
    assert by_id["http-slowloris"]["cves"] == ["CVE-2023-1234"]
    assert by_id["http-something"]["severity"] == "likely"
    assert by_id["sshv1"]["severity"] == "unknown"
    # ERROR-скрипт без реального State — не находка, должен быть отфильтрован
    assert "broken-script" not in by_id

    down_host = hosts[1]
    assert down_host["state"] == "down"
    assert down_host["findings"] == []


def test_state_line_disambiguates_vulnerable_vs_likely():
    """Регрессия из исходного докстринга: заголовок "VULNERABLE:" сам по
    себе не говорит о серьёзности — решает только строка "State: ..."."""
    xml = VULN_XML  # уже содержит оба случая с одинаковым заголовком
    hosts = parse_nmap_xml(xml)
    by_id = {f["script_id"]: f for f in hosts[0]["findings"]}
    assert by_id["http-slowloris"]["severity"] == "vulnerable"
    assert by_id["http-something"]["severity"] == "likely"


# --- API: мок nmap-подпроцесса, реальная БД/маршрутизация ---


class _FakeProc:
    def __init__(self, stdout: bytes):
        self._stdout = stdout
        self.returncode = 0

    async def communicate(self):
        return self._stdout, b""

    def kill(self):
        pass


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def fake_nmap(monkeypatch):
    """Подменяет реальный запуск nmap на канн-XML — тесты не зависят от
    установленного бинаря и не трогают сеть, как fake_device в
    test_api_sweeps.py подменяет SSH."""

    async def fake_exec(*args, **kwargs):
        return _FakeProc(VULN_XML.encode())

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)


@pytest.fixture()
def operator_key(db):
    return generate_key(db, label="дежурный", role=ApiKeyRole.operator)


@pytest.fixture()
def group_with_node(db):
    group = Group(name="Тест-Группа")
    db.add(group)
    db.commit()
    db.refresh(group)
    node = Node(name="sw1", address="10.0.0.5", group_id=group.id)
    db.add(node)
    db.commit()
    return group


def _h(key):
    return {"X-API-Key": key}


def _wait_done(client, key, group_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        scans = client.get(f"/api/groups/{group_id}/vuln-scans", headers=_h(key)).json()
        if scans and scans[0]["status"] != "running":
            return scans[0]
        time.sleep(0.05)
    raise AssertionError("скан не завершился за отведённое время")


def test_run_vuln_scan_ingests_findings_into_register(client, operator_key, group_with_node):
    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-scans",
        json={"profile": "vuln", "responsible": "Иванов И.И., инженер ИБ"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    assert resp.json()["targets"] == 1

    scan = _wait_done(client, operator_key, group_with_node.id)
    assert scan["status"] == "done"
    assert scan["findings_count"] == 3  # vulnerable + likely + unknown — всё, что не "info"

    register = client.get(f"/api/groups/{group_with_node.id}/vuln-register", headers=_h(operator_key)).json()
    descriptions = [row[3] for row in register["rows"]]
    assert any("CVE-2023-1234" in d for d in descriptions)

    xlsx = client.get(f"/api/groups/{group_with_node.id}/vuln-register.xlsx", headers=_h(operator_key))
    assert xlsx.status_code == 200
    assert xlsx.headers["content-type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert len(xlsx.content) > 0


def test_missing_group_has_no_targets_is_rejected(client, operator_key, db):
    group = Group(name="Пустая группа")
    db.add(group)
    db.commit()
    db.refresh(group)
    resp = client.post(
        f"/api/groups/{group.id}/vuln-scans",
        json={"profile": "ping"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_viewer_cannot_run_vuln_scan(client, db, group_with_node):
    viewer_key = generate_key(db, label="смотритель", role=ApiKeyRole.viewer)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-scans",
        json={"profile": "ping"},
        headers=_h(viewer_key),
    )
    assert resp.status_code == 403


def test_group_scoped_key_cannot_scan_other_group(client, db, group_with_node):
    other_group = Group(name="Другая группа")
    db.add(other_group)
    db.commit()
    db.refresh(other_group)
    scoped_key = generate_key(db, label="ограниченный", role=ApiKeyRole.operator, group_id=other_group.id)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-scans",
        json={"profile": "ping"},
        headers=_h(scoped_key),
    )
    assert resp.status_code == 403
