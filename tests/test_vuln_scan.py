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


# --- Плановый (по расписанию) запуск ---


def test_create_and_list_vuln_schedule(client, operator_key, group_with_node):
    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-schedules",
        json={
            "profiles": ["ping", "quick"],
            "weekday": 0,
            "start_time": "12:00",
            "end_time": "13:30",
            "responsible": "Иванов И.И.",
        },
        headers=_h(operator_key),
    )
    assert resp.status_code == 201
    sched_id = resp.json()["id"]

    rows = client.get(f"/api/groups/{group_with_node.id}/vuln-schedules", headers=_h(operator_key)).json()
    assert len(rows) == 1
    assert rows[0]["id"] == sched_id
    assert rows[0]["profiles"] == ["ping", "quick"]
    assert rows[0]["weekday"] == 0
    assert rows[0]["start_time"] == "12:00"
    assert rows[0]["enabled"] is True
    assert rows[0]["last_triggered_on"] is None


def test_create_vuln_schedule_rejects_unknown_profile(client, operator_key, group_with_node):
    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-schedules",
        json={"profiles": ["not-a-profile"], "weekday": 0, "start_time": "12:00"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 400


def test_update_and_delete_vuln_schedule(client, operator_key, group_with_node):
    sched_id = client.post(
        f"/api/groups/{group_with_node.id}/vuln-schedules",
        json={"profiles": ["ping"], "weekday": 0, "start_time": "12:00"},
        headers=_h(operator_key),
    ).json()["id"]

    resp = client.patch(
        f"/api/vuln-schedules/{sched_id}",
        json={"profiles": ["ping"], "weekday": 1, "start_time": "09:00", "enabled": False},
        headers=_h(operator_key),
    )
    assert resp.status_code == 200
    rows = client.get(f"/api/groups/{group_with_node.id}/vuln-schedules", headers=_h(operator_key)).json()
    assert rows[0]["weekday"] == 1
    assert rows[0]["enabled"] is False

    resp = client.delete(f"/api/vuln-schedules/{sched_id}", headers=_h(operator_key))
    assert resp.status_code == 204
    rows = client.get(f"/api/groups/{group_with_node.id}/vuln-schedules", headers=_h(operator_key)).json()
    assert rows == []


def test_viewer_cannot_create_vuln_schedule(client, db, group_with_node):
    viewer_key = generate_key(db, label="смотритель", role=ApiKeyRole.viewer)
    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-schedules",
        json={"profiles": ["ping"], "weekday": 0, "start_time": "12:00"},
        headers=_h(viewer_key),
    )
    assert resp.status_code == 403


def test_run_due_vuln_schedules_triggers_matching_and_skips_others(db, group_with_node):
    """Прямая проверка движка (без прохода через реальный планировщик):
    расписание "сегодня, уже наступило время" должно запустить сканы и
    выставить last_triggered_on; расписание "не сегодня" и "уже
    запускалось сегодня" — не должны трогаться."""
    import datetime as dt

    from app.db import SessionLocal
    from app.models import VulnScan, VulnScanSchedule
    from app.vuln_scan_engine import run_due_vuln_schedules

    now = dt.datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    past_hm = (now - dt.timedelta(minutes=5)).strftime("%H:%M")
    future_hm = (now + dt.timedelta(hours=1)).strftime("%H:%M")
    other_weekday = (now.weekday() + 1) % 7

    due = VulnScanSchedule(
        group_id=group_with_node.id, profiles=["ping"], weekday=now.weekday(), start_time=past_hm,
    )
    not_yet = VulnScanSchedule(
        group_id=group_with_node.id, profiles=["ping"], weekday=now.weekday(), start_time=future_hm,
    )
    wrong_day = VulnScanSchedule(
        group_id=group_with_node.id, profiles=["ping"], weekday=other_weekday, start_time=past_hm,
    )
    already_ran = VulnScanSchedule(
        group_id=group_with_node.id, profiles=["ping"], weekday=now.weekday(), start_time=past_hm,
        last_triggered_on=today_str,
    )
    db.add_all([due, not_yet, wrong_day, already_ran])
    db.commit()

    asyncio.run(run_due_vuln_schedules(SessionLocal))

    db.refresh(due)
    db.refresh(not_yet)
    db.refresh(wrong_day)
    assert due.last_triggered_on == today_str
    assert not_yet.last_triggered_on is None
    assert wrong_day.last_triggered_on is None

    scans = db.query(VulnScan).filter(VulnScan.group_id == group_with_node.id).all()
    assert len(scans) == 1
    assert scans[0].profile.value == "ping"
    assert scans[0].responsible == "плановый запуск по расписанию"


# --- Профиль Nuclei (docs/landscape-report.md, доразбор security-
# инструментов) — реальный вывод захвачен на живом прогоне против
# scanme.nmap.org (2026-09-25), синтетика ниже собрана по той же схеме,
# не выдумана по документации.

NUCLEI_JSONL = (
    '{"template-id":"apache-detect","info":{"name":"Apache Detection","severity":"info",'
    '"classification":{}},"host":"10.0.0.5","matched-at":"http://10.0.0.5"}\n'
    '{"template-id":"CVE-2023-9999-fake","info":{"name":"Пример критической уязвимости",'
    '"severity":"critical","classification":{"cve-id":["CVE-2023-9999"]}},'
    '"host":"10.0.0.5","matched-at":"http://10.0.0.5:8080"}\n'
)


def test_parse_nuclei_jsonl_maps_severity_and_cves():
    from app.vuln_scan_engine import parse_nuclei_jsonl

    hosts = parse_nuclei_jsonl(NUCLEI_JSONL, ["10.0.0.5"])
    assert len(hosts) == 1
    findings = {f["script_id"]: f for f in hosts[0]["findings"]}
    assert findings["apache-detect"]["severity"] == "info"
    assert findings["apache-detect"]["nuclei_severity"] == "info"
    assert findings["CVE-2023-9999-fake"]["severity"] == "vulnerable"  # critical -> vulnerable
    assert findings["CVE-2023-9999-fake"]["nuclei_severity"] == "critical"
    assert findings["CVE-2023-9999-fake"]["cves"] == ["CVE-2023-9999"]


def test_parse_nuclei_jsonl_skips_non_json_lines():
    """Реальный вывод nuclei может содержать баннер/статусные строки
    вперемешку с -jsonl, если -silent забыли — не должны ронять разбор."""
    from app.vuln_scan_engine import parse_nuclei_jsonl

    raw = "some banner text\n" + NUCLEI_JSONL + "\ntrailing garbage, not json"
    hosts = parse_nuclei_jsonl(raw, ["10.0.0.5"])
    assert sum(len(h["findings"]) for h in hosts) == 2


class _FakeNucleiProc:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.sent_input = None

    async def communicate(self, input=None):
        self.sent_input = input
        return self._stdout, self._stderr

    def kill(self):
        pass


def test_run_nuclei_scan_does_not_pass_dash_l_dash(monkeypatch, db, group_with_node):
    """Регрессия реальной находки (2026-09-25): "-l -" не читает цели из
    stdin в этой версии nuclei ("could not open targets file: open -: no
    such file or directory") — вызов не должен передавать -l/-u вовсе,
    цели уходят только через stdin."""
    from app.vuln_scan_engine import run_nuclei_scan
    from app.db import SessionLocal
    from app.models import VulnScan

    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["args"] = args
        return _FakeNucleiProc(NUCLEI_JSONL.encode())

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    scan = VulnScan(group_id=group_with_node.id, profile="nuclei")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    asyncio.run(run_nuclei_scan(scan.id, ["10.0.0.5"], SessionLocal))

    assert "-l" not in captured["args"]
    assert "-u" not in captured["args"]
    assert "-" not in captured["args"]

    db.refresh(scan)
    assert scan.status.value == "done"
    assert len(scan.hosts) == 1
    assert len(scan.hosts[0].findings) == 2


def test_run_nuclei_scan_fails_on_ftl_even_with_exit_code_zero(monkeypatch, db, group_with_node):
    """Регрессия реальной находки (2026-09-25): nuclei возвращает
    returncode=0 даже на фатальную ошибку ("no templates provided for
    scan" — проверено живым запуском) — полагаться только на код
    возврата нельзя, иначе это молча стало бы "готово, находок 0"."""
    from app.vuln_scan_engine import run_nuclei_scan
    from app.db import SessionLocal
    from app.models import VulnScan

    # Байты как в реальном выводе — уровень лога обёрнут ANSI-кодом
    # цвета, "FTL]" непрерывной подстрокой НЕ встречается.
    real_ftl_stderr = b"[\x1b[1;31mFTL\x1b[0m] Could not run nuclei: no templates provided for scan\n"

    async def fake_exec(*args, **kwargs):
        return _FakeNucleiProc(b"", stderr=real_ftl_stderr, returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    scan = VulnScan(group_id=group_with_node.id, profile="nuclei")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    asyncio.run(run_nuclei_scan(scan.id, ["10.0.0.5"], SessionLocal))

    db.refresh(scan)
    assert scan.status.value == "failed"
    assert "no templates" in scan.error


def test_run_nuclei_scan_via_api(monkeypatch, client, operator_key, group_with_node):
    """Тот же путь, что и у nmap-профилей — POST .../vuln-scans с
    profile=nuclei должен пойти через run_nuclei_scan, а не PROFILE_ARGS
    (у "nuclei" нет записи там намеренно, см. VALID_PROFILES)."""

    async def fake_exec(*args, **kwargs):
        return _FakeNucleiProc(NUCLEI_JSONL.encode())

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    resp = client.post(
        f"/api/groups/{group_with_node.id}/vuln-scans",
        json={"profile": "nuclei", "responsible": "тест"},
        headers=_h(operator_key),
    )
    assert resp.status_code == 201

    scan = _wait_done(client, operator_key, group_with_node.id)
    assert scan["status"] == "done"
    # findings_count исключает severity="info" (см. main.py) - из двух
    # синтетических находок в NUCLEI_JSONL считается только vulnerable.
    assert scan["findings_count"] == 1
