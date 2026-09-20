from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import Principal, generate_key
from app.dashboard_engine import build_dashboard
from app.main import app
from app.models import (
    ApiKeyRole,
    AuditFinding,
    Backup,
    Group,
    Incident,
    Node,
    Probe,
    ProbeKind,
    Sample,
    SyslogMessage,
    Watch,
    WatchOperator,
    WatchSeverity,
    _now,
)


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="admin", role=ApiKeyRole.admin)


def _unscoped() -> Principal:
    return Principal(label="тест", role=ApiKeyRole.admin, group_id=None, kind="api_key")


def _node_with_incident(db, name, severity=WatchSeverity.critical, group_id=None):
    node = Node(name=name, address="10.0.0.1", group_id=group_id)
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=severity, label=f"{name} упал")
    db.add(watch)
    db.commit()
    db.add(Incident(watch_id=watch.id, detail="не отвечает"))
    db.commit()
    return node


def test_empty_installation_gives_zeros(db):
    summary = build_dashboard(db, _unscoped())
    assert summary["nodes"]["total"] == 0
    assert summary["incidents"]["total"] == 0
    assert summary["problem_nodes"] == []


def test_incident_counts_by_severity(db):
    _node_with_incident(db, "критичный", WatchSeverity.critical)
    _node_with_incident(db, "предупреждение", WatchSeverity.warning)

    summary = build_dashboard(db, _unscoped())
    assert summary["incidents"]["critical"] == 1
    assert summary["incidents"]["warning"] == 1
    assert summary["incidents"]["total"] == 2
    assert summary["nodes"]["with_incidents"] == 2


def test_resolved_incidents_are_not_counted(db):
    node = _node_with_incident(db, "починенный")
    incident = db.query(Incident).first()
    incident.resolved_at = _now()
    db.commit()

    summary = build_dashboard(db, _unscoped())
    assert summary["incidents"]["total"] == 0
    assert summary["nodes"]["with_incidents"] == 0


def test_problem_nodes_show_worst_severity_first(db):
    _node_with_incident(db, "просто-предупреждение", WatchSeverity.warning)
    _node_with_incident(db, "всё-плохо", WatchSeverity.critical)

    problem = build_dashboard(db, _unscoped())["problem_nodes"]
    assert problem[0]["name"] == "всё-плохо"
    assert problem[0]["worst"] == "critical"


def test_silent_nodes_are_counted_separately(db):
    """Узел с включённой проверкой, но без измерений за сутки — это не
    «всё хорошо», а «мы о нём ничего не знаем»."""
    node = Node(name="молчун", address="10.0.0.5")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping, enabled=True)
    db.add(probe)
    db.commit()

    summary = build_dashboard(db, _unscoped())
    assert summary["nodes"]["silent"] == 1
    assert summary["incidents"]["total"] == 0  # инцидентов нет, но узел молчит


def test_recently_sampled_node_is_not_silent(db):
    node = Node(name="живой", address="10.0.0.6")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    db.add(Sample(probe_id=probe.id, ok=True, value=1.0, taken_at=_now()))
    db.commit()

    assert build_dashboard(db, _unscoped())["nodes"]["silent"] == 0


def test_backup_stats(db):
    node = Node(name="узел", address="10.0.0.7")
    other = Node(name="без-бэкапов", address="10.0.0.8")
    db.add_all([node, other])
    db.commit()
    db.add(Backup(node_id=node.id, content="ок", taken_at=_now()))
    db.add(Backup(node_id=node.id, content="", error="SSH timeout", taken_at=_now()))
    db.add(Backup(node_id=node.id, content="старый", taken_at=_now() - timedelta(days=3)))
    db.commit()

    backups = build_dashboard(db, _unscoped())["backups"]
    assert backups["last_24h"] == 2       # старый в сутки не попал
    assert backups["failed_24h"] == 1
    assert backups["never_backed_up"] == 1


def test_audit_and_syslog_stats(db):
    node = Node(name="узел", address="10.0.0.9")
    db.add(node)
    db.commit()
    db.add(AuditFinding(node_id=node.id, ok=False, detail="нет баннера"))
    db.add(AuditFinding(node_id=node.id, ok=True, detail="всё хорошо"))
    db.add(SyslogMessage(source_ip="10.0.0.9", node_id=node.id, message="обычное", severity=6, received_at=_now()))
    db.add(SyslogMessage(source_ip="10.0.0.9", node_id=node.id, message="ошибка", severity=3, received_at=_now()))
    db.commit()

    summary = build_dashboard(db, _unscoped())
    assert summary["audit"]["failed"] == 1
    assert summary["audit"]["nodes_with_findings"] == 1
    assert summary["syslog"]["last_24h"] == 2
    assert summary["syslog"]["errors_24h"] == 1  # severity<=3 — от error и хуже


def test_group_scope_applies_to_whole_summary(db):
    """Сводка обязана уважать ограничение по группе: иначе дашборд
    показывал бы «что-то где-то сломалось» из чужой зоны."""
    own = Group(name="своя")
    other = Group(name="чужая")
    db.add_all([own, other])
    db.commit()
    _node_with_incident(db, "свой", group_id=own.id)
    _node_with_incident(db, "чужой", group_id=other.id)

    scoped = Principal(label="ограниченный", role=ApiKeyRole.admin, group_id=own.id, kind="api_key")
    summary = build_dashboard(db, scoped)
    assert summary["nodes"]["total"] == 1
    assert summary["incidents"]["total"] == 1
    assert [n["name"] for n in summary["problem_nodes"]] == ["свой"]


def test_incident_list_now_says_which_node(client, admin_key, db):
    """Раньше список инцидентов отвечал «что сломалось», но не «где»."""
    _node_with_incident(db, "LAB-7")
    incidents = client.get("/api/incidents", headers={"X-API-Key": admin_key}).json()
    assert incidents[0]["node_name"] == "LAB-7"
    assert incidents[0]["node_address"] == "10.0.0.1"


def test_dashboard_endpoint_requires_auth(client):
    assert client.get("/api/dashboard").status_code == 401
