from datetime import timedelta

import pytest

from app.models import Backup, Capture, CaptureStatus, Node, Probe, ProbeKind, Sample, SyslogMessage, _now
from app.retention_engine import run_retention


@pytest.fixture()
def node(db):
    n = Node(name="ret-node", address="10.0.0.1")
    db.add(n)
    db.commit()
    return n


@pytest.fixture()
def probe(db, node):
    p = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(p)
    db.commit()
    return p


def test_old_samples_deleted_recent_kept(db, probe, monkeypatch):
    monkeypatch.setenv("GRIDFORGE_RETENTION_SAMPLES_DAYS", "30")
    db.add(Sample(probe_id=probe.id, ok=True, value=1.0, taken_at=_now() - timedelta(days=40)))
    db.add(Sample(probe_id=probe.id, ok=True, value=2.0, taken_at=_now() - timedelta(days=5)))
    db.commit()

    result = run_retention(db)
    assert result["samples"] == 1
    remaining = db.query(Sample).all()
    assert len(remaining) == 1
    assert remaining[0].value == 2.0


def test_old_syslog_deleted(db, monkeypatch):
    monkeypatch.setenv("GRIDFORGE_RETENTION_SYSLOG_DAYS", "30")
    db.add(SyslogMessage(source_ip="10.0.0.1", message="старое", received_at=_now() - timedelta(days=60)))
    db.add(SyslogMessage(source_ip="10.0.0.1", message="свежее", received_at=_now() - timedelta(hours=1)))
    db.commit()

    result = run_retention(db)
    assert result["syslog"] == 1
    assert [m.message for m in db.query(SyslogMessage).all()] == ["свежее"]


def test_backups_trimmed_by_count_not_age(db, node, monkeypatch):
    """Бэкапы ограничены количеством: у редко меняющегося узла все снимки
    могут быть очень старыми, и чистка по возрасту стёрла бы единственную
    копию конфигурации."""
    monkeypatch.setenv("GRIDFORGE_RETENTION_BACKUPS_KEEP", "3")
    for i in range(6):
        db.add(Backup(node_id=node.id, content=f"конфиг {i}", taken_at=_now() - timedelta(days=100 + i)))
    db.commit()

    result = run_retention(db)
    assert result["backups"] == 3
    kept = [b.content for b in db.query(Backup).order_by(Backup.taken_at.desc()).all()]
    assert kept == ["конфиг 0", "конфиг 1", "конфиг 2"]  # три самых свежих


def test_single_ancient_backup_is_never_deleted(db, node, monkeypatch):
    """Главная гарантия: последний снимок узла не исчезает ни при каком
    возрасте — иначе ретеншн уничтожал бы то, ради чего бэкапы делаются."""
    monkeypatch.setenv("GRIDFORGE_RETENTION_BACKUPS_KEEP", "3")
    monkeypatch.setenv("GRIDFORGE_RETENTION_SAMPLES_DAYS", "1")
    db.add(Backup(node_id=node.id, content="единственный", taken_at=_now() - timedelta(days=3650)))
    db.commit()

    run_retention(db)
    assert [b.content for b in db.query(Backup).all()] == ["единственный"]


def test_backups_of_different_nodes_counted_separately(db, node, monkeypatch):
    monkeypatch.setenv("GRIDFORGE_RETENTION_BACKUPS_KEEP", "2")
    other = Node(name="other", address="10.0.0.2")
    db.add(other)
    db.commit()
    for i in range(3):
        db.add(Backup(node_id=node.id, content=f"a{i}", taken_at=_now() - timedelta(days=i)))
        db.add(Backup(node_id=other.id, content=f"b{i}", taken_at=_now() - timedelta(days=i)))
    db.commit()

    run_retention(db)
    assert db.query(Backup).filter(Backup.node_id == node.id).count() == 2
    assert db.query(Backup).filter(Backup.node_id == other.id).count() == 2


def test_old_capture_row_and_pcap_file_both_removed(db, tmp_path, monkeypatch):
    """Запись и файл удаляются вместе — иначе в БД чисто, а диск занят
    .pcap, которые уже ниоткуда не открыть."""
    monkeypatch.setenv("GRIDFORGE_RETENTION_CAPTURES_DAYS", "7")
    pcap = tmp_path / "old.pcap"
    pcap.write_bytes(b"x" * 100)
    db.add(
        Capture(
            interface="eth0",
            status=CaptureStatus.done,
            started_at=_now() - timedelta(days=30),
            file_path=str(pcap),
        )
    )
    db.commit()

    result = run_retention(db)
    assert result["captures"] == 1
    assert not pcap.exists()
    assert db.query(Capture).count() == 0


def test_recent_capture_and_its_file_kept(db, tmp_path, monkeypatch):
    monkeypatch.setenv("GRIDFORGE_RETENTION_CAPTURES_DAYS", "7")
    pcap = tmp_path / "fresh.pcap"
    pcap.write_bytes(b"x")
    db.add(Capture(interface="eth0", status=CaptureStatus.done, started_at=_now(), file_path=str(pcap)))
    db.commit()

    run_retention(db)
    assert pcap.exists()
    assert db.query(Capture).count() == 1


def test_empty_database_is_a_no_op(db):
    assert run_retention(db) == {
        "samples": 0, "syslog": 0, "captures": 0, "backups": 0, "flows": 0, "sync_reports": 0,
    }


def test_bad_env_value_falls_back_to_default(db, probe, monkeypatch):
    """Опечатка в переменной окружения не должна ни ронять очистку, ни —
    что хуже — приводить к удалению всего подряд."""
    monkeypatch.setenv("GRIDFORGE_RETENTION_SAMPLES_DAYS", "тридцать")
    db.add(Sample(probe_id=probe.id, ok=True, value=1.0, taken_at=_now() - timedelta(days=5)))
    db.commit()

    result = run_retention(db)
    assert result["samples"] == 0  # 5 дней < дефолтных 30 — ничего не удалено
    assert db.query(Sample).count() == 1
