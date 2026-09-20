"""Удаление элементов инвентаря вместе с зависимостями.

ORM-каскад покрывает только Node → Probe → Sample/Watch. Всё остальное
(Incident и Action на Watch; Backup, AuditFinding, SyslogMessage на Node;
Channel на любом из них) убирается явно — эти тесты и проверяют, что
после удаления не остаётся строк, ссылающихся в пустоту.
"""

import pytest

from app.inventory_engine import delete_node, delete_probe, delete_watch
from app.models import (
    Action,
    ActionKind,
    AuditFinding,
    Backup,
    Channel,
    ChannelKind,
    Incident,
    Node,
    Probe,
    ProbeKind,
    Sample,
    SyslogMessage,
    Watch,
    WatchOperator,
    WatchSeverity,
)


@pytest.fixture()
def full_node(db):
    """Узел со всем, что к нему может прицепиться."""
    node = Node(name="полный-узел", address="10.0.0.1")
    db.add(node)
    db.commit()

    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()

    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="down")
    db.add(watch)
    db.commit()

    db.add(Sample(probe_id=probe.id, ok=True, value=1.0))
    db.add(Incident(watch_id=watch.id, detail="упал"))
    db.add(Action(watch_id=watch.id, kind=ActionKind.ssh_command, config={"command": "reload"}))
    db.add(Backup(node_id=node.id, content="конфиг", changed=True))
    db.add(AuditFinding(node_id=node.id, ok=False, detail="плохо"))
    db.add(SyslogMessage(source_ip="10.0.0.1", message="что-то", node_id=node.id))
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://x"}, node_id=node.id))
    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://y"}, watch_id=watch.id))
    db.commit()
    return {"node": node, "probe": probe, "watch": watch}


def test_delete_node_leaves_nothing_dangling(db, full_node):
    delete_node(db, full_node["node"])

    assert db.query(Node).count() == 0
    assert db.query(Probe).count() == 0
    assert db.query(Watch).count() == 0
    assert db.query(Sample).count() == 0
    assert db.query(Incident).count() == 0
    assert db.query(Action).count() == 0
    assert db.query(Backup).count() == 0
    assert db.query(AuditFinding).count() == 0


def test_delete_node_reports_what_it_removed(db, full_node):
    """Удаление узла задевает многое — эндпоинт обязан сказать, что именно,
    а не промолчать."""
    removed = delete_node(db, full_node["node"])
    assert removed["probes"] == 1
    assert removed["watches"] == 1
    assert removed["samples"] == 1
    assert removed["incidents"] == 1
    assert removed["actions"] == 1
    assert removed["backups"] == 1
    assert removed["audit_findings"] == 1
    assert removed["channels_disabled"] == 2
    assert removed["syslog_unlinked"] == 1


def test_syslog_survives_node_deletion_but_loses_link(db, full_node):
    """Сообщение ценно само по себе: именно так хранятся логи от
    неизвестных источников. Удалять их вместе с узлом — терять историю."""
    delete_node(db, full_node["node"])
    messages = db.query(SyslogMessage).all()
    assert len(messages) == 1
    assert messages[0].node_id is None
    assert messages[0].message == "что-то"


def test_channels_are_disabled_not_deleted_and_not_made_global(db, full_node):
    """Сделать канал глобальным значило бы молча начать слать по всем
    узлам — ровно обратное тому, что настраивал владелец. Удалить —
    потерять настроенный webhook. Поэтому отвязываем и выключаем."""
    delete_node(db, full_node["node"])
    channels = db.query(Channel).all()
    assert len(channels) == 2
    for channel in channels:
        assert channel.enabled is False
        assert channel.node_id is None
        assert channel.watch_id is None


def test_delete_probe_removes_its_watches_and_incidents(db, full_node):
    delete_probe(db, full_node["probe"])

    assert db.query(Probe).count() == 0
    assert db.query(Watch).count() == 0
    assert db.query(Sample).count() == 0
    assert db.query(Incident).count() == 0
    assert db.query(Action).count() == 0
    assert db.query(Node).count() == 1  # сам узел остаётся


def test_delete_watch_removes_incidents_and_actions_only(db, full_node):
    delete_watch(db, full_node["watch"])

    assert db.query(Watch).count() == 0
    assert db.query(Incident).count() == 0
    assert db.query(Action).count() == 0
    assert db.query(Probe).count() == 1  # проверка остаётся
    assert db.query(Sample).count() == 1  # измерения тоже
