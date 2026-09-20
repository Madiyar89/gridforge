"""Удаление элементов инвентаря со всеми зависимостями.

ORM-каскады покрывают только часть графа: Node → Probe → Sample/Watch.
Дальше ссылки идут в стороны, где каскада нет (Incident и Action висят на
Watch; Backup, AuditFinding и SyslogMessage — на Node; Channel может быть
привязан к любому из них). Без явной уборки удаление узла оставляло бы
осиротевшие строки, ссылающиеся в пустоту, — поэтому весь порядок собран
здесь, в одном месте, а не размазан по эндпоинтам.

Отдельное решение про Channel. Канал, привязанный к удаляемому узлу или
условию, НЕ удаляется и НЕ становится глобальным: он отвязывается и
выключается. Сделать его глобальным значило бы молча начать слать по
всем узлам сразу (пользователь настраивал ровно обратное), а удалить —
потерять настроенный webhook/бот. Выключенный канал виден в интерфейсе,
и владелец сам решает, что с ним делать.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import (
    Action,
    AuditFinding,
    Backup,
    Channel,
    Incident,
    Node,
    Probe,
    Sample,
    SyslogMessage,
    Watch,
)


def _detach_channels(db: Session, *, node_id: int | None = None, watch_ids: list[int] | None = None) -> int:
    """Отвязать и выключить каналы, указывавшие на удаляемое."""
    query = db.query(Channel)
    if node_id is not None and watch_ids:
        query = query.filter((Channel.node_id == node_id) | (Channel.watch_id.in_(watch_ids)))
    elif node_id is not None:
        query = query.filter(Channel.node_id == node_id)
    elif watch_ids:
        query = query.filter(Channel.watch_id.in_(watch_ids))
    else:
        return 0

    affected = query.all()
    for channel in affected:
        channel.node_id = None
        channel.watch_id = None
        channel.enabled = False
    return len(affected)


def delete_watch(db: Session, watch: Watch) -> None:
    """Условие + всё, что на нём висит: инциденты, действия, привязки каналов."""
    _detach_channels(db, watch_ids=[watch.id])
    db.query(Action).filter(Action.watch_id == watch.id).delete(synchronize_session=False)
    db.query(Incident).filter(Incident.watch_id == watch.id).delete(synchronize_session=False)
    db.delete(watch)
    db.commit()


def delete_probe(db: Session, probe: Probe) -> None:
    """Проверка + её измерения и условия (с зависимостями каждого условия).

    Сами Sample и Watch удаляет ORM-каскад при db.delete(probe) — вручную
    убирается только то, что каскадом не покрыто."""
    watch_ids = [w.id for w in probe.watches]
    if watch_ids:
        _detach_channels(db, watch_ids=watch_ids)
        db.query(Action).filter(Action.watch_id.in_(watch_ids)).delete(synchronize_session=False)
        db.query(Incident).filter(Incident.watch_id.in_(watch_ids)).delete(synchronize_session=False)
    db.delete(probe)
    db.commit()


def delete_node(db: Session, node: Node) -> dict[str, int]:
    """Узел и весь его след. Возвращает, что именно было удалено, —
    удаление узла задевает многое, и молча это делать неправильно."""
    probe_ids = [p.id for p in node.probes]
    watch_ids = [w.id for p in node.probes for w in p.watches]

    # Probe/Sample/Watch удалит ORM-каскад при db.delete(node) — их
    # количество считаем заранее, ради честного отчёта. Удалять их здесь
    # ещё и вручную (bulk-запросом) нельзя: сессия рассогласуется с тем,
    # что каскад потом попытается удалить повторно.
    removed = {
        "probes": len(probe_ids),
        "watches": len(watch_ids),
        "samples": db.query(Sample).filter(Sample.probe_id.in_(probe_ids)).count() if probe_ids else 0,
        "incidents": 0,
        "actions": 0,
        "backups": 0,
        "audit_findings": 0,
        "channels_disabled": _detach_channels(db, node_id=node.id, watch_ids=watch_ids),
        "syslog_unlinked": 0,
    }

    if watch_ids:
        removed["actions"] = db.query(Action).filter(Action.watch_id.in_(watch_ids)).delete(synchronize_session=False)
        removed["incidents"] = (
            db.query(Incident).filter(Incident.watch_id.in_(watch_ids)).delete(synchronize_session=False)
        )

    removed["backups"] = db.query(Backup).filter(Backup.node_id == node.id).delete(synchronize_session=False)
    removed["audit_findings"] = (
        db.query(AuditFinding).filter(AuditFinding.node_id == node.id).delete(synchronize_session=False)
    )
    # Syslog не удаляем: сообщение ценно само по себе и прекрасно живёт без
    # привязки к узлу (именно так хранятся сообщения от неизвестных
    # источников). Просто отвязываем.
    removed["syslog_unlinked"] = (
        db.query(SyslogMessage)
        .filter(SyslogMessage.node_id == node.id)
        .update({SyslogMessage.node_id: None}, synchronize_session=False)
    )

    db.delete(node)
    db.commit()
    return removed
