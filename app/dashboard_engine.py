"""Сводка для дашборда — одним запросом.

Считается на сервере, а не в браузере, по двум причинам. Во-первых,
иначе страница дёргала бы по эндпоинту на каждый виджет и ещё по
запросу на узел (это уже происходит в инвентаре и заметно), а дашборд
обновляется каждые 5 секунд. Во-вторых, сужение по группе живёт в
auth.py и применяется здесь один раз — виджет, собранный в браузере из
отдельных запросов, легко обошёл бы его мимо.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth import Principal, scope_nodes
from app.models import (
    AuditFinding,
    Backup,
    Incident,
    Node,
    Probe,
    Sample,
    SyslogMessage,
    Watch,
    WatchSeverity,
    _now,
)

RECENT_WINDOW = timedelta(hours=24)


def _visible_node_ids(db: Session, key: Principal) -> list[int]:
    return [row[0] for row in scope_nodes(db.query(Node.id), key).all()]


def build_dashboard(db: Session, key: Principal) -> dict:
    node_ids = _visible_node_ids(db, key)
    since = _now() - RECENT_WINDOW

    if not node_ids:
        return {
            "nodes": {"total": 0, "active": 0, "with_incidents": 0, "silent": 0},
            "incidents": {"critical": 0, "warning": 0, "info": 0, "total": 0},
            "problem_nodes": [],
            "backups": {"last_24h": 0, "failed_24h": 0, "never_backed_up": 0},
            "audit": {"failed": 0, "nodes_with_findings": 0},
            "syslog": {"last_24h": 0, "errors_24h": 0},
        }

    open_incidents = (
        db.query(Incident)
        .join(Incident.watch)
        .join(Watch.probe)
        .filter(Incident.resolved_at.is_(None), Probe.node_id.in_(node_ids))
        .all()
    )

    by_severity = {"critical": 0, "warning": 0, "info": 0}
    per_node: dict[int, dict] = {}
    for incident in open_incidents:
        severity = incident.watch.severity.value
        by_severity[severity] = by_severity.get(severity, 0) + 1
        node = incident.watch.probe.node
        entry = per_node.setdefault(
            node.id,
            {"node_id": node.id, "name": node.name, "address": node.address, "count": 0, "worst": "info"},
        )
        entry["count"] += 1
        if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[entry["worst"]]:
            entry["worst"] = severity

    # Узлы, у которых есть проверки, но ни одного измерения за сутки —
    # это не «всё хорошо», а «мы ничего о них не знаем»; на дашборде
    # такое должно быть видно отдельно от отсутствия инцидентов.
    probed_node_ids = {
        row[0] for row in db.query(Probe.node_id).filter(Probe.node_id.in_(node_ids), Probe.enabled.is_(True)).distinct()
    }
    recently_sampled = {
        row[0]
        for row in db.query(Probe.node_id)
        .join(Sample, Sample.probe_id == Probe.id)
        .filter(Probe.node_id.in_(node_ids), Sample.taken_at >= since)
        .distinct()
    }
    silent = len(probed_node_ids - recently_sampled)

    backups_recent = (
        db.query(Backup).filter(Backup.node_id.in_(node_ids), Backup.taken_at >= since).all()
    )
    nodes_with_backup = {row[0] for row in db.query(Backup.node_id).filter(Backup.node_id.in_(node_ids)).distinct()}

    failed_findings = (
        db.query(func.count(AuditFinding.id))
        .filter(AuditFinding.node_id.in_(node_ids), AuditFinding.ok.is_(False))
        .scalar()
        or 0
    )
    nodes_with_findings = (
        db.query(func.count(func.distinct(AuditFinding.node_id)))
        .filter(AuditFinding.node_id.in_(node_ids), AuditFinding.ok.is_(False))
        .scalar()
        or 0
    )

    syslog_query = db.query(SyslogMessage).filter(
        SyslogMessage.node_id.in_(node_ids), SyslogMessage.received_at >= since
    )
    syslog_total = syslog_query.count()
    # severity 0-3 по RFC 3164 — emergency/alert/critical/error.
    syslog_errors = syslog_query.filter(SyslogMessage.severity <= 3).count()

    active_nodes = db.query(func.count(Node.id)).filter(Node.id.in_(node_ids), Node.active.is_(True)).scalar() or 0

    problem_nodes = sorted(
        per_node.values(),
        key=lambda entry: (_SEVERITY_ORDER[entry["worst"]], entry["count"]),
        reverse=True,
    )[:10]

    return {
        "nodes": {
            "total": len(node_ids),
            "active": active_nodes,
            "with_incidents": len(per_node),
            "silent": silent,
        },
        "incidents": {**by_severity, "total": len(open_incidents)},
        "problem_nodes": problem_nodes,
        "backups": {
            "last_24h": len(backups_recent),
            "failed_24h": sum(1 for b in backups_recent if b.error),
            "never_backed_up": len(set(node_ids) - nodes_with_backup),
        },
        "audit": {"failed": failed_findings, "nodes_with_findings": nodes_with_findings},
        "syslog": {"last_24h": syslog_total, "errors_24h": syslog_errors},
    }


_SEVERITY_ORDER = {
    WatchSeverity.info.value: 0,
    WatchSeverity.warning.value: 1,
    WatchSeverity.critical.value: 2,
}
