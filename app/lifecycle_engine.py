"""Правила жизненного цикла устройств (docs/landscape-report.md, §4.6) —
небольшой движок правил поверх уже существующей модели Node/Group/Sample,
БЕЗ новой таблицы под находки: только чтение уже накопленных данных и
готовые подсказки. Применяет их админ явно через уже существующие
POST /api/groups и PATCH /api/nodes (сам этот модуль в БД не пишет,
поэтому нет риска молча за кого-то что-то заархивировать).

Источник идеи: NetAlertX, модуль Workflows."""

from __future__ import annotations

import os
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Group, Node, Probe, Sample, Vendor, _now

OFFLINE_DAYS_DEFAULT = int(os.environ.get("GRIDFORGE_LIFECYCLE_OFFLINE_DAYS", "14"))

_VENDOR_GROUP_NAMES = {
    Vendor.cisco_ios: "Cisco IOS",
    Vendor.cisco_ios_telnet: "Cisco IOS (Telnet)",
    Vendor.junos: "Juniper Junos",
    Vendor.generic: "Общее оборудование",
}


def suggest_vendor_grouping(db: Session) -> list[dict]:
    """Активные узлы с известным вендором, но без группы — сгруппировать
    по вендору. Группируем начиная с одного узла на вендор (не ждём
    порога) — это подсказка, не автоматика, решение всё равно за
    админом, лишняя группа на один узел не вредит."""
    rows = (
        db.query(Node.vendor, func.count(Node.id))
        .filter(Node.vendor.isnot(None), Node.group_id.is_(None), Node.active.is_(True))
        .group_by(Node.vendor)
        .all()
    )
    existing_groups = {g.name: g.id for g in db.query(Group).all()}
    suggestions = []
    for vendor, count in rows:
        group_name = _VENDOR_GROUP_NAMES.get(vendor, vendor.value)
        node_ids = [
            row[0]
            for row in db.query(Node.id)
            .filter(Node.vendor == vendor, Node.group_id.is_(None), Node.active.is_(True))
            .all()
        ]
        suggestions.append(
            {
                "vendor": vendor.value,
                "suggested_group_name": group_name,
                "existing_group_id": existing_groups.get(group_name),
                "node_ids": node_ids,
                "node_count": count,
            }
        )
    return suggestions


def suggest_offline_archival(db: Session, offline_days: int = OFFLINE_DAYS_DEFAULT) -> list[dict]:
    """«Офлайн N дней, предложить архивировать» — узел, у которого есть
    хотя бы один Sample старше cutoff (значит, реально опрашивался всё
    это время, не только что заведён и ещё не успел ответить), но ни
    одного успешного (ok=True) после cutoff. Только активные узлы —
    уже заархивированный трогать незачем."""
    cutoff = _now() - timedelta(days=offline_days)
    nodes = db.query(Node).filter(Node.active.is_(True)).all()
    suggestions = []
    for node in nodes:
        probe_ids = [row[0] for row in db.query(Probe.id).filter(Probe.node_id == node.id).all()]
        if not probe_ids:
            continue
        has_old_sample = (
            db.query(Sample.id).filter(Sample.probe_id.in_(probe_ids), Sample.taken_at < cutoff).first()
            is not None
        )
        if not has_old_sample:
            continue  # узел моложе offline_days — рано делать выводы
        last_ok = (
            db.query(func.max(Sample.taken_at))
            .filter(Sample.probe_id.in_(probe_ids), Sample.ok.is_(True))
            .scalar()
        )
        if last_ok is not None and last_ok >= cutoff:
            continue  # был успешный опрос совсем недавно — не офлайн
        suggestions.append(
            {
                "node_id": node.id,
                "name": node.name,
                "address": node.address,
                "last_ok_at": last_ok.isoformat() if last_ok else None,
                "offline_days": offline_days,
            }
        )
    return suggestions
