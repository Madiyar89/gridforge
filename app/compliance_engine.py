"""Compliance — «правило → список несоответствующих узлов» по всему парку,
перенесено из NetOpsHub (hub/backend/app/modules/reports/compliance.py).

Там это отдельный YAML-файл (golden_config.yml) поверх своего же
must_contain/must_not_contain движка. У GridForge тот же движок уже есть
как AuditRule (app/audit_engine.py, редактируется через API/UI, не YAML) —
здесь просто разворот того же самого правила на весь парк разом (рулит
правило → узлы), вместо узел → правила, как в audit_engine.run_audit().
Второй YAML-файл не нужен — одни и те же правила читаются с двух сторон."""

from __future__ import annotations

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.audit_engine import _rule_matches
from app.models import AuditRule, Backup, Node


def check_compliance(db: Session) -> list[dict]:
    rules = db.query(AuditRule).filter(AuditRule.enabled.is_(True)).order_by(AuditRule.name).all()
    nodes = db.query(Node).filter(Node.active.is_(True)).all()

    result = []
    for rule in rules:
        non_compliant = []
        checked = 0
        for node in nodes:
            if rule.vendor is not None and node.vendor != rule.vendor:
                continue
            backup = (
                db.query(Backup)
                .filter(Backup.node_id == node.id, Backup.error.is_(None))
                .order_by(desc(Backup.taken_at))
                .first()
            )
            if backup is None:
                continue  # нет бэкапа — не с чем сверять, не считаем ни соответствующим, ни нет
            checked += 1
            ok, detail = _rule_matches(rule, backup.content)
            if not ok:
                non_compliant.append({"node_id": node.id, "hostname": node.name, "detail": detail})
        result.append(
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity.value,
                "checked_count": checked,
                "non_compliant": non_compliant,
            }
        )
    return result
