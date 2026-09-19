"""Прогон AuditRule по последнему бэкапу узла. Синхронный (никакого SSH —
работает на уже снятых данных), в отличие от probes/actions/backups не
async, вызывается напрямую из FastAPI-роута."""

from __future__ import annotations

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import AuditCheckKind, AuditFinding, AuditRule, Backup, Node


def _rule_matches(rule: AuditRule, config_text: str) -> tuple[bool, str]:
    """Возвращает (ok, detail). ok=False — находка (правило нарушено)."""
    found = rule.pattern in config_text
    if rule.kind == AuditCheckKind.must_contain:
        if found:
            return True, f"«{rule.pattern}» найдено"
        return False, f"«{rule.pattern}» не найдено в конфиге"
    else:  # must_not_contain
        if found:
            return False, f"«{rule.pattern}» найдено в конфиге"
        return True, f"«{rule.pattern}» отсутствует"


def run_audit(db: Session, node: Node) -> list[AuditFinding]:
    """Перезаписывает находки узла (см. AuditFinding — не журнал прогонов).
    Возвращает актуальный список после прогона."""
    db.query(AuditFinding).filter(AuditFinding.node_id == node.id).delete()

    latest_backup = (
        db.query(Backup)
        .filter(Backup.node_id == node.id, Backup.error.is_(None))
        .order_by(desc(Backup.taken_at))
        .first()
    )
    if latest_backup is None:
        finding = AuditFinding(node_id=node.id, rule_id=None, ok=False, detail="нет успешного бэкапа — аудит не проводился")
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return [finding]

    query = db.query(AuditRule).filter(AuditRule.enabled.is_(True))
    if node.vendor is not None:
        query = query.filter((AuditRule.vendor.is_(None)) | (AuditRule.vendor == node.vendor))
    else:
        query = query.filter(AuditRule.vendor.is_(None))
    rules = query.all()

    findings: list[AuditFinding] = []
    for rule in rules:
        ok, detail = _rule_matches(rule, latest_backup.content)
        finding = AuditFinding(node_id=node.id, rule_id=rule.id, ok=ok, detail=detail)
        db.add(finding)
        findings.append(finding)
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings
