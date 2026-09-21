"""Безстейтовый флот-отчёт по аудиту конфигураций сетевого оборудования —
перенесено из NetOpsHub (шаг 3, тот же приём, что и AD-аудит: факты ->
правила -> скоринг, см. ad_audit_engine.run_ad_audit_fleet_report).

Область действия — как в NetOpsHub: только узлы с вендором cisco_ios/
cisco_ios_telnet/junos И хотя бы одним успешным бэкапом. Узлы без бэкапа
или с неподдержанным вендором (generic, None) в отчёт не попадают —
честно исключаются, не подставляются нулями."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import Backup, Node, Vendor
from app.network_audit_facts import extract_facts
from app.network_audit_rules import CATALOG_UPDATED_AT, CATALOG_VERSION, RULES
from app.risk_scoring import category_score, evaluate_rules, object_score, risk_band

_SUPPORTED_VENDORS = (Vendor.cisco_ios, Vendor.cisco_ios_telnet, Vendor.junos)


def _latest_backup(db: Session, node_id: int) -> Backup | None:
    return (
        db.query(Backup)
        .filter(Backup.node_id == node_id, Backup.error.is_(None))
        .order_by(desc(Backup.taken_at))
        .first()
    )


def build_node_report(node: Node, backup: Backup) -> dict:
    facts = extract_facts(node.vendor.value, backup.content) or {}
    # Telnet-only управление — находка сама по себе, не факт из текста
    # конфига (зависит от того, КАК бэкап был снят, не от его содержимого).
    facts["managed_via_telnet"] = node.vendor == Vendor.cisco_ios_telnet

    by_category: dict[str, list] = {}
    for rule in RULES:
        by_category.setdefault(rule.category, []).append(rule)

    categories: list[dict] = []
    category_scores: dict[str, int] = {}
    for category, rules in by_category.items():
        results = evaluate_rules(rules, facts)
        score = category_score(results)
        category_scores[category] = score
        categories.append({"name": category, "score": score, "rules": results})

    score = object_score(category_scores)
    return {
        "id": node.name,
        "node_id": node.id,
        "group_id": node.group_id,
        "vendor": node.vendor.value,
        "address": node.address,
        "scanned_at": backup.taken_at.isoformat(),
        "risk_score": score,
        "risk_band": risk_band(score),
        "categories": categories,
    }


def build_network_audit_fleet_report(db: Session) -> dict:
    nodes = db.query(Node).filter(Node.vendor.in_(_SUPPORTED_VENDORS), Node.active.is_(True)).all()
    devices: list[dict] = []
    skipped_no_backup: list[str] = []
    for node in nodes:
        backup = _latest_backup(db, node.id)
        if backup is None:
            skipped_no_backup.append(node.name)
            continue
        devices.append(build_node_report(node, backup))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog_version": CATALOG_VERSION,
        "catalog_updated_at": CATALOG_UPDATED_AT,
        "devices": devices,
        "skipped_no_backup": skipped_no_backup,
    }
