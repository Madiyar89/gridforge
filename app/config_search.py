"""Grep по конфигам всех устройств разом — перенесено из NetOpsHub
(hub/backend/app/modules/reports/config_search.py).

Ищет только в САМОМ СВЕЖЕМ бэкапе каждого узла, не по всей истории —
иначе одна и та же строка, которая не менялась полгода, нашлась бы в
каждом историческом снимке разом. Простой substring-поиск (без regex) —
обычный grep, для этого объёма конфигов ничего экзотического не нужно."""

from __future__ import annotations

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import Backup, Node


def search_configs(db: Session, query: str, limit_matches: int = 300) -> list[dict]:
    query_lower = query.lower()
    results: list[dict] = []
    nodes = db.query(Node).filter(Node.active.is_(True)).all()
    for node in nodes:
        backup = (
            db.query(Backup)
            .filter(Backup.node_id == node.id, Backup.error.is_(None))
            .order_by(desc(Backup.taken_at))
            .first()
        )
        if backup is None:
            continue
        for line_number, line in enumerate(backup.content.splitlines(), start=1):
            if query_lower in line.lower():
                results.append(
                    {
                        "node_id": node.id,
                        "hostname": node.name,
                        "line_number": line_number,
                        "line": line.strip(),
                        "backup_taken_at": backup.taken_at,
                    }
                )
                if len(results) >= limit_matches:
                    return results
    return results
