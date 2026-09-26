"""Пороговые оповещения по объёму трафика узла (docs/landscape-report.md
§4.5, доработка 2026-09-26) — проверяется из scheduler.py по расписанию,
тот же принцип, что у остальных плановых проверок (vuln/cable/discovery
schedules): дёшево проверить (агрегатный запрос по FlowRecord), реальная
отправка — только если порог реально превышен и не был разослан в
пределах своего же окна (см. FlowAlertRule.last_triggered_at)."""

from __future__ import annotations

import logging
from datetime import timedelta

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import FlowAlertRule, FlowRecord, Node, _now, as_aware
from app.signal import notify_flow_alert

logger = logging.getLogger("gridforge.flow_alerts")


def _total_bytes_for_address(db: Session, address: str, window_minutes: int) -> int:
    """Трафик узла в обе стороны (источник + получатель) за окно — та же
    агрегация, что у /api/flows/top-talkers (main.py), просто на один
    конкретный адрес, не сгруппированная по всем сразу."""
    cutoff = _now() - timedelta(minutes=window_minutes)
    src_total = (
        db.query(func.coalesce(func.sum(FlowRecord.byte_count), 0))
        .filter(FlowRecord.src_addr == address, FlowRecord.received_at >= cutoff)
        .scalar()
    )
    dst_total = (
        db.query(func.coalesce(func.sum(FlowRecord.byte_count), 0))
        .filter(FlowRecord.dst_addr == address, FlowRecord.received_at >= cutoff)
        .scalar()
    )
    return int(src_total or 0) + int(dst_total or 0)


def _format_bytes(n: int) -> str:
    if n < 1024**2:
        return f"{n / 1024:.1f} КБ"
    if n < 1024**3:
        return f"{n / 1024**2:.1f} МБ"
    return f"{n / 1024**3:.2f} ГБ"


async def run_due_flow_alerts(http_client: httpx.AsyncClient, get_session) -> None:
    db = get_session()
    try:
        rules = db.query(FlowAlertRule).filter(FlowAlertRule.enabled.is_(True)).all()
        now = _now()
        for rule in rules:
            node = db.get(Node, rule.node_id)
            if node is None or not node.address:
                continue
            if rule.last_triggered_at is not None:
                elapsed = (now - as_aware(rule.last_triggered_at)).total_seconds() / 60
                if elapsed < rule.window_minutes:
                    continue  # уже оповещали в пределах своего окна — не дублируем на каждый тик
            total = _total_bytes_for_address(db, node.address, rule.window_minutes)
            if total < rule.bytes_threshold:
                continue
            message = (
                f"[ТРАФИК] {node.name}: {_format_bytes(total)} за последние {rule.window_minutes} мин "
                f"(порог «{rule.label}»: {_format_bytes(rule.bytes_threshold)})"
            )
            try:
                await notify_flow_alert(http_client, db, rule.channel_id, message)
            except Exception:
                logger.exception("сбой отправки оповещения по трафику (rule_id=%s)", rule.id)
            rule.last_triggered_at = now
            db.commit()
    finally:
        db.close()
