"""Многоступенчатая эскалация — если Incident остаётся открытым дольше
`EscalationStep.delay_minutes`, уходит повторное уведомление через канал
этого шага. Своя реализация, не копирует escalation в Zabbix (там —
привязка к Action и Operation с условиями, здесь — прямой список шагов
по задержке, применяется ко всем открытым Incident одинаково; сужение по
конкретному узлу/Watch/severity задаётся не на шаге, а на самом Channel,
см. signal.channel_matches_incident)."""

from __future__ import annotations

import logging

from datetime import timezone

import httpx
from sqlalchemy.orm import Session

from app.models import EscalationStep, Incident, _now
from app.signal import channel_matches_incident, format_message, send_to_channel

logger = logging.getLogger("gridforge.escalation")


def _aware(dt):
    # SQLite не хранит tzinfo нативно (в отличие от MySQL/MariaDB) — при
    # чтении обратно может вернуться naive datetime, хотя записывался
    # aware (UTC). Без этой нормализации вычитание "now - opened_at"
    # упало бы с TypeError именно на SQLite-варианте (fallback БД).
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def run_escalations(client: httpx.AsyncClient, db: Session) -> None:
    steps = (
        db.query(EscalationStep)
        .filter(EscalationStep.enabled.is_(True))
        .order_by(EscalationStep.delay_minutes)
        .all()
    )
    if not steps:
        return

    open_incidents = db.query(Incident).filter(Incident.resolved_at.is_(None)).all()
    if not open_incidents:
        return

    now = _now()
    for incident in open_incidents:
        elapsed_minutes = (now - _aware(incident.opened_at)).total_seconds() / 60
        fired_up_to = incident.last_escalated_minutes
        for step in steps:
            if step.delay_minutes <= fired_up_to:
                continue  # этот шаг для данного инцидента уже отправлен
            if elapsed_minutes < step.delay_minutes:
                break  # шаги упорядочены по delay_minutes — дальше все ещё рано

            channel = step.channel
            if channel is not None and channel.enabled and channel_matches_incident(channel, incident):
                message = format_message(incident, prefix=f"эскалация +{step.delay_minutes}м")
                await send_to_channel(client, channel, incident, message)
            fired_up_to = step.delay_minutes

        if fired_up_to != incident.last_escalated_minutes:
            incident.last_escalated_minutes = fired_up_to
    db.commit()
