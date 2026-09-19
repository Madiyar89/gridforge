"""Оценка Watch-условий по свежим Sample. Вызывается сразу после записи
новой выборки конкретного Probe (см. scheduler.py) — не отдельным проходом
по всей базе, поэтому нет отдельного "trigger evaluation cycle" как у
Zabbix: оценка условий — прямое следствие прихода новой выборки."""

from __future__ import annotations

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import Incident, Probe, Sample, Watch, WatchOperator


def _condition_met(watch: Watch, sample: Sample) -> bool:
    if watch.operator == WatchOperator.probe_failed:
        return not sample.ok
    if not sample.ok or sample.value is None:
        return False
    if watch.threshold is None:
        return False
    if watch.operator == WatchOperator.gt:
        return sample.value > watch.threshold
    if watch.operator == WatchOperator.lt:
        return sample.value < watch.threshold
    if watch.operator == WatchOperator.eq:
        return sample.value == watch.threshold
    return False


def _recent_samples(db: Session, probe_id: int, limit: int) -> list[Sample]:
    return (
        db.query(Sample)
        .filter(Sample.probe_id == probe_id)
        .order_by(desc(Sample.taken_at))
        .limit(limit)
        .all()
    )


def _open_incident(db: Session, watch: Watch) -> Incident | None:
    return (
        db.query(Incident)
        .filter(Incident.watch_id == watch.id, Incident.resolved_at.is_(None))
        .first()
    )


def evaluate_probe(db: Session, probe: Probe) -> list[Incident]:
    """Возвращает вновь ОТКРЫТЫЕ на этом вызове Incident — вызывающий код
    (scheduler.py) использует их, чтобы разослать Signal (см. signal.py),
    не разбирая заново всю базу на "что нового"."""
    watches = db.query(Watch).filter(Watch.probe_id == probe.id).all()
    if not watches:
        return []
    newly_opened: list[Incident] = []
    for watch in watches:
        window = _recent_samples(db, probe.id, watch.streak_required)
        if len(window) < watch.streak_required:
            continue  # ещё не набрали нужную длину серии
        streak_matches = all(_condition_met(watch, s) for s in window)
        existing = _open_incident(db, watch)

        if streak_matches:
            if existing is not None:
                existing.last_seen_at = window[0].taken_at
                continue
            newest = window[0]
            reason = newest.detail or (str(newest.value) if newest.value is not None else "условие выполнено")
            incident = Incident(
                watch_id=watch.id,
                detail=f"{watch.label}: {reason}",
            )
            db.add(incident)
            db.flush()  # получить incident.id/opened_at до commit, для Signal
            newly_opened.append(incident)
        elif existing is not None:
            existing.resolved_at = window[0].taken_at
    db.commit()
    return newly_opened
