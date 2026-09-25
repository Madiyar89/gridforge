"""Sync Node, шаг 2 из 5 (docs/landscape-report.md, §4.10) — автоматическая
отправка сводки с удалённой площадки на хаб, когда у площадки есть сеть.
Реальный сценарий владельца (2026-09-25): переносной инстанс GridForge на
флешке (сеть появляется не на каждом выезде) + постоянный в корпоративной
сети — площадка сама звонит на хаб, хабу для этого не нужно её видеть
(входящих портов на переносном инстансе не требуется).

Один и тот же код (`app/main.py`) исполняет ОБЕ роли одновременно — и
хаб (принимает отчёты от других площадок через `/api/sync/report`), и
площадку (шлёт свой отчёт на чужой хаб, если настроен). Ничто не мешает
инстансу быть хабом для одних и площадкой для другого — просто в этом
шаге ни у кого пока нет причины так делать.

Роль площадки настраивается переменными окружения (тот же принцип, что у
AD/OIDC — параметр развёртывания, не то, что меняют из интерфейса):

  GRIDFORGE_SYNC_HUB_URL        базовый адрес хаба, например http://192.168.1.10:8100
  GRIDFORGE_SYNC_TOKEN          токен площадки, выданный хабом при её регистрации
  GRIDFORGE_SYNC_LABEL          как площадка называет себя в отчёте (для лога хаба)
  GRIDFORGE_SYNC_INTERVAL_MIN   как часто пробовать отправить (по умолчанию 15 минут)
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets

import httpx
from sqlalchemy.orm import Session

from app.models import Incident, Node, RemoteSite, RemoteSiteReport, WatchSeverity, iso

logger = logging.getLogger("gridforge.sync")

MAX_INCIDENTS_IN_REPORT = 50


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# --- Сторона хаба: регистрация площадок и приём отчётов -------------------


def create_site(db: Session, label: str) -> tuple[RemoteSite, str]:
    """Возвращает (площадка, сырой токен) — токен показывается вызывающей
    стороне ровно один раз, в БД остаётся только хеш (тот же паттерн, что
    у ApiKey.generate_key в auth.py)."""
    raw_token = secrets.token_urlsafe(32)
    site = RemoteSite(label=label, token_hash=_hash_token(raw_token))
    db.add(site)
    db.commit()
    db.refresh(site)
    return site, raw_token


def resolve_site(db: Session, raw_token: str | None) -> RemoteSite | None:
    if not raw_token:
        return None
    return db.query(RemoteSite).filter(RemoteSite.token_hash == _hash_token(raw_token)).first()


def record_report(db: Session, site: RemoteSite, payload: dict) -> RemoteSiteReport:
    report = RemoteSiteReport(
        site_id=site.id,
        node_count=int(payload.get("node_count", 0)),
        incidents_critical=int(payload.get("incidents_critical", 0)),
        incidents_warning=int(payload.get("incidents_warning", 0)),
        incidents_info=int(payload.get("incidents_info", 0)),
        incidents=payload.get("incidents", [])[:MAX_INCIDENTS_IN_REPORT],
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def latest_reports(db: Session) -> list[dict]:
    """Последний снимок по каждой площадке — для GET /api/sync/sites.
    Площадка без единого отчёта тоже показывается (не "ещё не звонила"
    молча, а видно, что зарегистрирована, но тишина)."""
    sites = db.query(RemoteSite).order_by(RemoteSite.label).all()
    out = []
    for site in sites:
        latest = (
            db.query(RemoteSiteReport)
            .filter(RemoteSiteReport.site_id == site.id)
            .order_by(RemoteSiteReport.received_at.desc())
            .first()
        )
        out.append(
            {
                "id": site.id,
                "label": site.label,
                "created_at": iso(site.created_at),
                "last_report": None
                if latest is None
                else {
                    "received_at": iso(latest.received_at),
                    "node_count": latest.node_count,
                    "incidents_critical": latest.incidents_critical,
                    "incidents_warning": latest.incidents_warning,
                    "incidents_info": latest.incidents_info,
                    "incidents": latest.incidents,
                },
            }
        )
    return out


# --- Сторона площадки: сборка своего снимка и отправка на хаб -------------


def sync_enabled() -> bool:
    return bool(os.environ.get("GRIDFORGE_SYNC_HUB_URL") and os.environ.get("GRIDFORGE_SYNC_TOKEN"))


def build_snapshot(db: Session) -> dict:
    node_count = db.query(Node).filter(Node.active.is_(True)).count()
    open_incidents = db.query(Incident).filter(Incident.resolved_at.is_(None)).all()
    by_severity = {WatchSeverity.critical: 0, WatchSeverity.warning: 0, WatchSeverity.info: 0}
    incidents_out = []
    for inc in open_incidents:
        severity = inc.watch.severity
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if len(incidents_out) < MAX_INCIDENTS_IN_REPORT:
            incidents_out.append(
                {
                    "node": inc.watch.probe.node.name,
                    "watch_label": inc.watch.label,
                    "severity": severity.value,
                    "opened_at": iso(inc.opened_at),
                }
            )
    return {
        "label": os.environ.get("GRIDFORGE_SYNC_LABEL") or "площадка без имени",
        "node_count": node_count,
        "incidents_critical": by_severity.get(WatchSeverity.critical, 0),
        "incidents_warning": by_severity.get(WatchSeverity.warning, 0),
        "incidents_info": by_severity.get(WatchSeverity.info, 0),
        "incidents": incidents_out,
    }


async def push_snapshot(db: Session) -> None:
    """Разовая попытка отправки — вызывается из scheduler.py по расписанию.
    Отсутствие сети — не ошибка приложения, а нормальное состояние
    переносного инстанса: тихо логируем и ждём следующего интервала, не
    роняем остальную работу планировщика."""
    if not sync_enabled():
        return
    hub_url = os.environ["GRIDFORGE_SYNC_HUB_URL"].rstrip("/")
    token = os.environ["GRIDFORGE_SYNC_TOKEN"]
    snapshot = build_snapshot(db)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.post(
                f"{hub_url}/api/sync/report", json=snapshot, headers={"X-Sync-Token": token}
            )
            res.raise_for_status()
        logger.info("отчёт площадки отправлен на хаб (%s)", hub_url)
    except httpx.HTTPError as exc:
        logger.info("не удалось отправить отчёт на хаб (%s) — нет сети или хаб недоступен: %s", hub_url, exc)
