"""Планировщик опроса: один asyncio-цикл + мин-куча (next_run_at, probe_id).

Отличие от модели Zabbix (несколько форкнутых процессов-poller'ов, каждый
берёт задачи из общей очереди с блокировкой) — здесь один event loop и
куча: у каждого Probe свой next_run_at, обработчик спит до ближайшего
события, просыпается, выполняет ровно те проверки, чьё время настало, и
сразу планирует каждую заново на `interval_seconds` вперёд. Дешевле по
памяти на масштабе в десятки-сотни узлов и не требует IPC между процессами
— обратная сторона: всё в одном потоке, поэтому исполнители проверок
обязаны быть asyncio-нативными (см. probes.py), не блокирующими вызовами.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
import time

import httpx
from sqlalchemy.orm import Session

from app import actions_engine, signal as signal_module
from app.db import get_session
from app.escalation_engine import run_escalations
from app.models import Probe, ProbeKind, Sample, _now
from app.probes import run_probe
from app.rate_engine import apply_rate, previous_rate_sample
from app.retention_engine import run_retention
from app.vuln_scan_engine import run_due_vuln_schedules
from app.watch_engine import evaluate_probe

logger = logging.getLogger("gridforge.scheduler")


class Scheduler:
    def __init__(self) -> None:
        self._heap: list[tuple[float, int]] = []
        self._known_probe_ids: set[int] = set()
        self._stop = asyncio.Event()
        self._http_client: httpx.AsyncClient | None = None

    def _reload_probes(self, db: Session) -> None:
        now = time.monotonic()
        probes = db.query(Probe).filter(Probe.enabled.is_(True)).all()
        current_ids = {p.id for p in probes}
        for probe in probes:
            if probe.id not in self._known_probe_ids:
                heapq.heappush(self._heap, (now, probe.id))
                self._known_probe_ids.add(probe.id)
        # Отключённые/удалённые probe просто перестают попадать в
        # current_ids — их события в куче будут отфильтрованы при выходе
        # наверх (см. _run_due), явно вычищать из кучи не нужно.
        self._known_probe_ids &= current_ids

    async def _run_due(self) -> None:
        now = time.monotonic()
        while self._heap and self._heap[0][0] <= now:
            _due_at, probe_id = heapq.heappop(self._heap)
            db = get_session()
            try:
                probe = db.get(Probe, probe_id)
                if probe is None or not probe.enabled:
                    self._known_probe_ids.discard(probe_id)
                    continue
                outcome = await run_probe(probe.kind, probe.node.address, probe.params, probe.timeout_seconds)
                sample = Sample(probe_id=probe.id, ok=outcome.ok, value=outcome.value, detail=outcome.detail)
                if probe.kind is ProbeKind.snmp_counter_rate:
                    # Счётчик сам по себе не метрика — превращаем в скорость по
                    # предыдущему измерению (ищем его ДО добавления текущего).
                    sample.taken_at = sample.taken_at or _now()
                    apply_rate(previous_rate_sample(db, probe.id), sample, probe)
                db.add(sample)
                db.commit()
                db.refresh(sample)
                newly_opened = evaluate_probe(db, probe)
                if newly_opened:
                    if self._http_client is not None:
                        await signal_module.dispatch(self._http_client, db, newly_opened)
                    await actions_engine.dispatch(db, newly_opened)
                heapq.heappush(self._heap, (time.monotonic() + probe.interval_seconds, probe.id))
            except Exception:
                logger.exception("сбой опроса probe_id=%s", probe_id)
                heapq.heappush(self._heap, (time.monotonic() + 30, probe_id))
            finally:
                db.close()

    async def _run_due_vuln_schedules_safe(self) -> None:
        try:
            await run_due_vuln_schedules(get_session)
        except Exception:
            logger.exception("сбой планового запуска сканов уязвимостей")

    async def run_forever(
        self,
        reload_interval_seconds: float = 5.0,
        escalation_interval_seconds: float = 30.0,
        retention_interval_seconds: float = 24 * 3600,
        vuln_schedule_interval_seconds: float = 60.0,
    ) -> None:
        self._http_client = httpx.AsyncClient()
        try:
            last_reload = 0.0
            last_escalation_check = 0.0
            last_vuln_schedule_check = 0.0
            # Первая очистка — не сразу при старте, а через сутки работы:
            # перезапуск сервиса не должен каждый раз запускать удаление.
            last_retention = time.monotonic()
            while not self._stop.is_set():
                now = time.monotonic()
                if now - last_reload >= reload_interval_seconds:
                    db = get_session()
                    try:
                        self._reload_probes(db)
                    finally:
                        db.close()
                    last_reload = now
                if now - last_escalation_check >= escalation_interval_seconds:
                    db = get_session()
                    try:
                        await run_escalations(self._http_client, db)
                    except Exception:
                        logger.exception("сбой проверки эскалации")
                    finally:
                        db.close()
                    last_escalation_check = now
                if now - last_vuln_schedule_check >= vuln_schedule_interval_seconds:
                    # В фоне отдельной задачей, не await здесь: прогон всех
                    # профилей расписания может занять до ~40 минут (5
                    # профилей, full_ports/vuln по 900с каждый) — если ждать
                    # его прямо в этом цикле, всё это время встанет опрос
                    # Probe (куча/heap ждать не умеет, пока цикл занят).
                    asyncio.create_task(self._run_due_vuln_schedules_safe())
                    last_vuln_schedule_check = now
                if now - last_retention >= retention_interval_seconds:
                    db = get_session()
                    try:
                        run_retention(db)
                    except Exception:
                        logger.exception("сбой очистки истории")
                    finally:
                        db.close()
                    last_retention = now
                await self._run_due()
                sleep_for = 0.5
                if self._heap:
                    sleep_for = max(0.05, min(1.0, self._heap[0][0] - time.monotonic()))
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=sleep_for)
                except asyncio.TimeoutError:
                    pass
        finally:
            await self._http_client.aclose()
            self._http_client = None

    def stop(self) -> None:
        self._stop.set()
