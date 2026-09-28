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
import os
import time

import httpx
from sqlalchemy.orm import Session

from app import actions_engine, signal as signal_module
from app.cable_discovery_engine import run_due_cable_discovery_schedules
from app.db import get_session
from app.escalation_engine import run_escalations
from app.geoip_engine import GeoipDownloadError, download_databases, needs_refresh
from app.integrations_engine import decrypt_token
from app.models import Incident, Integration, Probe, ProbeKind, Sample, _now
from app.sync_engine import push_snapshot, sync_enabled
from app.flow_alerts_engine import run_due_flow_alerts, run_due_flow_anomaly_detection
from app.probes import run_probe
from app.rate_engine import apply_rate, previous_rate_sample
from app.retention_engine import run_retention
from app.scan_engine import run_due_discovery_schedules
from app.vuln_scan_engine import run_due_vuln_schedules
from app.watch_engine import evaluate_probe

logger = logging.getLogger("gridforge.scheduler")


class Scheduler:
    def __init__(self) -> None:
        self._heap: list[tuple[float, int]] = []
        self._known_probe_ids: set[int] = set()
        self._stop = asyncio.Event()
        self._http_client: httpx.AsyncClient | None = None
        # Задачи dispatch() Action, запущенные в фоне (см. _run_due) —
        # отслеживаем, чтобы на остановке планировщика не бросить их
        # молча оборванными: ждём завершения (с таймаутом) в run_forever.
        self._action_tasks: set[asyncio.Task] = set()
        # Те же соображения — для плановых фоновых задач run_forever()
        # (vuln/cable/discovery-schedule, geoip-refresh, sync-push,
        # flow-alerts): раньше asyncio.create_task() для них вызывался
        # "выстрелил и забыл", без ссылки на задачу после создания — на
        # остановке планировщика (run_forever() возвращается) эти задачи
        # никак не отслеживались и не ожидались, то есть могли быть молча
        # оборваны вместе с event loop (см. задачу аудита — тот же класс
        # проблемы, что был у _action_tasks выше, до отдельного фикса).
        # Тот же паттерн: множество + add_done_callback для очистки +
        # asyncio.wait(...) с таймаутом на остановке в run_forever.
        self._periodic_tasks: set[asyncio.Task] = set()

    def _track_periodic(self, task: asyncio.Task) -> None:
        self._periodic_tasks.add(task)
        task.add_done_callback(self._periodic_tasks.discard)

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
                outcome = await run_probe(
                    probe.kind, probe.node.address, probe.params, probe.timeout_seconds, probe.node_id
                )
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
                    # Action может выполнять SSH-команду на устройстве —
                    # это может занять секунды (см. DEFAULT_ACTION_TIMEOUT_
                    # SECONDS в actions_engine.py). Раньше await здесь
                    # блокировал весь цикл: опрос ВСЕХ остальных узлов
                    # стоял, пока эта одна SSH-команда не завершится.
                    # Фоновая задача — тот же паттерн, что у vuln/cable/
                    # discovery/sync-report ниже в run_forever.
                    incident_ids = [incident.id for incident in newly_opened]
                    task = asyncio.create_task(self._dispatch_actions_safe(incident_ids))
                    self._action_tasks.add(task)
                    task.add_done_callback(self._action_tasks.discard)
                heapq.heappush(self._heap, (time.monotonic() + probe.interval_seconds, probe.id))
            except Exception:
                logger.exception("сбой опроса probe_id=%s", probe_id)
                heapq.heappush(self._heap, (time.monotonic() + 30, probe_id))
            finally:
                db.close()

    async def _dispatch_actions_safe(self, incident_ids: list[int]) -> None:
        """Отдельная db-сессия — objects из сессии _run_due закрываются
        (db.close() в её finally) раньше, чем эта фоновая задача успеет
        отработать, поэтому Incident перезагружаются по id здесь же, а не
        передаются как уже присоединённые к сессии ORM-объекты."""
        db = get_session()
        try:
            incidents = db.query(Incident).filter(Incident.id.in_(incident_ids)).all()
            await actions_engine.dispatch(db, incidents)
        except Exception:
            logger.exception("сбой выполнения Action по incident_ids=%s", incident_ids)
        finally:
            db.close()

    async def _run_due_vuln_schedules_safe(self) -> None:
        try:
            await run_due_vuln_schedules(get_session)
        except Exception:
            logger.exception("сбой планового запуска сканов уязвимостей")

    async def _run_due_cable_discovery_schedules_safe(self) -> None:
        try:
            await run_due_cable_discovery_schedules(get_session)
        except Exception:
            logger.exception("сбой планового автоопроса кабельных соединений")

    async def _run_due_discovery_schedules_safe(self) -> None:
        try:
            await run_due_discovery_schedules(get_session, self._http_client)
        except Exception:
            logger.exception("сбой планового скана новых устройств")

    async def _run_flow_alerts_safe(self) -> None:
        try:
            await run_due_flow_alerts(self._http_client, get_session)
        except Exception:
            logger.exception("сбой проверки порогов трафика")
        # Эвристики аномалий (port-scan/rogue DHCP/DHCP starvation/DNS) — не
        # настраиваются пользователем как FlowAlertRule, поэтому отдельного
        # интервала не заводим, проверяем на том же тике. Отдельный try —
        # сбой одной группы правил не должен глушить другую.
        try:
            await run_due_flow_anomaly_detection(self._http_client, get_session)
        except Exception:
            logger.exception("сбой проверки аномалий трафика (port-scan/DHCP/DNS)")

    async def _run_sync_push_safe(self) -> None:
        """Отправка отчёта на хаб (docs/landscape-report.md §4.10 шаг 2) —
        отсутствие сети/хаба не ошибка (переносной инстанс может быть
        офлайн большую часть времени), push_snapshot сама это тихо
        логирует и не бросает исключение наружу, но всё равно в try —
        защита от неожиданного сбоя сборки снимка (например, битые
        данные в БД)."""
        if not sync_enabled():
            return
        db = get_session()
        try:
            await push_snapshot(db)
        except Exception:
            logger.exception("сбой отправки отчёта на хаб")
        finally:
            db.close()

    async def _run_geoip_refresh_safe(self) -> None:
        """Проверка дешёвая (stat() двух файлов) — сама сеть только если
        база реально устарела (needs_refresh(), раз в ~7 дней) или её ещё
        нет. Без настроенной интеграции "maxmind" просто выходит — GeoIP
        опционален, отсутствие учётки не ошибка."""
        if not needs_refresh():
            return
        db = get_session()
        try:
            integration = db.query(Integration).filter(Integration.key == "maxmind").first()
            if integration is None:
                return
            account_id = integration.url
            license_key = decrypt_token(integration.api_token)
        finally:
            db.close()
        try:
            await download_databases(account_id, license_key)
        except GeoipDownloadError:
            logger.exception("сбой планового обновления баз GeoLite2")

    async def run_forever(
        self,
        reload_interval_seconds: float = 5.0,
        escalation_interval_seconds: float = 30.0,
        retention_interval_seconds: float = 24 * 3600,
        vuln_schedule_interval_seconds: float = 60.0,
        cable_schedule_interval_seconds: float = 60.0,
        discovery_schedule_interval_seconds: float = 60.0,
        geoip_refresh_interval_seconds: float = 3600.0,
        sync_push_interval_seconds: float = float(os.environ.get("GRIDFORGE_SYNC_INTERVAL_MIN", 15)) * 60,
        flow_alerts_interval_seconds: float = 60.0,
    ) -> None:
        self._http_client = httpx.AsyncClient()
        try:
            last_reload = 0.0
            last_escalation_check = 0.0
            last_vuln_schedule_check = 0.0
            last_cable_schedule_check = 0.0
            last_discovery_schedule_check = 0.0
            last_geoip_check = 0.0
            last_sync_push_check = 0.0
            last_flow_alerts_check = 0.0
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
                    self._track_periodic(asyncio.create_task(self._run_due_vuln_schedules_safe()))
                    last_vuln_schedule_check = now
                if now - last_cable_schedule_check >= cable_schedule_interval_seconds:
                    # Тоже в фоне отдельной задачей — CDP-опрос группы узлов
                    # по SSH не мгновенный, тот же довод, что у vuln-schedule.
                    self._track_periodic(asyncio.create_task(self._run_due_cable_discovery_schedules_safe()))
                    last_cable_schedule_check = now
                if now - last_discovery_schedule_check >= discovery_schedule_interval_seconds:
                    # Тоже фоновой задачей — скан диапазона может занять до
                    # SCAN_TIMEOUT_SECONDS (120с), тот же довод, что у
                    # vuln/cable-schedule.
                    self._track_periodic(asyncio.create_task(self._run_due_discovery_schedules_safe()))
                    last_discovery_schedule_check = now
                if now - last_geoip_check >= geoip_refresh_interval_seconds:
                    # Час — дёшево проверить (needs_refresh() почти всегда
                    # просто stat() двух файлов), реальное скачивание раз в
                    # ~7 дней, см. _run_geoip_refresh_safe.
                    self._track_periodic(asyncio.create_task(self._run_geoip_refresh_safe()))
                    last_geoip_check = now
                if now - last_sync_push_check >= sync_push_interval_seconds:
                    # Фоновой задачей — сетевой вызов на чужой хаб не должен
                    # задерживать опрос Probe, тот же довод, что у остальных
                    # плановых проверок выше.
                    self._track_periodic(asyncio.create_task(self._run_sync_push_safe()))
                    last_sync_push_check = now
                if now - last_flow_alerts_check >= flow_alerts_interval_seconds:
                    # Раз в минуту — дешёвый агрегатный запрос по FlowRecord
                    # на каждое включённое правило, реальная отправка только
                    # если порог превышен и не разослан в пределах своего
                    # окна (см. FlowAlertRule.last_triggered_at).
                    self._track_periodic(asyncio.create_task(self._run_flow_alerts_safe()))
                    last_flow_alerts_check = now
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
            if self._action_tasks:
                # Даём фоновым Action-задачам шанс дописать ActionRun перед
                # остановкой процесса: ждём с таймаутом, зависшие SSH-сессии
                # не должны бесконечно держать shutdown.
                await asyncio.wait(self._action_tasks, timeout=actions_engine.DEFAULT_ACTION_TIMEOUT_SECONDS + 5)
            await self._shutdown_periodic_tasks()
            await self._http_client.aclose()
            self._http_client = None

    async def _shutdown_periodic_tasks(self, grace_seconds: float = 5.0) -> None:
        """Останавливает плановые фоновые задачи (vuln/cable/discovery-
        schedule, geoip-refresh, sync-push, flow-alerts) — раньше они
        вообще нигде не отслеживались после asyncio.create_task() в
        run_forever() (см. _track_periodic в __init__). В отличие от
        Action (SSH-команда с известным ограниченным таймаутом,
        actions_engine.DEFAULT_ACTION_TIMEOUT_SECONDS), у этих задач нет
        общего верхнего предела — прогон всех профилей vuln-schedule
        может занять до ~40 минут (см. комментарий у
        vuln_schedule_interval_seconds в run_forever), а Docker всё равно
        не даёт больше ~10с грейс-периода на SIGTERM по умолчанию.
        Поэтому вместо долгого ожидания: короткое "дай доработать" окно,
        а всё, что не успело — явно cancel() + дожидаемся отмены, чтобы
        задачи не остались бесконтрольно висеть на закрывающемся event
        loop. _run_due_*_safe() ловят только `except Exception`, не
        `BaseException` — asyncio.CancelledError свободно долетает и
        останавливает задачу по cancel()."""
        if not self._periodic_tasks:
            return
        _, still_pending = await asyncio.wait(self._periodic_tasks, timeout=grace_seconds)
        for pending_task in still_pending:
            pending_task.cancel()
        if still_pending:
            await asyncio.gather(*still_pending, return_exceptions=True)

    def stop(self) -> None:
        self._stop.set()
