"""Пороговые оповещения по объёму трафика узла (docs/landscape-report.md
§4.5, доработка 2026-09-26) — проверяется из scheduler.py по расписанию,
тот же принцип, что у остальных плановых проверок (vuln/cable/discovery
schedules): дёшево проверить (агрегатный запрос по FlowRecord), реальная
отправка — только если порог реально превышен и не был разослан в
пределах своего же окна (см. FlowAlertRule.last_triggered_at)."""

from __future__ import annotations

import logging
import os
import time
from datetime import timedelta

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import FlowAlertRule, FlowRecord, Group, Node, VulnScan, VulnScanStatus, _now, as_aware
from app.signal import notify_flow_alert, notify_flow_anomaly

logger = logging.getLogger("gridforge.flow_alerts")

# --- Эвристики аномалий трафика (доработка 2026-09-27, по итогам анализа
# devops-agent) — в отличие от FlowAlertRule (порог, настроенный вручную
# пользователем на конкретный узел/канал), эти правила проверяются для
# ВСЕХ FlowRecord за окно, без предварительной настройки: рассылка идёт
# через signal.notify_flow_anomaly() на все общие каналы (тот же охват,
# что у notify_new_devices — см. её докстринг).

# TCP (протокол 6) — порт-скан по определению происходит по TCP (SYN),
# UDP-скан NetFlow-эвристикой того же рода не ловится (нет handshake).
_TCP_PROTOCOL = 6
# RFC 3954 TCP_FLAGS: SYN без ACK/FIN/RST — характерная подпись SYN-скана
# (полное TCP-соединение всегда содержит и ACK).
_SYN_ONLY_FLAGS = 0x02
_SYN_MAJORITY_RATIO = 0.8  # доля SYN-only флоу в группе, дающая "высокую" уверенность

PORT_SCAN_WINDOW_MINUTES = 2
# Порог подобран консервативно: обычный веб-браузер/клиент бьёт в 1-3 порта
# на dst за пару минут, но легитимный health-check/мониторинг (сам GridForge
# в том числе) может обратиться к паре десятков портов одного узла при
# первичном discovery — 15 разных портов с одного src на один dst за 2
# минуты уже заметно выделяется на этом фоне, не задевая обычный трафик.
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 15

DHCP_SERVER_PORT = 67
DHCP_WINDOW_MINUTES = 2
# DHCP DISCOVER-флуд (starvation) — десятки/сотни запросов за минуты с
# одного источника, легитимный клиент шлёт единицы (DISCOVER/REQUEST при
# получении или продлении аренды) — порог с большим запасом от нормы.
DHCP_STARVATION_FLOW_THRESHOLD = 20

DNS_ANOMALY_WINDOW_MINUTES = 5
_UDP_PROTOCOL = 17
DNS_PORT = 53
# Слабый сигнал (см. итоговое сообщение — маркируется тем же "unknown",
# что и самый неуверенный уровень VulnScanHost.findings[].severity,
# app/vuln_scan_engine.py) — NetFlow не видит содержимое DNS-запроса,
# только то, что src обратился к необычно большому числу разных
# резолверов/адресов на 53/UDP за окно.
DNS_ANOMALY_DISTINCT_DST_THRESHOLD = 30

# Доверенные DHCP-серверы (легитимная инфраструктура) — своего поля/тега
# на Node для этого в модели ещё нет, поэтому простой allow-list через
# переменную окружения, тот же стиль, что GRIDFORGE_NETFLOW_PORT
# (app/netflow_server.py): список IP через запятую.
_TRUSTED_DHCP_SERVERS = {
    ip.strip()
    for ip in os.environ.get("GRIDFORGE_TRUSTED_DHCP_SERVERS", "").split(",")
    if ip.strip()
}

# Cooldown в памяти процесса (не в БД — эти находки не настраиваются
# пользователем, отдельной таблицы под них заводить незачем), тот же
# принцип, что у _template_last_seen в netflow_server.py: без него один и
# тот же продолжающийся скан/шторм рассылался бы на каждый тик планировщика
# (раз в минуту). Переживает рестарт плохо (после рестарта cooldown
# сбрасывается) — приемлемо, рестарты сервиса не ежеминутные.
_ANOMALY_ALERT_COOLDOWN_SECONDS = 15 * 60
_port_scan_last_alerted: dict[tuple[str, str], float] = {}
_rogue_dhcp_last_alerted: dict[str, float] = {}
_dhcp_starvation_last_alerted: dict[str, float] = {}
_dns_anomaly_last_alerted: dict[str, float] = {}


def _cooldown_ok(cache: dict, key, now_monotonic: float) -> bool:
    last = cache.get(key)
    if last is not None and now_monotonic - last < _ANOMALY_ALERT_COOLDOWN_SECONDS:
        return False
    cache[key] = now_monotonic
    return True


def _is_vuln_scan_target(db: Session, address: str, now) -> bool:
    """Whitelist собственных плановых сканов GridForge (Nuclei/nmap, см.
    app/vuln_scan_engine.py) — они дают ровно тот же паттерн (один источник
    бьёт по многим портам одного адреса за короткое время), что и реальный
    port-scan. Активный (status=running) ИЛИ недавно завершившийся (в
    пределах 10 минут — не мгновенно после finished_at, отчёт/дозапись
    findings может занять ещё немного времени) скан на группу, в которую
    входит этот адрес как узел — значит, это, вероятнее всего, наш
    собственный скан, не алертим."""
    cutoff = now - timedelta(minutes=10)
    scans = (
        db.query(VulnScan)
        .filter(
            (VulnScan.status == VulnScanStatus.running)
            | (VulnScan.finished_at.isnot(None) & (VulnScan.finished_at >= cutoff))
        )
        .all()
    )
    if not scans:
        return False
    group_ids = {scan.group_id for scan in scans}
    groups = db.query(Group).filter(Group.id.in_(group_ids)).all()
    for group in groups:
        if any(n.address == address for n in group.nodes):
            return True
    return False


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


def _detect_port_scans(db: Session, now) -> list[dict]:
    """Группировка FlowRecord за короткое окно по (src_addr, dst_addr),
    COUNT(DISTINCT dst_port) — много разных портов одного назначения с
    одного источника за пару минут похоже на TCP SYN-скан (nmap/masscan
    и т.п. перебирают порты именно так). Использует TCP_FLAGS (когда
    декодирован) для усиления/ослабления уверенности: SYN без ACK/FIN у
    подавляющего большинства флоу в группе — характерная подпись именно
    SYN-скана (полноценное соединение всегда содержит ACK), тогда как
    отсутствие данных о флагах (старый экспортёр, шаблон без TCP_FLAGS)
    оставляет решение на голой эвристике по числу портов — умеренная
    уверенность, не высокая."""
    cutoff = now - timedelta(minutes=PORT_SCAN_WINDOW_MINUTES)
    groups = (
        db.query(
            FlowRecord.src_addr,
            FlowRecord.dst_addr,
            func.count(func.distinct(FlowRecord.dst_port)).label("distinct_ports"),
        )
        .filter(FlowRecord.received_at >= cutoff, FlowRecord.protocol == _TCP_PROTOCOL)
        .group_by(FlowRecord.src_addr, FlowRecord.dst_addr)
        .having(func.count(func.distinct(FlowRecord.dst_port)) >= PORT_SCAN_DISTINCT_PORTS_THRESHOLD)
        .all()
    )
    findings = []
    for src_addr, dst_addr, distinct_ports in groups:
        flags = [
            f
            for (f,) in db.query(FlowRecord.tcp_flags)
            .filter(
                FlowRecord.received_at >= cutoff,
                FlowRecord.src_addr == src_addr,
                FlowRecord.dst_addr == dst_addr,
                FlowRecord.protocol == _TCP_PROTOCOL,
            )
            .all()
            if f is not None
        ]
        if flags:
            syn_only_ratio = sum(1 for f in flags if f == _SYN_ONLY_FLAGS) / len(flags)
            confidence = "высокая" if syn_only_ratio >= _SYN_MAJORITY_RATIO else "умеренная"
        else:
            confidence = "умеренная"  # TCP_FLAGS не декодированы для этих флоу
        findings.append(
            {
                "src_addr": src_addr,
                "dst_addr": dst_addr,
                "distinct_ports": distinct_ports,
                "confidence": confidence,
            }
        )
    return findings


def _detect_rogue_dhcp_servers(db: Session, now) -> list[str]:
    """src_port=67 — отвечает DHCP-сервер (клиент шлёт на 67, отвечает С
    порта 67 на 68). Любой такой src вне allow-list (GRIDFORGE_TRUSTED_DHCP_SERVERS)
    — потенциальный rogue DHCP (Cisco DAI/DHCP snooping в парке есть не
    везде, отсюда ценность даже такой простой эвристики)."""
    cutoff = now - timedelta(minutes=DHCP_WINDOW_MINUTES)
    rows = (
        db.query(FlowRecord.src_addr)
        .filter(FlowRecord.received_at >= cutoff, FlowRecord.src_port == DHCP_SERVER_PORT)
        .distinct()
        .all()
    )
    return [addr for (addr,) in rows if addr not in _TRUSTED_DHCP_SERVERS]


def _detect_dhcp_starvation(db: Session, now) -> list[tuple[str, int]]:
    """dst_port=67 — клиент обращается к DHCP-серверу. Аномальный всплеск
    отдельных флоу с одного источника за короткое окно — возможная
    DHCP-starvation атака (шквал DISCOVER с разными поддельными MAC,
    исчерпывающий пул адресов легитимного сервера)."""
    cutoff = now - timedelta(minutes=DHCP_WINDOW_MINUTES)
    return (
        db.query(FlowRecord.src_addr, func.count(FlowRecord.id).label("flow_count"))
        .filter(FlowRecord.received_at >= cutoff, FlowRecord.dst_port == DHCP_SERVER_PORT)
        .group_by(FlowRecord.src_addr)
        .having(func.count(FlowRecord.id) >= DHCP_STARVATION_FLOW_THRESHOLD)
        .all()
    )


def _detect_dns_anomalies(db: Session, now) -> list[tuple[str, int]]:
    """Аномально много РАЗНЫХ dst_addr на 53/UDP с одного src за окно —
    потенциальный обход корпоративного резолвера (прямые запросы во
    внешние DNS вместо внутреннего). ЗАВЕДОМО СЛАБЫЙ сигнал — NetFlow не
    видит содержимое пакета, не отличит это от, например, легитимного
    инструмента диагностики DNS с массовым списком серверов. Помечается
    в сообщении тем же "unknown" — самым неуверенным уровнем трёхступенчатой
    шкалы VulnScanHost.findings[].severity (app/vuln_scan_engine.py) — не
    выдаётся за подтверждённый DNS-туннелинг/обход."""
    cutoff = now - timedelta(minutes=DNS_ANOMALY_WINDOW_MINUTES)
    return (
        db.query(FlowRecord.src_addr, func.count(func.distinct(FlowRecord.dst_addr)).label("distinct_dst"))
        .filter(
            FlowRecord.received_at >= cutoff,
            FlowRecord.dst_port == DNS_PORT,
            FlowRecord.protocol == _UDP_PROTOCOL,
        )
        .group_by(FlowRecord.src_addr)
        .having(func.count(func.distinct(FlowRecord.dst_addr)) >= DNS_ANOMALY_DISTINCT_DST_THRESHOLD)
        .all()
    )


async def run_due_flow_anomaly_detection(http_client: httpx.AsyncClient, get_session) -> None:
    """Проверяется из Scheduler.run_forever() на том же тике, что и
    run_due_flow_alerts (см. _run_flow_alerts_safe, app/scheduler.py) —
    не настраивается пользователем (в отличие от FlowAlertRule), поэтому
    не нужен отдельный интервал/расписание в БД, читает FlowRecord целиком
    за соответствующее окно на каждый тик."""
    db = get_session()
    try:
        now = _now()
        now_monotonic = time.monotonic()

        for finding in _detect_port_scans(db, now):
            src_addr, dst_addr = finding["src_addr"], finding["dst_addr"]
            if _is_vuln_scan_target(db, dst_addr, now) or _is_vuln_scan_target(db, src_addr, now):
                continue  # похоже на собственный плановый Nuclei/nmap-скан GridForge — не алертим
            if not _cooldown_ok(_port_scan_last_alerted, (src_addr, dst_addr), now_monotonic):
                continue
            message = (
                f"[PORT-SCAN] {src_addr} -> {dst_addr}: {finding['distinct_ports']} разных портов "
                f"за {PORT_SCAN_WINDOW_MINUTES} мин (уверенность: {finding['confidence']}, "
                f"признак SYN-скана по TCP_FLAGS учтён)"
            )
            try:
                await notify_flow_anomaly(http_client, db, message)
            except Exception:
                logger.exception("сбой отправки оповещения о port-scan (%s -> %s)", src_addr, dst_addr)

        for src_addr in _detect_rogue_dhcp_servers(db, now):
            if not _cooldown_ok(_rogue_dhcp_last_alerted, src_addr, now_monotonic):
                continue
            message = (
                f"[ROGUE DHCP] {src_addr} отвечает с порта {DHCP_SERVER_PORT} (DHCP-сервер), "
                f"не входит в доверенный список (GRIDFORGE_TRUSTED_DHCP_SERVERS)"
            )
            try:
                await notify_flow_anomaly(http_client, db, message)
            except Exception:
                logger.exception("сбой отправки оповещения о rogue DHCP (%s)", src_addr)

        for src_addr, flow_count in _detect_dhcp_starvation(db, now):
            if not _cooldown_ok(_dhcp_starvation_last_alerted, src_addr, now_monotonic):
                continue
            message = (
                f"[DHCP STARVATION?] {src_addr}: {flow_count} обращений к порту "
                f"{DHCP_SERVER_PORT} за {DHCP_WINDOW_MINUTES} мин — возможная попытка "
                f"исчерпать пул адресов легитимного DHCP-сервера"
            )
            try:
                await notify_flow_anomaly(http_client, db, message)
            except Exception:
                logger.exception("сбой отправки оповещения о DHCP starvation (%s)", src_addr)

        for src_addr, distinct_dst in _detect_dns_anomalies(db, now):
            if not _cooldown_ok(_dns_anomaly_last_alerted, src_addr, now_monotonic):
                continue
            message = (
                f"[DNS АНОМАЛИЯ] (уверенность: unknown — слабый сигнал, NetFlow не видит "
                f"содержимое запроса) {src_addr} обратился к {distinct_dst} разным адресам "
                f"на порт {DNS_PORT}/UDP за {DNS_ANOMALY_WINDOW_MINUTES} мин — возможный обход "
                f"корпоративного DNS-резолвера, НЕ подтверждённый DNS-туннелинг"
            )
            try:
                await notify_flow_anomaly(http_client, db, message)
            except Exception:
                logger.exception("сбой отправки оповещения о DNS-аномалии (%s)", src_addr)
    finally:
        db.close()
