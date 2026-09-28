"""Приём Syslog по UDP — своя версия hub-syslog из NetOpsHub (там отдельный
контейнер; здесь — asyncio DatagramProtocol в том же процессе, что и
остальной GridForge, экономит ещё один процесс/порт на инструмент такого
масштаба).

Порт по умолчанию — 5140, не стандартный 514: последний требует root
(privileged port), GridForge работает под обычным пользователем.
Устройство нужно будет настроить слать именно на 5140 — задокументировано
в README, это сознательный компромисс, не забытая деталь.

Батчинг + rate-limiting (доработка по итогам аудита, medium severity):
UDP source IP тривиально подделывается (нет handshake) — шумное/подделанное
устройство может залить приёмник датаграммами. Раньше был один db.commit()
на каждое сообщение — под потоком датаграмм это была основная стоимость.
Теперь сообщения буферизуются в памяти и сбрасываются в БД одним
bulk-insert либо по размеру буфера, либо по таймеру (см. SyslogBatcher,
_periodic_flush), а RateLimiter (app/udp_flood_guard.py) отбрасывает
датаграммы, если частота по source_ip или суммарно превышает порог —
не ставит их в очередь, не блокирует, просто не сохраняет."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass

import httpx

from app.db import get_session
from app.models import Node, SyslogMessage, _now
from app.signal import notify_security_event
from app.udp_flood_guard import RateLimiter

logger = logging.getLogger("gridforge.syslog")

DEFAULT_SYSLOG_PORT = int(os.environ.get("GRIDFORGE_SYSLOG_PORT", "5140"))

# Буфер сбрасывается в БД при достижении SYSLOG_BATCH_SIZE сообщений ИЛИ
# каждые SYSLOG_BATCH_INTERVAL_SECONDS секунд — что раньше. На масштабе
# проекта (десятки-сотни узлов) реальный поток syslog почти всегда
# намного меньше 100 сообщений/с, так что в норме буфер сбрасывается по
# таймеру (задержка публикации в БД — до ~2с, приемлемо для инструмента
# мониторинга, не для алертинга в реальном времени); переполнение буфера —
# сигнал вспышки (много устройств залогировали событие разом или начался
# флуд), там как раз важно НЕ копить по одному INSERT на строку.
SYSLOG_BATCH_SIZE = int(os.environ.get("GRIDFORGE_SYSLOG_BATCH_SIZE", "200"))
SYSLOG_BATCH_INTERVAL_SECONDS = float(os.environ.get("GRIDFORGE_SYSLOG_BATCH_INTERVAL_SECONDS", "2"))

# Пороги rate-limiting: даже заметно активное устройство (например,
# флаппающий линк с длинной серией логов) реально шлёт единицы-десятки
# сообщений в секунду, не сотни. 500/с на source_ip и 2000/с суммарно —
# с большим запасом выше нормальной нагрузки паркового масштаба GridForge
# (даже 200 узлов по 5 msg/с каждый = 1000/с суммарно, ниже глобального
# порога), но достаточно низко, чтобы UDP-флуд с одного/нескольких
# (подделанных) IP не заваливал приёмник и буфер бесконтрольно.
SYSLOG_RATE_LIMIT_PER_SOURCE = int(os.environ.get("GRIDFORGE_SYSLOG_RATE_LIMIT_PER_SOURCE", "500"))
SYSLOG_RATE_LIMIT_GLOBAL = int(os.environ.get("GRIDFORGE_SYSLOG_RATE_LIMIT_GLOBAL", "2000"))

_PRI_RE = re.compile(r"^<(\d{1,3})>")


def _parse_pri(raw: str) -> tuple[int | None, int | None, str]:
    """RFC3164/5424 PRI = facility*8 + severity, в треугольных скобках в
    начале сообщения. Если PRI нет (устройство шлёт "голый" текст) —
    facility/severity остаются None, само сообщение не теряется."""
    m = _PRI_RE.match(raw)
    if not m:
        return None, None, raw
    pri = int(m.group(1))
    facility, severity = divmod(pri, 8)
    return facility, severity, raw[m.end():].lstrip()


# Распознавание СРАБОТАВШИХ (не настроенных — за это отвечает
# app/network_audit_rules.py, правила L1/L7/L8) защитных механизмов Cisco
# IOS/IOS-XE по стандартному syslog message-ID (facility-severity-mnemonic,
# см. Cisco System Message Guide). Это дополнение к сохранению сырого
# текста (см. datagram_received ниже), не замена — SyslogMessage пишется
# всегда, независимо от того, распознано что-то тут или нет.
#
# Конкретные regex — точные строки из задания/реальных примеров, но
# достаточно гибкие на номер severity (`\d`) и суффикс мнемоники (`\w+`),
# чтобы не ловить только один вариант версии IOS.
_DAI_RE = re.compile(r"%SW_DAI-\d-\w+")
_DHCP_SNOOPING_RE = re.compile(r"%DHCP_SNOOPING-\d-\w+")
_PORT_SECURITY_RE = re.compile(r"%PORT_SECURITY-\d-PSECURE_VIOLATION")

# Общий вид любого Cisco message-ID — используется только для того, чтобы
# заметить и залогировать ПОХОЖИЕ на security-события, но ещё не попавшие
# в список выше (например DOT1X/MAB/STORM_CONTROL с другой станции Cisco,
# или другая мнемоника DAI/DHCP snooping) — задел на расширение списка,
# без выдумывания точных ID из головы.
_GENERIC_CISCO_MSGID_RE = re.compile(r"%([A-Z0-9_]+)-\d-([A-Z0-9_]+)")
_SECURITY_LOOKALIKE_KEYWORDS = (
    "DAI",
    "ARP_INSPECT",
    "DHCP_SNOOP",
    "PSECURE",
    "PORT_SECURITY",
    "DOT1X",
    "MAB",
    "STORM_CONTROL",
    "AUTHMGR",
    "SECURITY",
    "INTRUSION",
)


@dataclass
class DetectedSecurityEvent:
    kind: str
    # Шаблон на русском с плейсхолдером {node} — окончательное описание
    # (с привязкой к конкретному узлу и id SyslogMessage) собирается в
    # datagram_received, здесь только сам факт распознавания.
    description_template: str


def _detect_security_event(message: str) -> DetectedSecurityEvent | None:
    """Ищет в теле syslog-сообщения ID реально СРАБОТАВШЕГО защитного
    механизма (не факт его наличия в конфиге — за это app/network_audit_rules.py,
    правила L8/DAI, L7/DHCP snooping, L1/port-security). Возвращает None,
    если сообщение не про это — тогда датаграмма всё равно сохраняется как
    обычный SyslogMessage, ничего не теряется."""
    if _DAI_RE.search(message):
        return DetectedSecurityEvent(
            kind="dai_invalid_arp",
            description_template=(
                "Dynamic ARP Inspection заблокировала поддельный ARP-ответ на узле {node}."
            ),
        )
    if _DHCP_SNOOPING_RE.search(message):
        return DetectedSecurityEvent(
            kind="dhcp_snooping_deny",
            description_template=(
                "DHCP snooping заблокировал недоверенный (rogue) DHCP-ответ "
                "на нетрастованном порту узла {node}."
            ),
        )
    if _PORT_SECURITY_RE.search(message):
        return DetectedSecurityEvent(
            kind="port_security_violation",
            description_template=(
                "Port-security обнаружил неавторизованный MAC-адрес на порту узла {node}."
            ),
        )

    m = _GENERIC_CISCO_MSGID_RE.search(message)
    if m:
        facility, mnemonic = m.group(1), m.group(2)
        if any(kw in facility or kw in mnemonic for kw in _SECURITY_LOOKALIKE_KEYWORDS):
            logger.info(
                "syslog: похожее на security-событие message-ID не в списке "
                "распознаваемых — %%%s-N-%s, кандидат на расширение "
                "_detect_security_event()",
                facility,
                mnemonic,
            )
    return None


class SyslogBatcher:
    """Буфер сообщений в памяти + сброс одним bulk-insert. Датаграммы
    обрабатываются синхронно в event loop (datagram_received — не
    корутина, выполняется до конца без переключения контекста), поэтому
    добавление в буфер и периодический flush() никогда не пересекаются
    посреди друг друга — отдельная блокировка не нужна."""

    def __init__(self, batch_size: int = SYSLOG_BATCH_SIZE) -> None:
        self._batch_size = batch_size
        self._buffer: list[dict] = []

    def __len__(self) -> int:
        return len(self._buffer)

    def add(self, source_ip: str, facility: int | None, severity: int | None, message: str) -> None:
        self._buffer.append(
            {
                "source_ip": source_ip,
                "facility": facility,
                "severity": severity,
                "message": message[:4000],
                "received_at": _now(),
            }
        )
        if len(self._buffer) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return
        batch, self._buffer = self._buffer, []
        db = get_session()
        try:
            # node_id разрешается одним запросом на весь batch (IN по
            # source_ip), а не отдельным SELECT на каждое сообщение —
            # тот же принцип батчинга, что и для самого INSERT.
            source_ips = {row["source_ip"] for row in batch}
            node_map = dict(db.query(Node.address, Node.id).filter(Node.address.in_(source_ips)).all())
            for row in batch:
                row["node_id"] = node_map.get(row["source_ip"])
            db.bulk_insert_mappings(SyslogMessage, batch)
            db.commit()
        except Exception:
            logger.exception("сбой сохранения batch из %d syslog-сообщений", len(batch))
        finally:
            db.close()


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, batcher: SyslogBatcher, rate_limiter: RateLimiter) -> None:
        self._batcher = batcher
        self._rate_limiter = rate_limiter

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # noqa: D102
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]
        try:
            text = data.decode("utf-8", errors="replace").rstrip("\x00\r\n")
        except Exception:
            return
        if not text:
            return
        facility, severity, message = _parse_pri(text)

        # Детекция сработавших защитных механизмов идёт ДО rate-limiter'а
        # и не зависит от него: source_ip в UDP тривиально подделывается
        # (см. докстринг модуля), а значит флудом со спуфленным адресом
        # реального узла злоумышленник мог бы упереть его в
        # SYSLOG_RATE_LIMIT_PER_SOURCE и тем самым заглушить обнаружение
        # НАСТОЯЩИХ security-событий (DAI/DHCP snooping/port-security) от
        # этого узла — именно тогда, когда алертинг нужнее всего. Под
        # лимит попадает только объёмная запись обычных сообщений ниже.
        detected = _detect_security_event(message)
        if detected is not None:
            try:
                asyncio.get_running_loop().create_task(
                    _dispatch_security_event(source_ip, detected)
                )
            except RuntimeError:
                # Нет запущенного event loop (например, вызвано напрямую
                # из синхронного теста) — рассылка молча пропускается, сам
                # SyslogMessage всё равно попадёт в батч и не потеряется.
                logger.warning(
                    "syslog: нет активного event loop, security-оповещение "
                    "не разослано (source_ip=%s)",
                    source_ip,
                )

        if not self._rate_limiter.allow(source_ip):
            return
        self._batcher.add(source_ip, facility, severity, message)


async def _dispatch_security_event(source_ip: str, detected: DetectedSecurityEvent) -> None:
    """Рассылка распознанного сработавшего защитного механизма на каналы —
    планируется как отдельная задача из datagram_received (сам приём UDP
    синхронный, `await` там невозможен). Собственная сессия БД и
    httpx.AsyncClient. Узел ищется здесь же отдельным запросом (не через
    общий батч SyslogBatcher — тот пишет пачкой и с задержкой до
    SYSLOG_BATCH_INTERVAL_SECONDS, а security-событие редкое и должно уйти
    сразу, не дожидаясь следующего flush).

    Не заводит Incident: Incident в этом проекте жёстко привязан к Watch на
    Probe на Node (см. CLAUDE.md/gridforge-idioms) — периодической выборки,
    которая могла бы иметь такой Watch, для разового syslog-сообщения нет,
    а Incident.watch_id NOT NULL в схеме. Тот же обходной путь, что уже
    выбран в проекте для структурно похожих событий без Watch —
    signal.notify_new_devices()/notify_flow_alert()."""
    db = get_session()
    try:
        node = db.query(Node).filter(Node.address == source_ip).first()
        node_name = node.name if node else source_ip
        node_id = node.id if node else None
        description = detected.description_template.format(node=node_name)
        async with httpx.AsyncClient() as client:
            await notify_security_event(client, db, node_id, source_ip, description)
    except Exception:
        logger.exception(
            "syslog: не удалось разослать security-оповещение (source_ip=%s)", source_ip
        )
    finally:
        db.close()


async def _periodic_flush(batcher: SyslogBatcher, stop: asyncio.Event, interval: float) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
        batcher.flush()
    batcher.flush()  # финальный сброс — не терять неполный batch на остановке


class SyslogServerHandle:
    """Оборачивает транспорт + фоновую задачу периодического flush —
    aclose() гарантирует, что последний неполный batch не потеряется при
    штатной остановке (см. lifespan() в app/main.py)."""

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        stop_event: asyncio.Event,
        flush_task: asyncio.Task,
        batcher: SyslogBatcher,
    ) -> None:
        self.transport = transport
        self.batcher = batcher
        self._stop_event = stop_event
        self._flush_task = flush_task

    async def aclose(self) -> None:
        self.transport.close()
        self._stop_event.set()
        await self._flush_task


async def start_syslog_server(port: int = DEFAULT_SYSLOG_PORT) -> SyslogServerHandle:
    loop = asyncio.get_running_loop()
    batcher = SyslogBatcher()
    rate_limiter = RateLimiter(
        per_source_limit=SYSLOG_RATE_LIMIT_PER_SOURCE,
        global_limit=SYSLOG_RATE_LIMIT_GLOBAL,
        logger=logger,
        label="syslog",
    )
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(batcher, rate_limiter), local_addr=("0.0.0.0", port)
    )
    stop_event = asyncio.Event()
    flush_task = asyncio.create_task(_periodic_flush(batcher, stop_event, SYSLOG_BATCH_INTERVAL_SECONDS))
    return SyslogServerHandle(transport, stop_event, flush_task, batcher)
