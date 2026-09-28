"""Приёмник NetFlow v9 по UDP (docs/landscape-report.md, п.4.5) — узкий
приёмник, не полный ntopng (без DPI/eBPF): только то, что нужно для
дашборда «топ говорящих» — src/dst-адрес, порты, протокол, байты/пакеты
за поток. sFlow и IPFIX сознательно не реализованы (другой формат
пакета) — начали с NetFlow v9, потому что его уже умеет отдавать
большинство Cisco 9300 в этом парке без дополнительных агентов (см.
landscape-report).

NetFlow v9, в отличие от v5, самоописывающийся: экспортёр сначала шлёт
Template FlowSet (какие поля и в каком порядке будут в потоках), потом
Data FlowSet со значениями по этому шаблону — тот же принцип, что у
Protocol Buffers (схема отдельно от данных). Шаблон должен быть получен
и закэширован ДО первого Data FlowSet с этим template_id — если Data
пришёл раньше Template (маршрутизатор долго не переотправлял шаблон),
поток молча пропускается, это не баг парсера, а свойство протокола.

Порт по умолчанию — 2055 (общепринятый для NetFlow, не 514/что-то
привилегированное — не требует root, тот же довод, что у syslog на 5140).

Батчинг + rate-limiting (доработка по итогам аудита, medium severity): один
UDP-пакет NetFlow обычно несёт МНОГО flow-записей сразу (Data FlowSet —
это уже естественный батч на уровне протокола), но раньше каждая запись
всё равно писалась через db.add()+один общий db.commit() НА ПАКЕТ — под
частым потоком пакетов от нескольких экспортёров это всё ещё много мелких
commit'ов. Теперь записи из всех пакетов буферизуются и сбрасываются одним
bulk-insert по размеру буфера или по таймеру (см. FlowBatcher,
_periodic_flush). RateLimiter — на уровне ПАКЕТОВ (не отдельных
flow-записей внутри пакета: экспортёр — не источник спуфинга в том же
смысле, что произвольный источник syslog, но exporter_ip в UDP всё равно
подделываем, поэтому та же защита нужна)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct
import time

from app.db import get_session
from app.models import FlowRecord, _now
from app.udp_flood_guard import RateLimiter

logger = logging.getLogger("gridforge.netflow")

DEFAULT_NETFLOW_PORT = int(os.environ.get("GRIDFORGE_NETFLOW_PORT", "2055"))

# Буфер flow-записей сбрасывается в БД при достижении NETFLOW_BATCH_SIZE
# записей ИЛИ каждые NETFLOW_BATCH_INTERVAL_SECONDS секунд — что раньше.
# Порог выше, чем у syslog (SYSLOG_BATCH_SIZE=200): один NetFlow-пакет уже
# сам по себе несёт до пары десятков записей, поэтому естественный размер
# батча на уровне протокола больше, чем у построчного syslog.
NETFLOW_BATCH_SIZE = int(os.environ.get("GRIDFORGE_NETFLOW_BATCH_SIZE", "500"))
NETFLOW_BATCH_INTERVAL_SECONDS = float(os.environ.get("GRIDFORGE_NETFLOW_BATCH_INTERVAL_SECONDS", "2"))

# Пороги rate-limiting считаются в ПАКЕТАХ/с (не в отдельных flow-записях
# внутри пакета — количество записей в пакете и так ограничено MTU).
# Парк из нескольких Cisco 9300, каждый экспортирует активные потоки раз в
# несколько секунд, реально шлёт единицы-десятки пакетов/с на экспортёр —
# 300/с на exporter_ip и 1000/с суммарно с большим запасом выше этого, но
# ограничивают то, что один (возможно, подделанный) источник может залить
# приёмник пакетами.
NETFLOW_RATE_LIMIT_PER_SOURCE = int(os.environ.get("GRIDFORGE_NETFLOW_RATE_LIMIT_PER_SOURCE", "300"))
NETFLOW_RATE_LIMIT_GLOBAL = int(os.environ.get("GRIDFORGE_NETFLOW_RATE_LIMIT_GLOBAL", "1000"))

# Field Type -> (имя, конвертер raw-bytes -> Python-значение). Только то,
# что реально используется дашбордом — остальные типы полей шаблона
# распознаются (знаем их длину из шаблона), но не декодируются.
IPV4_SRC_ADDR = 8
IPV4_DST_ADDR = 12
L4_SRC_PORT = 7
L4_DST_PORT = 11
PROTOCOL = 4
IN_BYTES = 1
IN_PKTS = 2
# TCP_FLAGS (RFC 3954 §8) — 1 байт, битовая маска (FIN=0x01, SYN=0x02,
# RST=0x04, PSH=0x08, ACK=0x10, URG=0x20). Нужен для отличения SYN-скана
# (только SYN, без ACK) от обычного TCP-соединения (см. flow_alerts_engine.py
# _detect_port_scans) — без этого поля детектор port-скана видит только
# число портов, не может отличить скан от, например, легитимного веб-краулера.
TCP_FLAGS = 6

_FIELD_DECODERS = {
    IPV4_SRC_ADDR: lambda b: ("src_addr", str(ipaddress.IPv4Address(b))),
    IPV4_DST_ADDR: lambda b: ("dst_addr", str(ipaddress.IPv4Address(b))),
    L4_SRC_PORT: lambda b: ("src_port", int.from_bytes(b, "big")),
    L4_DST_PORT: lambda b: ("dst_port", int.from_bytes(b, "big")),
    PROTOCOL: lambda b: ("protocol", int.from_bytes(b, "big")),
    IN_BYTES: lambda b: ("byte_count", int.from_bytes(b, "big")),
    IN_PKTS: lambda b: ("packet_count", int.from_bytes(b, "big")),
    TCP_FLAGS: lambda b: ("tcp_flags", int.from_bytes(b, "big")),
}

# Ключ — (exporter_ip, source_id, template_id): template_id назначается
# экспортёром произвольно и уникален только В ПРЕДЕЛАХ него самого — два
# разных коммутатора вполне могут использовать один и тот же номер под
# разные шаблоны.
TemplateKey = tuple[str, int, int]
# Шаблон — список (field_type, field_length) в порядке следования в Data FlowSet.
_templates: dict[TemplateKey, list[tuple[int, int]]] = {}
# Последний раз, когда ключ реально использовался (получен заново ИЛИ
# применён к Data FlowSet) — для purge_stale_templates (доработка
# 2026-09-26, "что мы можем улучшить"): без этого словарь растёт на весь
# аптайм процесса, даже если экспортёр давно выключен/переехал.
_template_last_seen: dict[TemplateKey, float] = {}


def purge_stale_templates(max_age_seconds: float = 24 * 3600) -> int:
    """Вызывается раз в сутки из retention_engine.run_retention() — тот же
    ритм, что у остальной очистки старых данных. Возвращает, сколько
    шаблонов убрано (для лога, тот же принцип, что у остальных счётчиков
    в run_retention)."""
    now = time.monotonic()
    stale = [k for k, last_seen in _template_last_seen.items() if now - last_seen > max_age_seconds]
    for key in stale:
        _templates.pop(key, None)
        _template_last_seen.pop(key, None)
    return len(stale)


def _parse_template_flowset(data: bytes, exporter_ip: str, source_id: int) -> None:
    offset = 0
    while offset + 4 <= len(data):
        template_id, field_count = struct.unpack_from(">HH", data, offset)
        offset += 4
        fields: list[tuple[int, int]] = []
        for _ in range(field_count):
            if offset + 4 > len(data):
                return  # обрезанный шаблон — не наш пакет, молча прекращаем разбор
            field_type, field_length = struct.unpack_from(">HH", data, offset)
            offset += 4
            fields.append((field_type, field_length))
        key = (exporter_ip, source_id, template_id)
        _templates[key] = fields
        _template_last_seen[key] = time.monotonic()


def _parse_data_flowset(
    data: bytes, template: list[tuple[int, int]], exporter_ip: str
) -> list[dict]:
    record_length = sum(length for _type, length in template)
    if record_length == 0:
        return []
    records = []
    offset = 0
    while offset + record_length <= len(data):
        record: dict = {"exporter_ip": exporter_ip}
        pos = offset
        for field_type, field_length in template:
            raw = data[pos : pos + field_length]
            decoder = _FIELD_DECODERS.get(field_type)
            if decoder is not None:
                try:
                    name, value = decoder(raw)
                    record[name] = value
                except (ValueError, struct.error):
                    pass  # неожиданная длина поля для этого типа — пропускаем именно его, не весь пакет
            pos += field_length
        offset += record_length
        # src_addr/dst_addr обязательны — без них запись бессмысленна для
        # дашборда «топ говорящих» (не топ портов/протоколов).
        if "src_addr" in record and "dst_addr" in record:
            records.append(record)
    return records


def _parse_packet(data: bytes, exporter_ip: str) -> list[dict]:
    if len(data) < 20:
        return []
    version, count, _uptime, _unix_secs, _seq, source_id = struct.unpack_from(">HHIIII", data, 0)
    if version != 9:
        return []  # v5/IPFIX/sFlow — не наш формат, молча игнорируем пакет
    offset = 20
    out: list[dict] = []
    for _ in range(count):
        if offset + 4 > len(data):
            break
        flowset_id, flowset_length = struct.unpack_from(">HH", data, offset)
        if flowset_length < 4 or offset + flowset_length > len(data):
            break  # повреждённый/обрезанный FlowSet — не наш пакет
        body = data[offset + 4 : offset + flowset_length]
        if flowset_id == 0:
            _parse_template_flowset(body, exporter_ip, source_id)
        elif flowset_id >= 256:
            key = (exporter_ip, source_id, flowset_id)
            template = _templates.get(key)
            if template is not None:
                _template_last_seen[key] = time.monotonic()
                out.extend(_parse_data_flowset(body, template, exporter_ip))
        # flowset_id == 1 (Options Template) — метаданные экспортёра, не
        # поток трафика, сознательно пропускается: дашборду не нужен.
        offset += flowset_length
    return out


class FlowBatcher:
    """Буфер flow-записей в памяти + сброс одним bulk-insert. Как и у
    SyslogBatcher — датаграммы обрабатываются синхронно в event loop, add()
    и периодический flush() никогда не пересекаются посреди друг друга."""

    def __init__(self, batch_size: int = NETFLOW_BATCH_SIZE) -> None:
        self._batch_size = batch_size
        self._buffer: list[dict] = []

    def __len__(self) -> int:
        return len(self._buffer)

    def add_many(self, records: list[dict]) -> None:
        for rec in records:
            self._buffer.append(
                {
                    "exporter_ip": rec["exporter_ip"],
                    "src_addr": rec["src_addr"],
                    "dst_addr": rec["dst_addr"],
                    "src_port": rec.get("src_port"),
                    "dst_port": rec.get("dst_port"),
                    "protocol": rec.get("protocol"),
                    "byte_count": rec.get("byte_count", 0),
                    "packet_count": rec.get("packet_count", 0),
                    "tcp_flags": rec.get("tcp_flags"),
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
            db.bulk_insert_mappings(FlowRecord, batch)
            db.commit()
        except Exception:
            logger.exception("сбой сохранения batch из %d flow-записей", len(batch))
        finally:
            db.close()


class NetflowProtocol(asyncio.DatagramProtocol):
    def __init__(self, batcher: FlowBatcher, rate_limiter: RateLimiter) -> None:
        self._batcher = batcher
        self._rate_limiter = rate_limiter

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # noqa: D102
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        exporter_ip = addr[0]
        if not self._rate_limiter.allow(exporter_ip):
            return
        try:
            records = _parse_packet(data, exporter_ip)
        except Exception:
            logger.exception("сбой разбора NetFlow-пакета от %s", exporter_ip)
            return
        if not records:
            return
        self._batcher.add_many(records)


async def _periodic_flush(batcher: FlowBatcher, stop: asyncio.Event, interval: float) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
        batcher.flush()
    batcher.flush()  # финальный сброс — не терять неполный batch на остановке


class NetflowServerHandle:
    """Оборачивает транспорт + фоновую задачу периодического flush —
    aclose() гарантирует, что последний неполный batch не потеряется при
    штатной остановке (см. lifespan() в app/main.py)."""

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        stop_event: asyncio.Event,
        flush_task: asyncio.Task,
        batcher: FlowBatcher,
    ) -> None:
        self.transport = transport
        self.batcher = batcher
        self._stop_event = stop_event
        self._flush_task = flush_task

    async def aclose(self) -> None:
        self.transport.close()
        self._stop_event.set()
        await self._flush_task


async def start_netflow_server(port: int = DEFAULT_NETFLOW_PORT) -> NetflowServerHandle:
    loop = asyncio.get_running_loop()
    batcher = FlowBatcher()
    rate_limiter = RateLimiter(
        per_source_limit=NETFLOW_RATE_LIMIT_PER_SOURCE,
        global_limit=NETFLOW_RATE_LIMIT_GLOBAL,
        logger=logger,
        label="netflow",
    )
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: NetflowProtocol(batcher, rate_limiter), local_addr=("0.0.0.0", port)
    )
    stop_event = asyncio.Event()
    flush_task = asyncio.create_task(_periodic_flush(batcher, stop_event, NETFLOW_BATCH_INTERVAL_SECONDS))
    return NetflowServerHandle(transport, stop_event, flush_task, batcher)
