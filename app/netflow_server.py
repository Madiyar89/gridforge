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
привилегированное — не требует root, тот же довод, что у syslog на 5140)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct

from app.db import get_session
from app.models import FlowRecord

logger = logging.getLogger("gridforge.netflow")

DEFAULT_NETFLOW_PORT = int(os.environ.get("GRIDFORGE_NETFLOW_PORT", "2055"))

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

_FIELD_DECODERS = {
    IPV4_SRC_ADDR: lambda b: ("src_addr", str(ipaddress.IPv4Address(b))),
    IPV4_DST_ADDR: lambda b: ("dst_addr", str(ipaddress.IPv4Address(b))),
    L4_SRC_PORT: lambda b: ("src_port", int.from_bytes(b, "big")),
    L4_DST_PORT: lambda b: ("dst_port", int.from_bytes(b, "big")),
    PROTOCOL: lambda b: ("protocol", int.from_bytes(b, "big")),
    IN_BYTES: lambda b: ("byte_count", int.from_bytes(b, "big")),
    IN_PKTS: lambda b: ("packet_count", int.from_bytes(b, "big")),
}

# Ключ — (exporter_ip, source_id, template_id): template_id назначается
# экспортёром произвольно и уникален только В ПРЕДЕЛАХ него самого — два
# разных коммутатора вполне могут использовать один и тот же номер под
# разные шаблоны.
TemplateKey = tuple[str, int, int]
# Шаблон — список (field_type, field_length) в порядке следования в Data FlowSet.
_templates: dict[TemplateKey, list[tuple[int, int]]] = {}


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
        _templates[(exporter_ip, source_id, template_id)] = fields


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
            template = _templates.get((exporter_ip, source_id, flowset_id))
            if template is not None:
                out.extend(_parse_data_flowset(body, template, exporter_ip))
        # flowset_id == 1 (Options Template) — метаданные экспортёра, не
        # поток трафика, сознательно пропускается: дашборду не нужен.
        offset += flowset_length
    return out


class NetflowProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # noqa: D102
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        exporter_ip = addr[0]
        try:
            records = _parse_packet(data, exporter_ip)
        except Exception:
            logger.exception("сбой разбора NetFlow-пакета от %s", exporter_ip)
            return
        if not records:
            return
        db = get_session()
        try:
            for rec in records:
                db.add(
                    FlowRecord(
                        exporter_ip=rec["exporter_ip"],
                        src_addr=rec["src_addr"],
                        dst_addr=rec["dst_addr"],
                        src_port=rec.get("src_port"),
                        dst_port=rec.get("dst_port"),
                        protocol=rec.get("protocol"),
                        byte_count=rec.get("byte_count", 0),
                        packet_count=rec.get("packet_count", 0),
                    )
                )
            db.commit()
        finally:
            db.close()


async def start_netflow_server(port: int = DEFAULT_NETFLOW_PORT) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        NetflowProtocol, local_addr=("0.0.0.0", port)
    )
    return transport
