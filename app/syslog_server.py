"""Приём Syslog по UDP — своя версия hub-syslog из NetOpsHub (там отдельный
контейнер; здесь — asyncio DatagramProtocol в том же процессе, что и
остальной GridForge, экономит ещё один процесс/порт на инструмент такого
масштаба).

Порт по умолчанию — 5140, не стандартный 514: последний требует root
(privileged port), GridForge работает под обычным пользователем.
Устройство нужно будет настроить слать именно на 5140 — задокументировано
в README, это сознательный компромисс, не забытая деталь."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass

import httpx

from app.db import get_session
from app.models import Node, SyslogMessage
from app.signal import notify_security_event

logger = logging.getLogger("gridforge.syslog")

DEFAULT_SYSLOG_PORT = int(os.environ.get("GRIDFORGE_SYSLOG_PORT", "5140"))

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


class SyslogProtocol(asyncio.DatagramProtocol):
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

        db = get_session()
        try:
            node = db.query(Node).filter(Node.address == source_ip).first()
            syslog_msg = SyslogMessage(
                node_id=node.id if node else None,
                source_ip=source_ip,
                facility=facility,
                severity=severity,
                message=message[:4000],
            )
            db.add(syslog_msg)
            db.commit()

            detected = _detect_security_event(message)
            if detected is not None:
                node_name = node.name if node else source_ip
                description = (
                    f"{detected.description_template.format(node=node_name)} "
                    f"(источник: SyslogMessage#{syslog_msg.id})"
                )
                node_id = node.id if node else None
                try:
                    asyncio.get_running_loop().create_task(
                        _dispatch_security_event(node_id, source_ip, description)
                    )
                except RuntimeError:
                    # Нет запущенного event loop (например, вызвано напрямую
                    # из синхронного теста) — рассылка молча пропускается,
                    # сам SyslogMessage уже сохранён и не теряется.
                    logger.warning(
                        "syslog: нет активного event loop, security-оповещение "
                        "не разослано (source_ip=%s)",
                        source_ip,
                    )
        finally:
            db.close()


async def _dispatch_security_event(node_id: int | None, source_ip: str, description: str) -> None:
    """Рассылка распознанного сработавшего защитного механизма на каналы —
    планируется как отдельная задача из datagram_received (сам приём UDP
    синхронный, `await` там невозможен). Собственная сессия БД и
    httpx.AsyncClient — этот код не разделяет ни с чем сессию, которой уже
    сохранил SyslogMessage (та закрыта до планирования задачи).

    Не заводит Incident: Incident в этом проекте жёстко привязан к Watch на
    Probe на Node (см. CLAUDE.md/gridforge-idioms) — периодической выборки,
    которая могла бы иметь такой Watch, для разового syslog-сообщения нет,
    а Incident.watch_id NOT NULL в схеме. Тот же обходной путь, что уже
    выбран в проекте для структурно похожих событий без Watch —
    signal.notify_new_devices()/notify_flow_alert()."""
    db = get_session()
    try:
        async with httpx.AsyncClient() as client:
            await notify_security_event(client, db, node_id, source_ip, description)
    except Exception:
        logger.exception(
            "syslog: не удалось разослать security-оповещение (source_ip=%s)", source_ip
        )
    finally:
        db.close()


async def start_syslog_server(port: int = DEFAULT_SYSLOG_PORT) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        SyslogProtocol, local_addr=("0.0.0.0", port)
    )
    return transport
