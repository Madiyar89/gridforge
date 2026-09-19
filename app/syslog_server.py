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
import os
import re

from app.db import get_session
from app.models import Node, SyslogMessage

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
            db.add(
                SyslogMessage(
                    node_id=node.id if node else None,
                    source_ip=source_ip,
                    facility=facility,
                    severity=severity,
                    message=message[:4000],
                )
            )
            db.commit()
        finally:
            db.close()


async def start_syslog_server(port: int = DEFAULT_SYSLOG_PORT) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        SyslogProtocol, local_addr=("0.0.0.0", port)
    )
    return transport
