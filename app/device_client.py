"""Единая точка подключения к устройству: SSH или Telnet.

Транспорт выбирается по вендору узла, а не задаётся вызывающим кодом.
Это важно: бэкапы, Рубка и снятие состояния портов должны одинаково
работать на всём парке, а решение «этот коммутатор только по Telnet»
принимается в одном месте. Иначе каждый вызывающий модуль пришлось бы
учить различать транспорт — и один из них рано или поздно забыли бы.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models import Vendor
from app.ssh_client import run_ssh_command
from app.telnet_client import DEFAULT_TELNET_PORT, run_telnet_command

# Вендоры, к которым ходим по Telnet. Узкий список, а не «всё, что не
# SSH»: по умолчанию должен быть защищённый транспорт, а Telnet —
# осознанное исключение для конкретного старого оборудования.
TELNET_VENDORS = {Vendor.cisco_ios_telnet}


@dataclass
class DeviceResult:
    ok: bool
    exit_status: int | None
    stdout: str
    error: str | None
    transport: str  # "ssh" | "telnet" — видно в интерфейсе и в журнале


def uses_telnet(vendor: Vendor | None) -> bool:
    return vendor in TELNET_VENDORS


def default_port(vendor: Vendor | None) -> int:
    return DEFAULT_TELNET_PORT if uses_telnet(vendor) else 22


async def run_device_command(
    *,
    vendor: Vendor | None,
    host: str,
    command: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int | None = None,
    timeout_seconds: float = 20.0,
    enable_password: str | None = None,
) -> DeviceResult:
    """Выполняет команду на устройстве подходящим транспортом."""
    if uses_telnet(vendor):
        result = await run_telnet_command(
            host=host,
            port=port or DEFAULT_TELNET_PORT,
            username=username,
            password=password,
            command=command,
            timeout_seconds=timeout_seconds,
            enable_password=enable_password,
        )
        return DeviceResult(result.ok, result.exit_status, result.stdout, result.error, "telnet")

    result = await run_ssh_command(
        host=host,
        port=port or 22,
        username=username,
        command=command,
        timeout_seconds=timeout_seconds,
        key_path=key_path,
        password=password,
    )
    return DeviceResult(result.ok, result.exit_status, result.stdout, result.error, "ssh")
