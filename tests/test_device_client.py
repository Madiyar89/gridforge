"""Выбор транспорта по вендору узла.

Развилка «SSH или Telnet» живёт в одном месте намеренно: бэкапы, Рубка и
снятие состояния портов должны одинаково работать на всём парке. Если бы
каждый из них решал сам, один рано или поздно забыли бы — и часть
устройств молча выпала бы из инструмента.
"""

import asyncio

import pytest

from app.device_client import TELNET_VENDORS, default_port, run_device_command, uses_telnet
from app.models import Vendor


def test_only_listed_vendors_use_telnet():
    """Белый список, а не «всё, что не SSH»: по умолчанию должен быть
    защищённый транспорт, Telnet — осознанное исключение."""
    assert uses_telnet(Vendor.cisco_ios_telnet) is True
    assert uses_telnet(Vendor.cisco_ios) is False
    assert uses_telnet(Vendor.junos) is False
    assert uses_telnet(Vendor.generic) is False
    assert uses_telnet(None) is False
    assert TELNET_VENDORS == {Vendor.cisco_ios_telnet}


def test_default_port_matches_transport():
    assert default_port(Vendor.cisco_ios_telnet) == 23
    assert default_port(Vendor.cisco_ios) == 22
    assert default_port(None) == 22


def test_telnet_vendor_goes_through_telnet(monkeypatch):
    calls = {}

    async def fake_telnet(**kwargs):
        calls["telnet"] = kwargs
        from app.telnet_client import TelnetResult

        return TelnetResult(True, 0, "вывод", None)

    async def fake_ssh(**kwargs):
        calls["ssh"] = kwargs
        raise AssertionError("для Telnet-вендора SSH использоваться не должен")

    monkeypatch.setattr("app.device_client.run_telnet_command", fake_telnet)
    monkeypatch.setattr("app.device_client.run_ssh_command", fake_ssh)

    result = asyncio.run(
        run_device_command(
            vendor=Vendor.cisco_ios_telnet,
            host="10.0.0.1",
            command="show version",
            username="admin",
            password="x",
        )
    )
    assert result.transport == "telnet"
    assert "telnet" in calls and "ssh" not in calls


def test_ssh_vendor_goes_through_ssh(monkeypatch):
    calls = {}

    async def fake_ssh(**kwargs):
        calls["ssh"] = kwargs
        from app.ssh_client import SshResult

        return SshResult(True, 0, "вывод", None)

    async def fake_telnet(**kwargs):
        raise AssertionError("для SSH-вендора Telnet использоваться не должен")

    monkeypatch.setattr("app.device_client.run_ssh_command", fake_ssh)
    monkeypatch.setattr("app.device_client.run_telnet_command", fake_telnet)

    result = asyncio.run(
        run_device_command(
            vendor=Vendor.cisco_ios,
            host="10.0.0.2",
            command="show version",
            username="admin",
            password="x",
        )
    )
    assert result.transport == "ssh"
    assert calls["ssh"]["port"] == 22


def test_telnet_gets_port_23_when_not_specified(monkeypatch):
    """Узел заведён без явного порта — для Telnet это 23, а не 22."""
    seen = {}

    async def fake_telnet(**kwargs):
        seen.update(kwargs)
        from app.telnet_client import TelnetResult

        return TelnetResult(True, 0, "", None)

    monkeypatch.setattr("app.device_client.run_telnet_command", fake_telnet)
    asyncio.run(
        run_device_command(
            vendor=Vendor.cisco_ios_telnet,
            host="10.0.0.1",
            command="show version",
            username="admin",
            port=None,
        )
    )
    assert seen["port"] == 23


def test_explicit_port_is_respected(monkeypatch):
    seen = {}

    async def fake_telnet(**kwargs):
        seen.update(kwargs)
        from app.telnet_client import TelnetResult

        return TelnetResult(True, 0, "", None)

    monkeypatch.setattr("app.device_client.run_telnet_command", fake_telnet)
    asyncio.run(
        run_device_command(
            vendor=Vendor.cisco_ios_telnet,
            host="10.0.0.1",
            command="show version",
            username="admin",
            port=2323,
        )
    )
    assert seen["port"] == 2323


def test_error_is_passed_through_with_transport(monkeypatch):
    """Ошибка не должна теряться, а транспорт виден в результате — по
    журналу должно быть понятно, как именно ходили на устройство."""
    async def failing(**kwargs):
        from app.telnet_client import TelnetResult

        return TelnetResult(False, None, "", "timeout")

    monkeypatch.setattr("app.device_client.run_telnet_command", failing)
    result = asyncio.run(
        run_device_command(
            vendor=Vendor.cisco_ios_telnet,
            host="10.0.0.1",
            command="show version",
            username="admin",
        )
    )
    assert result.ok is False
    assert result.error == "timeout"
    assert result.transport == "telnet"
