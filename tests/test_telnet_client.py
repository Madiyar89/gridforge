"""Telnet-клиент против поддельного коммутатора.

Настоящих 2950/2960 в тестах нет, поэтому поднимается локальный сервер,
который ведёт себя как Cisco IOS по Telnet: предлагает опции протокола,
спрашивает логин и пароль, отвечает приглашением, эхом повторяет команду
и печатает вывод. Это проверяет именно то, где легко ошибиться —
разбор управляющих последовательностей и распознавание приглашений.
"""

import asyncio

import pytest

from app.telnet_client import (
    DO,
    IAC,
    WILL,
    run_telnet_command,
)


class FakeSwitch:
    """Минимальный Cisco-подобный сервер."""

    def __init__(self, *, ask_username=True, password="secret", enable_password=None, offer_options=True):
        self.ask_username = ask_username
        self.password = password
        self.enable_password = enable_password
        self.offer_options = offer_options
        self.commands: list[str] = []
        self.server = None
        self.port = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()

    async def _readline(self, reader) -> str:
        """Читает строку, отбрасывая управляющие последовательности.

        Настоящее оборудование разбирает IAC-команды и не путает их с
        вводом пользователя. Без этого ответы клиента на предложения
        опций попадали в поддельный коммутатор как «пароль» — и тест
        падал там, где реальное устройство сработало бы."""
        data = await reader.readline()
        out, i = bytearray(), 0
        while i < len(data):
            if data[i] == IAC and i + 2 < len(data):
                i += 3  # IAC + команда + опция
                continue
            out.append(data[i])
            i += 1
        return out.decode(errors="replace").strip()

    async def _handle(self, reader, writer):
        if self.offer_options:
            # Настоящее оборудование начинает с предложения опций.
            writer.write(bytes([IAC, WILL, 1, IAC, DO, 24]))
            await writer.drain()

        if self.ask_username:
            writer.write(b"\r\nUser Access Verification\r\n\r\nUsername: ")
            await writer.drain()
            await self._readline(reader)

        writer.write(b"\r\nPassword: ")
        await writer.drain()
        given = await self._readline(reader)
        if given != self.password:
            writer.write(b"\r\n% Bad passwords\r\n\r\nPassword: ")
            await writer.drain()
            writer.close()
            return

        prompt = b"\r\nSW-TEST>"
        writer.write(prompt)
        await writer.drain()

        while True:
            line = await self._readline(reader)
            if not line:
                break
            self.commands.append(line)

            if line == "enable":
                writer.write(b"\r\nPassword: ")
                await writer.drain()
                given = await self._readline(reader)
                if given == self.enable_password:
                    prompt = b"\r\nSW-TEST#"
                    writer.write(prompt)
                else:
                    writer.write(b"\r\n% Bad secrets\r\n" + prompt)
                await writer.drain()
                continue

            if line == "terminal length 0":
                writer.write(b"\r\n" + prompt)
                await writer.drain()
                continue

            if line == "show version":
                writer.write(b"\r\n" + line.encode() + b"\r\nCisco IOS Software, C2960 Software\r\nuptime is 3 weeks\r\n" + prompt)
            elif line == "show running-config":
                writer.write(b"\r\n" + line.encode() + b"\r\nBuilding configuration...\r\n!\r\nhostname SW-TEST\r\n!\r\nend\r\n" + prompt)
            else:
                writer.write(b"\r\n" + line.encode() + b"\r\n% Invalid input detected\r\n" + prompt)
            await writer.drain()


async def _run(switch: FakeSwitch, **kwargs):
    defaults = dict(
        host="127.0.0.1",
        port=switch.port,
        username="admin",
        password="secret",
        command="show version",
        timeout_seconds=5.0,
    )
    defaults.update(kwargs)
    return await run_telnet_command(**defaults)


def test_command_output_is_returned():
    async def scenario():
        switch = await FakeSwitch().start()
        try:
            return await _run(switch), switch
        finally:
            await switch.stop()

    result, switch = asyncio.run(scenario())
    assert result.ok is True
    assert "Cisco IOS Software" in result.stdout
    assert "show version" in switch.commands


def test_telnet_option_negotiation_does_not_leak_into_output():
    """Управляющие байты протокола не должны попасть в текст вывода —
    иначе разбор конфигурации спотыкается на мусоре."""
    async def scenario():
        switch = await FakeSwitch(offer_options=True).start()
        try:
            return await _run(switch)
        finally:
            await switch.stop()

    result = asyncio.run(scenario())
    assert result.ok
    assert "\xff" not in result.stdout
    assert chr(IAC) not in result.stdout


def test_command_echo_is_stripped():
    """Устройство повторяет команду эхом — в выводе её быть не должно."""
    async def scenario():
        switch = await FakeSwitch().start()
        try:
            return await _run(switch, command="show running-config")
        finally:
            await switch.stop()

    result = asyncio.run(scenario())
    assert not result.stdout.startswith("show running-config")
    assert "hostname SW-TEST" in result.stdout


def test_trailing_prompt_is_stripped():
    async def scenario():
        switch = await FakeSwitch().start()
        try:
            return await _run(switch)
        finally:
            await switch.stop()

    result = asyncio.run(scenario())
    assert not result.stdout.rstrip().endswith(">")
    assert "SW-TEST>" not in result.stdout


def test_password_only_login_works():
    """Часть устройств логин не спрашивает — только пароль на линии vty."""
    async def scenario():
        switch = await FakeSwitch(ask_username=False).start()
        try:
            return await _run(switch)
        finally:
            await switch.stop()

    result = asyncio.run(scenario())
    assert result.ok is True


def test_wrong_password_is_reported_not_hung():
    """Неверный пароль должен дать понятную ошибку, а не зависание до
    таймаута."""
    async def scenario():
        switch = await FakeSwitch(password="other").start()
        try:
            return await _run(switch, timeout_seconds=3.0)
        finally:
            await switch.stop()

    result = asyncio.run(scenario())
    assert result.ok is False
    assert result.error


def test_enable_password_is_used():
    async def scenario():
        switch = await FakeSwitch(enable_password="enablepass").start()
        try:
            return await _run(switch, enable_password="enablepass"), switch
        finally:
            await switch.stop()

    result, switch = asyncio.run(scenario())
    assert result.ok is True
    assert "enable" in switch.commands


def test_terminal_length_is_disabled():
    """Без `terminal length 0` длинный вывод встанет на «--More--» и
    команда зависнет до таймаута."""
    async def scenario():
        switch = await FakeSwitch().start()
        try:
            await _run(switch)
            return switch
        finally:
            await switch.stop()

    switch = asyncio.run(scenario())
    assert "terminal length 0" in switch.commands


def test_unreachable_host_returns_error_quickly():
    result = asyncio.run(
        run_telnet_command(
            host="127.0.0.1",
            port=1,  # на этом порту никто не слушает
            username="admin",
            password="secret",
            command="show version",
            timeout_seconds=3.0,
        )
    )
    assert result.ok is False
    assert result.error
