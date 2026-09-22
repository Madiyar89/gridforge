"""Telnet-клиент для старых коммутаторов.

Зачем вообще. В парке есть 2950/2960, где SSH не поднять — только
Telnet. Без этого пять устройств недоступны инструменту вообще: ни
бэкапа, ни Рубки, ни состояния портов.

ПРЕДУПРЕЖДЕНИЕ, которое нельзя замалчивать: Telnet передаёт логин и
пароль ОТКРЫТЫМ ТЕКСТОМ. Любой в том же сегменте видит их целиком. Это
не недоработка клиента, а свойство протокола — поэтому аудит GridForge
сам же помечает `transport input telnet` как критичную находку.
Пользоваться этим стоит только там, где другого пути нет, и только пока
устройство не заменено.

Своя реализация, а не библиотека: `telnetlib` удалён из стандартной
библиотеки в Python 3.13, а тянуть внешнюю зависимость ради пяти
устройств не хочется. Нужен узкий набор: подключиться, пройти
приглашение логина, выполнить команду, прочитать до приглашения. Полное
согласование опций Telnet здесь не требуется — на все предложения
отвечаем отказом, и оборудование спокойно работает в построчном режиме.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

# Управляющие байты протокола (RFC 854).
IAC = 255   # начало команды
DONT, DO, WONT, WILL = 254, 253, 252, 251
SB, SE = 250, 240  # начало и конец подпеременной

DEFAULT_TELNET_PORT = 23

# Приглашения. Оборудование отвечает по-разному, поэтому ищем по смыслу,
# а не по точной строке.
_LOGIN_PROMPT = re.compile(rb"(?i)(user\s*name|login)\s*:\s*$")
_PASSWORD_PROMPT = re.compile(rb"(?i)password\s*:\s*$")
# Приглашение командной строки: имя устройства и > или #. Точка в конце
# обязательна — иначе под шаблон попадёт любая строка вывода.
_SHELL_PROMPT = re.compile(rb"[\r\n][\w.\-]+\s*[>#]\s*$")
_ENABLE_PROMPT = re.compile(rb"[\r\n][\w.\-]+\s*#\s*$")


@dataclass
class TelnetResult:
    """Тот же вид результата, что у SSH-клиента, чтобы вызывающий код не
    различал транспорт."""

    ok: bool
    exit_status: int | None
    stdout: str
    error: str | None


def _strip_telnet_commands(data: bytes, writer: asyncio.StreamWriter) -> bytes:
    """Убирает управляющие последовательности и отвечает на предложения.

    На каждое WILL отвечаем DONT, на каждое DO — WONT: нам не нужна ни
    одна опция, нужен простой построчный обмен. Без ответа некоторые
    устройства ждут согласования и не показывают приглашение."""
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte != IAC:
            out.append(byte)
            i += 1
            continue

        if i + 1 >= len(data):
            break
        command = data[i + 1]
        if command in (DO, DONT, WILL, WONT):
            if i + 2 >= len(data):
                break
            option = data[i + 2]
            # Отказываемся от всего: WILL→DONT, DO→WONT.
            answer = DONT if command == WILL else WONT if command == DO else None
            if answer is not None:
                writer.write(bytes([IAC, answer, option]))
            i += 3
        elif command == SB:
            end = data.find(bytes([IAC, SE]), i)
            i = len(data) if end == -1 else end + 2
        elif command == IAC:
            out.append(IAC)  # экранированный 0xFF — это данные
            i += 2
        else:
            i += 2
    return bytes(out)


async def _read_until(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    patterns: list[re.Pattern],
    timeout: float,
) -> tuple[bytes, int | None]:
    """Читает, пока не совпадёт один из шаблонов. Возвращает накопленное
    и номер сработавшего шаблона (None — истекло время)."""
    buffer = bytearray()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return bytes(buffer), None
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
        except asyncio.TimeoutError:
            return bytes(buffer), None
        if not chunk:
            return bytes(buffer), None
        buffer += _strip_telnet_commands(chunk, writer)
        await writer.drain()
        for index, pattern in enumerate(patterns):
            if pattern.search(bytes(buffer)):
                return bytes(buffer), index


def _clean_output(raw: str, command: str) -> str:
    """Убирает эхо команды и завершающее приглашение — остаётся только то,
    что вывело устройство."""
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # Эхо ищем в первых непустых строках, а не строго в первой: вывод
    # начинается с перевода строки, и эхо оказывается не нулевой строкой.
    wanted = command.strip()
    for index, line in enumerate(lines[:3]):
        if wanted and wanted in line:
            lines = lines[index + 1:]
            break
    while lines and _SHELL_PROMPT.search(("\n" + lines[-1]).encode("utf-8", "replace")):
        lines.pop()
    return "\n".join(lines).strip()


async def _login(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    username: str | None,
    password: str | None,
    enable_password: str | None,
    timeout_seconds: float,
) -> str | None:
    """Проходит приглашение логина/пароля и, если дан enable_password,
    поднимается до привилегированного режима. Возвращает текст ошибки
    (None — вход прошёл). Общая часть run_telnet_command и
    run_telnet_config_lines — раньше жила только внутри первой, вынесена
    при добавлении второй, чтобы не дублировать ~40 строк хендшейка."""
    buffer, matched = await _read_until(
        reader, writer, [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT], timeout_seconds
    )
    if matched is None:
        return "устройство не прислало приглашение входа"

    if matched == 0:  # спросили логин
        writer.write((username or "").encode() + b"\r\n")
        await writer.drain()
        buffer, matched = await _read_until(
            reader, writer, [_PASSWORD_PROMPT, _SHELL_PROMPT], timeout_seconds
        )
        if matched is None:
            return "после логина не пришло приглашение пароля"
        matched = 1 if matched == 0 else 2

    if matched == 1:  # спросили пароль
        writer.write((password or "").encode() + b"\r\n")
        await writer.drain()
        buffer, matched = await _read_until(
            reader, writer, [_SHELL_PROMPT, _PASSWORD_PROMPT], timeout_seconds
        )
        if matched is None:
            return "нет приглашения после пароля"
        if matched == 1:
            return "неверный логин или пароль"  # снова спрашивают пароль — не подошёл

    if enable_password and not _ENABLE_PROMPT.search(buffer):
        writer.write(b"enable\r\n")
        await writer.drain()
        _, matched = await _read_until(reader, writer, [_PASSWORD_PROMPT, _ENABLE_PROMPT], timeout_seconds)
        if matched == 0:
            writer.write(enable_password.encode() + b"\r\n")
            await writer.drain()
            _, matched = await _read_until(reader, writer, [_ENABLE_PROMPT, _PASSWORD_PROMPT], timeout_seconds)
            if matched != 0:
                return "enable-пароль не подошёл"

    # Отключаем постраничный вывод: иначе на длинной команде устройство
    # остановится на «--More--» и будет ждать пробела.
    writer.write(b"terminal length 0\r\n")
    await writer.drain()
    await _read_until(reader, writer, [_SHELL_PROMPT], timeout_seconds)
    return None


async def run_telnet_command(
    *,
    host: str,
    port: int = DEFAULT_TELNET_PORT,
    username: str | None,
    password: str | None,
    command: str,
    timeout_seconds: float,
    enable_password: str | None = None,
) -> TelnetResult:
    """Выполняет одну команду по Telnet и возвращает её вывод."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_seconds
        )

        error = await _login(
            reader, writer, username=username, password=password,
            enable_password=enable_password, timeout_seconds=timeout_seconds,
        )
        if error is not None:
            return TelnetResult(False, None, "", error)

        writer.write(command.encode() + b"\r\n")
        await writer.drain()
        raw, matched = await _read_until(reader, writer, [_SHELL_PROMPT], timeout_seconds)
        text = raw.decode("utf-8", errors="replace")
        if matched is None:
            return TelnetResult(False, None, _clean_output(text, command), "истекло время ожидания вывода")

        return TelnetResult(True, 0, _clean_output(text, command), None)

    except asyncio.TimeoutError:
        return TelnetResult(False, None, "", "timeout")
    except OSError as exc:
        return TelnetResult(False, None, "", str(exc) or exc.__class__.__name__)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def run_telnet_config_lines(
    *,
    host: str,
    port: int = DEFAULT_TELNET_PORT,
    username: str | None,
    password: str | None,
    lines: list[str],
    timeout_seconds: float,
    enable_password: str | None = None,
    line_delay: float = 0.4,
    settle_seconds: float = 2.0,
) -> TelnetResult:
    """Многострочные конфигурирующие команды по Telnet — тот же принцип,
    что ssh_client.run_ssh_config_lines (см. подробный разбор там): одну
    команду с "\\n" внутри устройство воспринимает как единый текст, не
    последовательность, поэтому строки пишутся по одной с паузой между
    ними, как будто человек печатает их в реальном терминале.

    В отличие от run_telnet_command здесь НЕ ищем конкретный prompt после
    каждой строки — под-режимы конфигурации меняют приглашение
    ("Switch(config)#", "Switch(config-line)#", ...), которое _SHELL_PROMPT
    (рассчитан на базовый EXEC-prompt) не ловит. Вместо этого — тот же
    time-based приём, что в SSH-варианте: копим весь вывод фоновым
    читателем, ждём settle_seconds после последней строки."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_seconds
        )

        error = await _login(
            reader, writer, username=username, password=password,
            enable_password=enable_password, timeout_seconds=timeout_seconds,
        )
        if error is not None:
            return TelnetResult(False, None, "", error)

        output_chunks: list[bytes] = []

        async def _reader_task() -> None:
            try:
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    output_chunks.append(_strip_telnet_commands(chunk, writer))
            except OSError:
                pass

        task = asyncio.create_task(_reader_task())
        for line in lines:
            writer.write(line.encode() + b"\r\n")
            await writer.drain()
            await asyncio.sleep(line_delay)
        await asyncio.sleep(settle_seconds)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        text = b"".join(output_chunks).decode("utf-8", errors="replace").strip()
        return TelnetResult(True, 0, text, None)

    except asyncio.TimeoutError:
        return TelnetResult(False, None, "", "timeout")
    except OSError as exc:
        return TelnetResult(False, None, "", str(exc) or exc.__class__.__name__)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
