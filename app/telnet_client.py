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

        # Вход. У части устройств спрашивают только пароль (аутентификация
        # на линии vty), у части — логин и пароль.
        buffer, matched = await _read_until(
            reader, writer, [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT], timeout_seconds
        )
        if matched is None:
            return TelnetResult(False, None, "", "устройство не прислало приглашение входа")

        if matched == 0:  # спросили логин
            writer.write((username or "") .encode() + b"\r\n")
            await writer.drain()
            buffer, matched = await _read_until(
                reader, writer, [_PASSWORD_PROMPT, _SHELL_PROMPT], timeout_seconds
            )
            if matched is None:
                return TelnetResult(False, None, "", "после логина не пришло приглашение пароля")
            matched = 1 if matched == 0 else 2

        if matched == 1:  # спросили пароль
            writer.write((password or "").encode() + b"\r\n")
            await writer.drain()
            buffer, matched = await _read_until(
                reader, writer, [_SHELL_PROMPT, _PASSWORD_PROMPT], timeout_seconds
            )
            if matched is None:
                return TelnetResult(False, None, "", "нет приглашения после пароля")
            if matched == 1:
                # Снова спрашивают пароль — значит не подошёл.
                return TelnetResult(False, None, "", "неверный логин или пароль")

        # Повышение привилегий, если оно нужно и пароль дан.
        if enable_password and not _ENABLE_PROMPT.search(buffer):
            writer.write(b"enable\r\n")
            await writer.drain()
            _, matched = await _read_until(reader, writer, [_PASSWORD_PROMPT, _ENABLE_PROMPT], timeout_seconds)
            if matched == 0:
                writer.write(enable_password.encode() + b"\r\n")
                await writer.drain()
                _, matched = await _read_until(reader, writer, [_ENABLE_PROMPT, _PASSWORD_PROMPT], timeout_seconds)
                if matched != 0:
                    return TelnetResult(False, None, "", "enable-пароль не подошёл")

        # Отключаем постраничный вывод: иначе на длинной команде
        # устройство остановится на «--More--» и будет ждать пробела.
        writer.write(b"terminal length 0\r\n")
        await writer.drain()
        await _read_until(reader, writer, [_SHELL_PROMPT], timeout_seconds)

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
