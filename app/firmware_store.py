"""Хранилище файлов образов ПО — перенесено из NetOpsHub, только сама
часть "хранилище" (загрузить/посмотреть список/скачать/удалить). Заливка
на устройство и активация там шли отдельными Ansible-плейбуками через
TFTP-сервер — ни того, ни другого у GridForge нет, по прямому запросу
пользователя (AskUserQuestion) сюда переносится только хранилище: файл
скачивается сайтом, дальше заливается вручную (TFTP/консоль), не
автоматически.

Файлы лежат на диске под DATA_DIR/firmware/{vendor}/{filename} — тот же
принцип, что DATA_DIR/backups у NetOpsHub, отдельной таблицы в БД не
нужно, список читается прямо из файловой системы."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import BinaryIO

from app.db import DATA_DIR

FIRMWARE_DIR = DATA_DIR / "firmware"

# Только вендоры, для которых вообще есть смысл держать образы отдельно
# по каталогам (тот же список, что был в форме загрузки на старом сайте).
ALLOWED_VENDORS = ("cisco_ios", "junos")

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class FirmwareError(Exception):
    pass


def _vendor_dir(vendor: str) -> Path:
    if vendor not in ALLOWED_VENDORS:
        raise FirmwareError(f"Неизвестный вендор: {vendor}")
    d = FIRMWARE_DIR / vendor
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_filename(filename: str) -> str:
    name = Path(filename).name  # отбрасывает любой путь клиента, оставляет только имя файла
    if not name or not _SAFE_NAME_RE.match(name):
        raise FirmwareError("Недопустимое имя файла — разрешены буквы/цифры/точка/дефис/подчёркивание")
    return name


def list_firmware() -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for vendor in ALLOWED_VENDORS:
        d = FIRMWARE_DIR / vendor
        files = []
        if d.is_dir():
            for path in sorted(d.iterdir()):
                if not path.is_file():
                    continue
                stat = path.stat()
                files.append({"filename": path.name, "size": stat.st_size, "modified_at": stat.st_mtime})
        result[vendor] = files
    return result


def save_firmware(vendor: str, filename: str, stream: BinaryIO) -> Path:
    """Пишет потоком (shutil.copyfileobj), не читает файл целиком в
    память — образы ПО легко бывают несколько сотен МБ."""
    d = _vendor_dir(vendor)
    name = _safe_filename(filename)
    path = d / name
    with path.open("wb") as out:
        shutil.copyfileobj(stream, out)
    return path


def firmware_path(vendor: str, filename: str) -> Path:
    d = _vendor_dir(vendor)
    path = d / _safe_filename(filename)
    if not path.is_file():
        raise FirmwareError("Файл не найден")
    return path


def delete_firmware(vendor: str, filename: str) -> None:
    path = firmware_path(vendor, filename)
    path.unlink()
