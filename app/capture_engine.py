"""Захват и разбор трафика через tshark/dumpcap — asyncio-подпроцесс, тот
же принцип, что и scan_engine.py (nmap). Честная граница, унаследованная
от NetOpsHub: видим только интерфейс этой машины, не mirror-порт
коммутатора — это вопрос физической топологии, не софта."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import Capture, CaptureStatus

CAPTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "captures"
MAX_DURATION_SECONDS = 300

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,32}$")
_BPF_SAFE_RE = re.compile(r"^[a-zA-Z0-9_.\-\s()<>=!/]{0,255}$")  # без ; | & ` $ — не пробрасывается в shell (см. ниже), но всё равно ограничиваем алфавит


class CaptureValidationError(ValueError):
    pass


def _validate(interface: str, bpf_filter: str | None, duration: int) -> None:
    if not _IFACE_RE.match(interface):
        raise CaptureValidationError(f"некорректное имя интерфейса: {interface!r}")
    if bpf_filter and not _BPF_SAFE_RE.match(bpf_filter):
        raise CaptureValidationError(f"недопустимые символы в BPF-фильтре: {bpf_filter!r}")
    if not (1 <= duration <= MAX_DURATION_SECONDS):
        raise CaptureValidationError(f"duration должен быть от 1 до {MAX_DURATION_SECONDS} секунд")


async def run_capture(db: Session, interface: str, bpf_filter: str | None, duration_seconds: int) -> Capture:
    _validate(interface, bpf_filter, duration_seconds)
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    capture = Capture(interface=interface, bpf_filter=bpf_filter, duration_seconds=duration_seconds, status=CaptureStatus.running)
    db.add(capture)
    db.commit()
    db.refresh(capture)

    file_path = CAPTURE_DIR / f"{capture.id}.pcap"
    # dumpcap — не tshark: он и есть непривилегированный сборщик пакетов у
    # Wireshark (cap_net_raw/cap_net_admin через setcap, не root целиком),
    # tshark сам под капотом его же вызывает для захвата.
    cmd = ["dumpcap", "-i", interface, "-a", f"duration:{duration_seconds}", "-w", str(file_path)]
    if bpf_filter:
        cmd += ["-f", bpf_filter]

    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration_seconds + 15)
    except asyncio.TimeoutError:
        proc.kill()
        capture.status = CaptureStatus.failed
        capture.error = "таймаут захвата"
        db.commit()
        db.refresh(capture)
        return capture

    if proc.returncode != 0 or not file_path.exists():
        capture.status = CaptureStatus.failed
        capture.error = (stderr.decode(errors="replace") or "dumpcap завершился с ошибкой")[:500]
        db.commit()
        db.refresh(capture)
        return capture

    count_proc = await asyncio.create_subprocess_exec(
        "tshark", "-r", str(file_path), "-q", "-z", "io,stat,0",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    count_out, _ = await count_proc.communicate()
    packet_count = 0
    m = re.search(r"\|\s*(\d+)\s*\|\s*[\d.]+\s*\|", count_out.decode(errors="replace"))
    if m:
        packet_count = int(m.group(1))

    capture.status = CaptureStatus.done
    capture.finished_at = datetime.now(timezone.utc)
    capture.packet_count = packet_count
    capture.file_path = str(file_path)
    db.commit()
    db.refresh(capture)
    return capture


async def analyze_capture(capture: Capture, method: str) -> str:
    """method: protocols | conversations | top-talkers"""
    if not capture.file_path or not Path(capture.file_path).exists():
        return "файл захвата недоступен"

    if method == "protocols":
        args = ["-q", "-z", "io,phs"]
    elif method == "conversations":
        args = ["-q", "-z", "conv,ip"]
    else:
        return f"неизвестный метод анализа: {method}"

    proc = await asyncio.create_subprocess_exec(
        "tshark", "-r", capture.file_path, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode(errors="replace") or "(пусто)"
