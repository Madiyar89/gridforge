"""Nmap-скан диапазона — asyncio-подпроцесс, разбор XML напрямую в память
(не на диск, в отличие от NetOpsHub, где сырой XML лежит в data/scans/ и
разбирается отдельным проходом). Whitelist на диапазон портов — тот же
принцип, что в NetOpsHub (строгая проверка на backend, не только доверие
вызывающей стороне), но здесь достаточно самого факта, что cidr/ports не
дают инъекцию в командную строку (см. validate_cidr/validate_ports)."""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import DiscoveryScanSchedule, Node, Scan, ScanHost, ScanStatus

DEFAULT_TOP_PORTS = 20
SCAN_TIMEOUT_SECONDS = 120

_CIDR_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$")
_PORTS_RE = re.compile(r"^[0-9,\-]+$")


class ScanValidationError(ValueError):
    pass


def validate_cidr(cidr: str) -> None:
    if not _CIDR_RE.match(cidr):
        raise ScanValidationError(f"некорректный CIDR/IP: {cidr!r}")


def validate_ports(ports: str) -> None:
    if not _PORTS_RE.match(ports):
        raise ScanValidationError(f"некорректный список портов: {ports!r} — только цифры, запятые, дефисы")


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        address = addr_el.get("addr")
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        open_ports = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            open_ports.append(
                {
                    "port": int(port_el.get("portid")),
                    "service": service_el.get("name") if service_el is not None else None,
                }
            )
        hosts.append({"address": address, "hostname": hostname, "open_ports": open_ports})
    return hosts


async def run_scan(db: Session, cidr: str, ports: str | None = None) -> Scan:
    validate_cidr(cidr)
    if ports:
        validate_ports(ports)

    scan = Scan(cidr=cidr, status=ScanStatus.running)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    port_args = ["-p", ports] if ports else ["--top-ports", str(DEFAULT_TOP_PORTS)]
    proc = await asyncio.create_subprocess_exec(
        "nmap", "-oX", "-", "-T4", "-Pn", "-sT", *port_args, cidr,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        proc.kill()
        scan.status = ScanStatus.failed
        scan.error = "таймаут скана"
        scan.finished_at = None
        db.commit()
        db.refresh(scan)
        return scan

    if proc.returncode != 0:
        scan.status = ScanStatus.failed
        scan.error = (stderr.decode(errors="replace") or "nmap завершился с ошибкой")[:500]
        db.commit()
        db.refresh(scan)
        return scan

    try:
        hosts = _parse_nmap_xml(stdout.decode(errors="replace"))
    except ET.ParseError as exc:
        scan.status = ScanStatus.failed
        scan.error = f"не удалось разобрать вывод nmap: {exc}"
        db.commit()
        db.refresh(scan)
        return scan

    for h in hosts:
        db.add(ScanHost(scan_id=scan.id, address=h["address"], hostname=h["hostname"], open_ports=h["open_ports"]))
    scan.status = ScanStatus.done
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


def new_hosts_in_scan(db: Session, scan: Scan) -> list[dict]:
    """Хосты скана, чей адрес ещё не заведён как Node (docs/
    landscape-report.md, п.4.1) — та же проверка, что уже считает
    /api/scans/{id}/hosts (already_node), просто в виде списка для
    оповещения, а не построчного флага для интерфейса."""
    known_addresses = {n.address for n in db.query(Node).all()}
    return [
        {"address": h.address, "hostname": h.hostname}
        for h in scan.hosts
        if h.address not in known_addresses
    ]


async def run_scan_and_notify(db: Session, http_client, cidr: str, ports: str | None = None) -> Scan:
    """Как run_scan, но дополнительно оповещает включённые каналы о вновь
    найденных адресах, которых ещё нет среди Node (signal.notify_new_devices).
    Используется и ручным запуском (POST /api/scans), и плановым (см.
    run_due_discovery_schedules ниже) — оповещение не должно быть только
    у одного из двух путей."""
    from app.signal import notify_new_devices

    scan = await run_scan(db, cidr, ports)
    if scan.status == ScanStatus.done:
        new_hosts = new_hosts_in_scan(db, scan)
        if new_hosts:
            await notify_new_devices(http_client, db, new_hosts)
    return scan


async def run_due_discovery_schedules(get_session, http_client) -> None:
    """Проверяется раз в минуту из Scheduler.run_forever() (app/scheduler.py)
    — тот же принцип, что у run_due_vuln_schedules/
    run_due_cable_discovery_schedules: расписания на сегодня, чьё время
    уже наступило и сегодня ещё не запускались, last_triggered_on
    выставляется ДО прогона (не после — скан может занять до
    SCAN_TIMEOUT_SECONDS)."""
    import datetime as _dt

    db = get_session()
    try:
        now = _dt.datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        current_hm = now.strftime("%H:%M")
        due = (
            db.query(DiscoveryScanSchedule)
            .filter(
                DiscoveryScanSchedule.enabled.is_(True),
                DiscoveryScanSchedule.weekday == now.weekday(),
            )
            .all()
        )
        for sched in due:
            if sched.last_triggered_on == today_str or current_hm < sched.start_time:
                continue
            sched.last_triggered_on = today_str
            db.commit()
            try:
                await run_scan_and_notify(db, http_client, sched.cidr, sched.ports)
            except ScanValidationError:
                pass  # расписание могло быть создано раньше правкой валидации — не ронять цикл
    finally:
        db.close()
