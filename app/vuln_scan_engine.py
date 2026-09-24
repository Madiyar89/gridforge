"""Проверка на уязвимости — перенос функции NetOpsHub (nmap_scan.yml +
backend/app/modules/reports/nmap_parser.py). Та же логика и те же 5
профилей/флаги nmap (значения из nmap_profiles в nmap_scan.yml — важно
совпадать дословно, чтобы поведение не поменялось незаметно), но без
Ansible: прямой asyncio-подпроцесс на все узлы группы разом (NetOpsHub
гонял playbook отдельно на каждую цель — один XML-файл на хост), разбор
XML сразу в БД, как уже сделано для scan_engine.py/domain_scan_engine.py.

Итоговое решение "это реальная уязвимость или ложное срабатывание"
по-прежнему за человеком — отсюда severity vulnerable/likely/unknown как
факт вывода nmap, не автоматический вердикт (тот же принцип, что в
NetOpsHub, см. исходный докстринг nmap_parser.py)."""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from app.models import VulnScan, VulnScanHost, VulnScanStatus

# Профиль -> флаги nmap. Дословно из NetOpsHub (ansible/playbooks/
# nmap_scan.yml: nmap_profiles) — то же поведение проверки, что было
# на старом сайте.
PROFILE_ARGS: dict[str, list[str]] = {
    "ping": ["-sn"],
    "quick": ["-F", "-sV"],
    "full_ports": ["-p-", "-sV"],
    "vuln": ["-sV", "--script", "vuln"],
    "os": ["-O", "-sV"],
}

# full_ports/vuln проверяют куда больше портов/скриптов на цель — им
# нужно заметно больше времени, чем ping/quick/os.
PROFILE_TIMEOUT_SECONDS: dict[str, int] = {
    "ping": 60,
    "quick": 180,
    "full_ports": 900,
    "vuln": 900,
    "os": 180,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
# NSE vuln-скрипты печатают заголовок "VULNERABLE:" одинаково что для
# подтверждённой, что для вероятной уязвимости — реальная строгость
# всегда в отдельной строке "State: ...".
_STATE_RE = re.compile(r"State:\s*(VULNERABLE|LIKELY VULNERABLE|UNKNOWN)")


class VulnScanValidationError(ValueError):
    pass


def _finding_summary(output: str) -> str:
    for line in output.strip().splitlines():
        line = line.strip()
        if line and line != "VULNERABLE:":
            return line[:200]
    return ""


def _script_severity(output: str) -> str:
    match = _STATE_RE.search(output)
    if not match:
        return "info"
    state = match.group(1)
    if state == "VULNERABLE":
        return "vulnerable"
    if state == "LIKELY VULNERABLE":
        return "likely"
    return "unknown"


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Тот же разбор, что в NetOpsHub nmap_parser.parse_nmap_xml, но из
    строки в памяти (не с диска — здесь нет промежуточного файла)."""
    root = ET.fromstring(xml_text)
    hosts = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None:
            continue
        addr_el = host_el.find("address")
        hostnames_el = host_el.find("hostnames/hostname")

        findings = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                for script_el in port_el.findall("script"):
                    output = script_el.get("output", "")
                    severity = _script_severity(output)
                    if severity == "info" and "ERROR" in output:
                        continue  # скрипт не смог выполниться — не находка, шум
                    findings.append(
                        {
                            "port": f"{port_el.get('protocol')}/{port_el.get('portid')}",
                            "script_id": script_el.get("id"),
                            "severity": severity,
                            "cves": sorted(set(_CVE_RE.findall(output))),
                            "summary": _finding_summary(output),
                        }
                    )

        hosts.append(
            {
                "address": addr_el.get("addr") if addr_el is not None else "",
                "hostname": hostnames_el.get("name") if hostnames_el is not None else None,
                "state": status_el.get("state"),
                "findings": findings,
            }
        )
    return hosts


async def run_vuln_scan(scan_id: int, targets: list[str], profile: str, get_session) -> None:
    """Фон: создаёт VulnScanHost на каждый ответивший хост, обновляет
    статус VulnScan, затем дописывает результат в накопительный .xlsx
    реестр группы (см. app/vuln_register.py) — тот же принцип "прогон
    уходит в фон", что у Sweep/DomainScan/ScenarioRun (main.py)."""
    from app.vuln_register import ingest_scan

    db = get_session()
    try:
        scan = db.get(VulnScan, scan_id)
        if scan is None:
            return

        args = PROFILE_ARGS[profile]
        timeout = PROFILE_TIMEOUT_SECONDS[profile]
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-oX", "-", *args, *targets,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            scan.status = VulnScanStatus.failed
            scan.error = "таймаут скана"
            db.commit()
            return

        if proc.returncode != 0:
            scan.status = VulnScanStatus.failed
            scan.error = (stderr.decode(errors="replace") or "nmap завершился с ошибкой")[:500]
            db.commit()
            return

        try:
            hosts = parse_nmap_xml(stdout.decode(errors="replace"))
        except ET.ParseError as exc:
            scan.status = VulnScanStatus.failed
            scan.error = f"не удалось разобрать вывод nmap: {exc}"
            db.commit()
            return

        for h in hosts:
            db.add(
                VulnScanHost(
                    scan_id=scan.id,
                    address=h["address"],
                    hostname=h["hostname"],
                    state=h["state"],
                    findings=h["findings"],
                )
            )
        scan.status = VulnScanStatus.done
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)

        try:
            ingest_scan(db, scan)
        except Exception as exc:  # noqa: BLE001 — реестр не должен ронять сам скан
            scan.error = f"скан выполнен, но не удалось дописать реестр: {exc}"
            db.commit()
    finally:
        db.close()
