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
NetOpsHub, см. исходный докстринг nmap_parser.py).

Профиль "nuclei" (2026-09-25, доразбор внешних security-инструментов —
см. docs/landscape-report.md) — не nmap, отдельный runner
(run_nuclei_scan) поверх бинарника nuclei (ProjectDiscovery, MIT):
шаблонная база CVE/misconfig обновляется куда чаще, чем NSE-скрипты
категории vuln у самого nmap, тот же принцип "внешний бинарник вызывается
подпроцессом, код не копируется", что уже применялся для nmap/tshark/
dumpcap. Severity Nuclei (5 уровней: critical/high/medium/low/info)
сведён к трёхуровневой шкале register'а (vulnerable/likely/unknown) —
см. NUCLEI_SEVERITY_MAP; исходный уровень Nuclei остаётся в
finding["nuclei_severity"] для UI, где нужна точность выше трёх ступеней.

ВНИМАНИЕ (2026-09-25): интеграция написана по официальной, стабильной
JSON-схеме вывода Nuclei (`-jsonl`: template-id/info.severity/matched-
at/host) — та же схема годами не менялась, задокументирована в PD
wiki. Живой прогон на этой машине не подтверждён: скачивание
nuclei-templates упёрлось в сетевой таймаут (конкурирующая по полосе
фоновая синхронизация apt-mirror на той же машине, см. HANDOFF.md).
Разобрать реальный вывод перед тем, как доверять этому парсеру
вслепую — обязательно, тот же урок, что уже был с CDP/LLDP в этом
проекте (см. CLAUDE.md, "Прогресс по docs/landscape-report.md")."""

from __future__ import annotations

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from app.models import VulnScan, VulnScanHost, VulnScanStatus

NUCLEI_TIMEOUT_SECONDS = 900

NUCLEI_SEVERITY_MAP = {
    "critical": "vulnerable",
    "high": "vulnerable",
    "medium": "likely",
    "low": "unknown",
    "unknown": "unknown",
    "info": "info",
}

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

# Все допустимые профили — используется валидацией в main.py вместо
# "голого" PROFILE_ARGS, потому что "nuclei" туда намеренно не входит
# (это не nmap-флаги, см. run_nuclei_scan).
VALID_PROFILES: set[str] = set(PROFILE_ARGS) | {"nuclei"}

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


def parse_nuclei_jsonl(raw_output: str, targets: list[str]) -> list[dict]:
    """Разбор `-jsonl`-вывода Nuclei в ту же форму findings, что и у nmap
    (port/script_id/severity/cves/summary) — общий формат, который уже
    понимает app/vuln_register.py. Каждая строка — отдельный JSON-объект
    (одна находка), несвязанные/пустые строки молча пропускаются, а не
    роняют весь разбор — вывод Nuclei может содержать статусные строки
    вперемешку, если -silent забыли передать."""
    findings_by_host: dict[str, list[dict]] = {t: [] for t in targets}
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = rec.get("host") or rec.get("matched-at") or ""
        # host у Nuclei обычно с протоколом/портом (http://1.2.3.4:8080) —
        # сопоставляем с исходным targets по вхождению адреса, не точным
        # совпадением строки.
        target = next((t for t in targets if t in host), None)
        if target is None:
            target = targets[0] if len(targets) == 1 else host
            findings_by_host.setdefault(target, [])
        info = rec.get("info") or {}
        nuclei_severity = (info.get("severity") or "unknown").lower()
        cves = [c.upper() for c in (info.get("classification", {}) or {}).get("cve-id") or []]
        findings_by_host[target].append(
            {
                "port": rec.get("matched-at", host),
                "script_id": rec.get("template-id", ""),
                "severity": NUCLEI_SEVERITY_MAP.get(nuclei_severity, "unknown"),
                "nuclei_severity": nuclei_severity,
                "cves": cves,
                "summary": (info.get("name") or "")[:200],
            }
        )
    return [{"address": t, "hostname": None, "state": "up", "findings": f} for t, f in findings_by_host.items()]


async def run_nuclei_scan(scan_id: int, targets: list[str], get_session) -> None:
    """Отдельный от run_vuln_scan путь — Nuclei не понимает nmap-флаги,
    но пишет в ту же VulnScan/VulnScanHost и тот же .xlsx-реестр (см.
    докстринг модуля насчёт живой проверки — статус см. там)."""
    from app.vuln_register import ingest_scan

    db = get_session()
    try:
        scan = db.get(VulnScan, scan_id)
        if scan is None:
            return

        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-l", "-", "-jsonl", "-silent",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(("\n".join(targets) + "\n").encode()), timeout=NUCLEI_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            proc.kill()
            scan.status = VulnScanStatus.failed
            scan.error = "таймаут скана"
            db.commit()
            return

        if proc.returncode != 0:
            scan.status = VulnScanStatus.failed
            scan.error = (stderr.decode(errors="replace") or "nuclei завершился с ошибкой")[:500]
            db.commit()
            return

        hosts = parse_nuclei_jsonl(stdout.decode(errors="replace"), targets)
        for h in hosts:
            db.add(
                VulnScanHost(
                    scan_id=scan.id, address=h["address"], hostname=h["hostname"],
                    state=h["state"], findings=h["findings"],
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


async def run_vuln_scan(scan_id: int, targets: list[str], profile: str, get_session) -> None:
    """Фон: создаёт VulnScanHost на каждый ответивший хост, обновляет
    статус VulnScan, затем дописывает результат в накопительный .xlsx
    реестр группы (см. app/vuln_register.py) — тот же принцип "прогон
    уходит в фон", что у Sweep/DomainScan/ScenarioRun (main.py)."""
    if profile == "nuclei":
        await run_nuclei_scan(scan_id, targets, get_session)
        return

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


async def run_due_vuln_schedules(get_session) -> None:
    """Проверяется раз в минуту из Scheduler.run_forever() (app/scheduler.py).
    Находит расписания (VulnScanSchedule), у которых сегодня нужный день
    недели, текущее время уже дошло до start_time, и сегодня ещё не
    запускали — и прогоняет для них все выбранные профили ПОСЛЕДОВАТЕЛЬНО
    (await, не create_task): общий набор хостов группы, гонять nmap на них
    параллельно из нескольких профилей незачем и рискованно по ресурсам."""
    from app.models import Group, VulnScanSchedule

    db = get_session()
    try:
        now = datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        current_hm = now.strftime("%H:%M")
        due = (
            db.query(VulnScanSchedule)
            .filter(
                VulnScanSchedule.enabled.is_(True),
                VulnScanSchedule.weekday == now.weekday(),
            )
            .all()
        )
        for sched in due:
            if sched.last_triggered_on == today_str or current_hm < sched.start_time:
                continue
            # Помечаем сразу — не после прогона (который может занять до ~40
            # минут) — иначе следующая проверка через минуту запустит его же
            # ещё раз, пока предыдущий прогон ещё не закончился.
            sched.last_triggered_on = today_str
            db.commit()

            group = db.get(Group, sched.group_id)
            if group is None:
                continue
            targets = [n.address for n in group.nodes if n.address]
            if not targets:
                continue

            for profile in sched.profiles:
                if profile not in PROFILE_ARGS:
                    continue
                scan = VulnScan(
                    group_id=sched.group_id,
                    profile=profile,
                    responsible=sched.responsible or "плановый запуск по расписанию",
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)
                await run_vuln_scan(scan.id, targets, profile, get_session)
    finally:
        db.close()
