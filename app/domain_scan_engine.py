"""Доменная инвентаризация — перенесено из NetOpsHub (Ярус 2, раздел 4.8
ТЗ: hub/ansible/scripts/domain_inventory.py + app/modules/domain_scan/).

Там это Ansible-плейбук (nmap -sn) + отдельный Python-скрипт (WinRM/SMB на
каждый живой хост), результат — JSON-файл на диске, читаемый backend'ом
по запросу. Здесь — прямой asyncio, без Ansible/промежуточных файлов, тот
же общий принцип, что уже применяется для обычного nmap-скана
(scan_engine.py) и для Sweep: узлы опрашиваются параллельно с
ограничением, результат каждого хоста пишется в БД сразу по готовности.

Методы опроса — те же три (winrm/smb_domain/smb_anonymous), та же цепочка
fallback (метод → fallback_method из набора → smb_anonymous как последний
рубеж всегда, если его ещё нет в цепочке) и те же эвристики против ложных
находок (PartOfDomain=False у WinRM — не домен, а рабочая группа; "домен"
в ответе SMB, совпавший с NetBIOS-именем самой машины — распознан хост,
не AD-домен)."""

from __future__ import annotations

import asyncio
import ipaddress
import xml.etree.ElementTree as ET

from sqlalchemy.orm import Session

from app.models import DomainScan, DomainScanCredentialSet, DomainScanHost, DomainScanMethod, ScanStatus, _now
from app.secrets_crypto import decrypt_secret

PING_SCAN_TIMEOUT_SECONDS = 120
PROBE_TIMEOUT_SECONDS = 6.0
MAX_PARALLEL = 12
WINRM_HTTPS_PORT = 5986
SMB_PORT = 445
_METHOD_PORT = {
    DomainScanMethod.winrm: WINRM_HTTPS_PORT,
    DomainScanMethod.smb_domain: SMB_PORT,
    DomainScanMethod.smb_anonymous: SMB_PORT,
}


class DomainScanValidationError(ValueError):
    pass


# === Этап 1 — живые хосты подсети (nmap -sn, без выбора портов — тут не
# важно, что открыто, важно только "отвечает ли вообще") ===


def _network_broadcast_addresses(cidr: str) -> set[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return set()
    if net.num_addresses <= 2:
        return set()
    return {str(net.network_address), str(net.broadcast_address)}


async def ping_sweep(cidr: str) -> list[str]:
    proc = await asyncio.create_subprocess_exec(
        "nmap", "-sn", "-T4", "-oX", "-", cidr,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=PING_SCAN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        proc.kill()
        raise DomainScanValidationError("таймаут ping-скана")
    if proc.returncode != 0:
        raise DomainScanValidationError((stderr.decode(errors="replace") or "nmap -sn завершился с ошибкой")[:500])

    excluded = _network_broadcast_addresses(cidr)
    root = ET.fromstring(stdout)
    hosts = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None
        if ip and ip not in excluded:
            hosts.append(ip)
    return hosts


# === Резолюция credential-набора по IP — тот же приоритет, что в
# NetOpsHub (group_id+range_cidr точный > group_id дефолт > range_cidr
# глобальный > глобальный дефолт) ===


def resolve_credential_set(ip: str, group_id: int | None, sets: list[DomainScanCredentialSet]) -> DomainScanCredentialSet | None:
    def matches_cidr(s: DomainScanCredentialSet) -> bool:
        if not s.range_cidr:
            return False
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(s.range_cidr, strict=False)
        except ValueError:
            return False

    own_group = [s for s in sets if s.group_id == group_id]
    global_sets = [s for s in sets if s.group_id is None]

    for s in own_group:
        if matches_cidr(s):
            return s
    for s in own_group:
        if not s.range_cidr:
            return s
    for s in global_sets:
        if matches_cidr(s):
            return s
    for s in global_sets:
        if not s.range_cidr:
            return s
    return None


async def _check_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


# === Методы опроса — синхронные библиотеки (pywinrm/impacket), крутятся
# через asyncio.to_thread, чтобы не блокировать event loop ===


def _query_winrm_sync(ip: str, domain: str, username: str, password: str) -> dict:
    import winrm

    session = winrm.Session(
        f"https://{ip}:{WINRM_HTTPS_PORT}/wsman",
        auth=(f"{domain}\\{username}", password),
        transport="ntlm",
        server_cert_validation="ignore",
    )
    ps = (
        "$cs = Get-CimInstance Win32_ComputerSystem; "
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "Write-Output ($cs.Domain + '|' + $cs.PartOfDomain + '|' + $cs.Name + '|' + $os.Caption)"
    )
    result = session.run_ps(ps)
    if result.status_code != 0:
        err_text = result.std_err.decode(errors="replace") if result.std_err else "WinRM: ненулевой код возврата"
        raise RuntimeError(err_text[:300])
    parts = result.std_out.decode(errors="replace").strip().split("|")
    if len(parts) < 4:
        raise RuntimeError("WinRM: неожиданный формат ответа PowerShell")
    domain_out, part_of_domain, computer_name, os_caption = parts[0], parts[1], parts[2], parts[3]
    return {
        "domain": domain_out if part_of_domain.strip().lower() == "true" else None,
        "computer_name": computer_name or None,
        "os_caption": os_caption or None,
    }


def _query_smb_sync(ip: str, domain: str | None, username: str, password: str) -> dict:
    from impacket.smbconnection import SMBConnection

    conn = SMBConnection(ip, ip, timeout=5)
    try:
        conn.login(username, password, domain or "")
        server_domain = conn.getServerDNSDomainName() or conn.getServerDomain() or None
        return {"domain": server_domain, "computer_name": conn.getServerName() or None, "os_caption": None}
    finally:
        conn.close()


async def _run_method(method: DomainScanMethod, ip: str, creds: dict | None) -> dict:
    if method == DomainScanMethod.winrm:
        if not creds:
            raise RuntimeError("нет расшифрованной учётки для WinRM")
        return await asyncio.to_thread(_query_winrm_sync, ip, creds["domain"], creds["username"], creds["password"])
    if method == DomainScanMethod.smb_domain:
        if not creds:
            raise RuntimeError("нет расшифрованной учётки для SMB")
        return await asyncio.to_thread(_query_smb_sync, ip, creds["domain"], creds["username"], creds["password"])
    if method == DomainScanMethod.smb_anonymous:
        return await asyncio.to_thread(_query_smb_sync, ip, None, "", "")
    raise RuntimeError(f"неизвестный метод: {method}")


def _credential_dict(cred_set: DomainScanCredentialSet) -> dict | None:
    if not cred_set.domain or not cred_set.username or not cred_set.password:
        return None
    return {"domain": cred_set.domain, "username": cred_set.username, "password": decrypt_secret(cred_set.password)}


async def _probe_host(semaphore: asyncio.Semaphore, ip: str, group_id: int | None, sets: list[DomainScanCredentialSet]) -> dict:
    entry = {
        "address": ip, "computer_name": None, "domain": None, "os_caption": None,
        "status": "error", "error_reason": None, "method_used": None,
    }
    cred_set = resolve_credential_set(ip, group_id, sets)
    if cred_set is None:
        entry["error_reason"] = "нет подходящего credential-набора для этого диапазона"
        return entry

    chain = [cred_set.method]
    if cred_set.fallback_method:
        chain.append(cred_set.fallback_method)
    if DomainScanMethod.smb_anonymous not in chain:
        chain.append(DomainScanMethod.smb_anonymous)

    data = None
    last_error = None
    used_method = None
    async with semaphore:
        for method in chain:
            port = _METHOD_PORT[method]
            if not await _check_port(ip, port):
                last_error = f"порт {port} ({method.value}) недоступен"
                continue
            try:
                creds = _credential_dict(cred_set) if method != DomainScanMethod.smb_anonymous else None
                data = await asyncio.wait_for(_run_method(method, ip, creds), timeout=PROBE_TIMEOUT_SECONDS)
                used_method = method.value
                break
            except Exception as exc:  # noqa: BLE001 — реальная ошибка опроса (неверные креды, RPC недоступен), пробуем следующий метод в цепочке, не роняем весь скан
                msg = str(exc)
                if "STATUS_LOGON_FAILURE" in msg or "rpc_s_access_denied" in msg or "401" in msg:
                    last_error = "неверные учётные данные"
                else:
                    last_error = msg[:200]

    entry["method_used"] = used_method
    if data is None:
        entry["error_reason"] = last_error or "метод(ы) опроса недоступны на этом хосте"
        return entry

    entry["domain"] = data.get("domain")
    entry["os_caption"] = data.get("os_caption")
    computer_name = data.get("computer_name")
    entry["computer_name"] = computer_name
    if entry["domain"] and computer_name and entry["domain"].upper() == computer_name.upper():
        entry["status"] = "error"
        entry["error_reason"] = f'в ответе "домен" совпал с именем компьютера ({computer_name}) — похоже, распознан хост, не AD-домен'
        entry["domain"] = None
    else:
        entry["status"] = "not_in_domain" if not entry["domain"] or entry["domain"].upper() == "WORKGROUP" else "in_domain"
    return entry


async def run_domain_scan(scan_id: int, cidr: str, group_id: int | None, get_session) -> None:
    """Фоновая часть: ping-скан + опрос живых хостов. Своя сессия на
    каждую запись (та же причина, что у Sweep — задачи идут параллельно,
    сессия SQLAlchemy не рассчитана на конкурентный доступ)."""
    db = get_session()
    try:
        scan = db.get(DomainScan, scan_id)
        sets = db.query(DomainScanCredentialSet).filter(
            (DomainScanCredentialSet.group_id == group_id) | (DomainScanCredentialSet.group_id.is_(None))
        ).all()
        if not sets:
            scan.status = ScanStatus.failed
            scan.error = "Ни одного credential-набора не подходит под эту группу — заведи хотя бы один ниже"
            scan.finished_at = _now()
            db.commit()
            return
        try:
            targets = await ping_sweep(cidr)
        except DomainScanValidationError as exc:
            scan.status = ScanStatus.failed
            scan.error = str(exc)
            scan.finished_at = _now()
            db.commit()
            return
        scan.live_hosts = len(targets)
        db.commit()
    finally:
        db.close()

    semaphore = asyncio.Semaphore(MAX_PARALLEL)

    async def _one(ip: str) -> None:
        db2 = get_session()
        try:
            sets2 = db2.query(DomainScanCredentialSet).filter(
                (DomainScanCredentialSet.group_id == group_id) | (DomainScanCredentialSet.group_id.is_(None))
            ).all()
            entry = await _probe_host(semaphore, ip, group_id, sets2)
            db2.add(DomainScanHost(scan_id=scan_id, **entry))
            db2.commit()
        finally:
            db2.close()

    await asyncio.gather(*(_one(ip) for ip in targets), return_exceptions=True)

    db = get_session()
    try:
        scan = db.get(DomainScan, scan_id)
        if scan is not None:
            scan.status = ScanStatus.done
            scan.finished_at = _now()
            db.commit()
    finally:
        db.close()
