"""Проверки VLAN/подсети (docs/landscape-report.md, запрос пользователя
2026-09-25 — "не только узлы коммутаторов проверять"): доступность
шлюза и скан живых адресов в подсети. Оба переиспользуют уже
существующие исполнители — icmp_ping из app/probes.py (тот же, что у
обычных Probe) и Scan/ScanHost из app/scan_engine.py (тот же nmap
ping-скан, что у "Обнаружение сети"/Sweep) — свой отдельный сканер тут
не нужен."""

from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from app.models import ProbeKind, Vlan, _now
from app.probes import run_probe

GATEWAY_PING_TIMEOUT_SECONDS = 3.0


def usable_address_count(cidr: str) -> int:
    """Хосты без адреса сети/broadcast — для /31 и /32 (точка-точка,
    один адрес) считаем все адреса, вычитать нечего."""
    net = ipaddress.ip_network(cidr, strict=False)
    return net.num_addresses if net.num_addresses <= 2 else net.num_addresses - 2


async def check_vlan_gateway(db: Session, vlan: Vlan) -> None:
    if not vlan.gateway:
        vlan.gateway_ok = None
        vlan.gateway_detail = None
        vlan.gateway_checked_at = None
        db.commit()
        return
    outcome = await run_probe(ProbeKind.icmp_ping, vlan.gateway, {}, GATEWAY_PING_TIMEOUT_SECONDS)
    vlan.gateway_ok = outcome.ok
    vlan.gateway_detail = outcome.detail
    vlan.gateway_checked_at = _now()
    db.commit()
