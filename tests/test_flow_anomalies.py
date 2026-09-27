"""Эвристики аномалий трафика (port-scan/SYN-скан, rogue DHCP, DHCP
starvation, DNS-аномалия) — flow_alerts_engine.py, доработка 2026-09-27.
Проверяет только чистую логику агрегации/whitelisting на синтетических
FlowRecord, без реальной сети/сервиса (та же фикстура `db`, что и у
остальных тестов — изолированная SQLite-БД в /tmp, см. conftest.py)."""

from __future__ import annotations

import time

from app import flow_alerts_engine as fae
from app.models import FlowRecord, Group, Node, VulnScan, VulnScanStatus, _now
from app.netflow_server import TCP_FLAGS, _FIELD_DECODERS


def test_tcp_flags_decoder_reads_single_byte():
    name, value = _FIELD_DECODERS[TCP_FLAGS](bytes([0x02]))
    assert name == "tcp_flags"
    assert value == 0x02  # SYN


def test_port_scan_detected_with_high_confidence_on_syn_only(db):
    now = _now()
    for port in range(1000, 1020):  # 20 разных портов — выше порога
        db.add(
            FlowRecord(
                exporter_ip="192.0.2.1",
                src_addr="10.1.1.50",
                dst_addr="10.1.1.60",
                src_port=54321,
                dst_port=port,
                protocol=6,
                tcp_flags=0x02,  # SYN без ACK — подпись SYN-скана
                received_at=now,
            )
        )
    db.commit()

    findings = fae._detect_port_scans(db, now)
    assert len(findings) == 1
    assert findings[0]["src_addr"] == "10.1.1.50"
    assert findings[0]["dst_addr"] == "10.1.1.60"
    assert findings[0]["confidence"] == "высокая"


def test_port_scan_not_flagged_for_normal_web_traffic(db):
    now = _now()
    for port in [80, 443]:
        db.add(
            FlowRecord(
                exporter_ip="192.0.2.1",
                src_addr="10.1.1.70",
                dst_addr="10.1.1.80",
                src_port=55000,
                dst_port=port,
                protocol=6,
                tcp_flags=0x10,  # ACK — обычное соединение
                received_at=now,
            )
        )
    db.commit()

    assert fae._detect_port_scans(db, now) == []


def test_port_scan_moderate_confidence_without_tcp_flags(db):
    """Экспортёр не прислал TCP_FLAGS в шаблоне (старое устройство) — эвристика
    по-прежнему видит много портов, но уверенность понижена, не "высокая"."""
    now = _now()
    for port in range(2000, 2020):
        db.add(
            FlowRecord(
                exporter_ip="192.0.2.1",
                src_addr="10.1.1.51",
                dst_addr="10.1.1.61",
                src_port=54322,
                dst_port=port,
                protocol=6,
                tcp_flags=None,
                received_at=now,
            )
        )
    db.commit()

    findings = fae._detect_port_scans(db, now)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "умеренная"


def test_vuln_scan_target_whitelisted_out_of_port_scan(db):
    """Собственный плановый Nuclei/nmap-скан GridForge даёт тот же паттерн
    (много портов одного адреса за короткое время) — не должен алертиться
    как port-scan, если это активный VulnScan на этот же адрес."""
    now = _now()
    group = Group(name="scan-group")
    db.add(group)
    db.commit()
    db.refresh(group)
    db.add(Node(name="target", address="10.1.1.60", group_id=group.id))
    db.add(VulnScan(group_id=group.id, profile="quick", status=VulnScanStatus.running))
    db.commit()

    for port in range(1000, 1020):
        db.add(
            FlowRecord(
                exporter_ip="192.0.2.1",
                src_addr="10.1.1.50",
                dst_addr="10.1.1.60",
                src_port=54321,
                dst_port=port,
                protocol=6,
                tcp_flags=0x02,
                received_at=now,
            )
        )
    db.commit()

    findings = fae._detect_port_scans(db, now)
    assert len(findings) == 1  # находка сама по себе есть...
    assert fae._is_vuln_scan_target(db, findings[0]["dst_addr"], now) is True
    # ...но целиком отфильтровывается в run_due_flow_anomaly_detection (см.
    # _is_vuln_scan_target выше) — здесь проверяем сам предикат whitelisting,
    # оркестратор дальше не дублируем (требует http_client/notify-стек).


def test_rogue_dhcp_detected_and_trusted_excluded(db, monkeypatch):
    monkeypatch.setattr(fae, "_TRUSTED_DHCP_SERVERS", {"10.0.0.1"})
    now = _now()
    db.add(
        FlowRecord(
            exporter_ip="192.0.2.1",
            src_addr="10.1.1.99",
            dst_addr="10.1.1.100",
            src_port=67,
            dst_port=68,
            protocol=17,
            received_at=now,
        )
    )
    db.add(
        FlowRecord(
            exporter_ip="192.0.2.1",
            src_addr="10.0.0.1",  # доверенный — не должен попасть в находки
            dst_addr="10.1.1.101",
            src_port=67,
            dst_port=68,
            protocol=17,
            received_at=now,
        )
    )
    db.commit()

    rogue = fae._detect_rogue_dhcp_servers(db, now)
    assert rogue == ["10.1.1.99"]


def test_dhcp_starvation_detected_above_threshold(db):
    now = _now()
    for _ in range(fae.DHCP_STARVATION_FLOW_THRESHOLD + 5):
        db.add(
            FlowRecord(
                exporter_ip="192.0.2.1",
                src_addr="10.1.1.55",
                dst_addr="10.0.0.1",
                src_port=68,
                dst_port=67,
                protocol=17,
                received_at=now,
            )
        )
    db.commit()

    starv = fae._detect_dhcp_starvation(db, now)
    assert any(addr == "10.1.1.55" and count >= fae.DHCP_STARVATION_FLOW_THRESHOLD for addr, count in starv)


def test_dns_anomaly_detected_above_threshold(db):
    now = _now()
    for i in range(fae.DNS_ANOMALY_DISTINCT_DST_THRESHOLD + 5):
        db.add(
            FlowRecord(
                exporter_ip="192.0.2.1",
                src_addr="10.1.1.77",
                dst_addr=f"8.8.{i}.{i}",
                src_port=51000,
                dst_port=53,
                protocol=17,
                received_at=now,
            )
        )
    db.commit()

    dns = fae._detect_dns_anomalies(db, now)
    assert any(
        addr == "10.1.1.77" and count >= fae.DNS_ANOMALY_DISTINCT_DST_THRESHOLD for addr, count in dns
    )


def test_cooldown_suppresses_repeat_alert_within_window():
    cache: dict = {}
    now_monotonic = time.monotonic()
    assert fae._cooldown_ok(cache, "key", now_monotonic) is True
    assert fae._cooldown_ok(cache, "key", now_monotonic + 1) is False
    # За пределами cooldown-окна — снова можно алертить.
    future = now_monotonic + fae._ANOMALY_ALERT_COOLDOWN_SECONDS + 1
    assert fae._cooldown_ok(cache, "key", future) is True
