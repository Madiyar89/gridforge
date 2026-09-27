from app.syslog_server import DetectedSecurityEvent, _detect_security_event, _parse_pri


def test_detects_dai_invalid_arp():
    raw = (
        "<189>1234: *Jan 1 00:00:01.123: %SW_DAI-4-INVALID_ARP: 1 Invalid ARPs "
        "(Res) on Gi1/0/5, vlan 10.([aabb.ccdd.eeff/192.168.1.50/0000.0000.0000/"
        "192.168.1.1/00:00:01 UTC Mon Jan 1 1970])"
    )
    _, _, message = _parse_pri(raw)
    detected = _detect_security_event(message)
    assert isinstance(detected, DetectedSecurityEvent)
    assert detected.kind == "dai_invalid_arp"
    assert "{node}" in detected.description_template


def test_detects_dhcp_snooping_deny():
    raw = (
        "<188>1234: *Jan 1 00:00:02.456: %DHCP_SNOOPING-5-DHCP_SNOOPING_DENY: "
        "DHCP_SNOOPING drop message on untrusted port, message type: DHCPOFFER, "
        "MAC sa: aabb.ccdd.eeff"
    )
    _, _, message = _parse_pri(raw)
    detected = _detect_security_event(message)
    assert isinstance(detected, DetectedSecurityEvent)
    assert detected.kind == "dhcp_snooping_deny"


def test_detects_port_security_violation():
    raw = (
        "<180>1234: *Jan 1 00:00:03.789: %PORT_SECURITY-2-PSECURE_VIOLATION: "
        "Security violation occurred, caused by MAC address aabb.ccdd.eeff on "
        "port GigabitEthernet1/0/10."
    )
    _, _, message = _parse_pri(raw)
    detected = _detect_security_event(message)
    assert isinstance(detected, DetectedSecurityEvent)
    assert detected.kind == "port_security_violation"


def test_ordinary_link_state_message_is_not_flagged():
    raw = (
        "<189>1234: *Jan 1 00:00:04.000: %LINK-3-UPDOWN: Interface "
        "GigabitEthernet1/0/1, changed state to down"
    )
    _, _, message = _parse_pri(raw)
    assert _detect_security_event(message) is None


def test_security_lookalike_but_unlisted_id_is_not_falsely_matched(caplog):
    # %DOT1X-... не входит в список конкретных распознаваемых событий —
    # не должен создавать DetectedSecurityEvent, но должен залогироваться
    # как кандидат на расширение списка (см. _detect_security_event).
    raw = (
        "<188>1234: *Jan 1 00:00:05.000: %DOT1X-5-SUCCESS: Authentication "
        "successful for client aabb.ccdd.eeff"
    )
    _, _, message = _parse_pri(raw)
    with caplog.at_level("INFO", logger="gridforge.syslog"):
        result = _detect_security_event(message)
    assert result is None
    assert any("DOT1X" in record.message for record in caplog.records)
