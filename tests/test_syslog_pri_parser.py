from app.syslog_server import _parse_pri


def test_pri_present_splits_facility_severity_and_message():
    # <134> = facility 16 (local0), severity 6 (info): 16*8+6=134
    facility, severity, message = _parse_pri("<134>Oct 10 10:00:00 host: something happened")
    assert facility == 16
    assert severity == 6
    assert message == "Oct 10 10:00:00 host: something happened"


def test_pri_absent_keeps_whole_message_and_returns_none():
    facility, severity, message = _parse_pri("just a plain log line, no PRI header at all")
    assert facility is None
    assert severity is None
    assert message == "just a plain log line, no PRI header at all"


def test_pri_strips_leading_whitespace_after_bracket():
    _, _, message = _parse_pri("<13>   spaced out message")
    assert message == "spaced out message"


def test_pri_zero_is_valid_not_treated_as_absent():
    # <0> = facility 0, severity 0 (kernel emergency) — валидный PRI,
    # не должен ошибочно считаться "нет PRI" из-за falsy-значений.
    facility, severity, message = _parse_pri("<0>kernel panic")
    assert facility == 0
    assert severity == 0
    assert message == "kernel panic"


def test_pri_max_facility_and_severity():
    # <191> = facility 23 (local7), severity 7 (debug) — верхняя граница.
    facility, severity, _ = _parse_pri("<191>debug message")
    assert facility == 23
    assert severity == 7
