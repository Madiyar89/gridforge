from app.ip_lookup import extract_hints


def test_isc_dhcp_extracts_hostname():
    msg = "DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (client-host) via eth0"
    assert extract_hints(msg) == {"hostname": "client-host", "user": None}


def test_dnsmasq_extracts_hostname():
    msg = "DHCPACK(eth0) 192.168.1.50 aa:bb:cc:dd:ee:ff client-host"
    assert extract_hints(msg) == {"hostname": "client-host", "user": None}


def test_ssh_auth_extracts_user():
    msg = "Accepted password for jdoe from 10.0.0.5 port 51000"
    hints = extract_hints(msg)
    assert hints["user"] == "jdoe"


def test_ssh_auth_publickey_also_matches():
    # \w+ после "Accepted" — не только "password", любой метод (publickey и т.п.)
    msg = "Accepted publickey for admin2 from 10.0.0.6 port 51001"
    assert extract_hints(msg)["user"] == "admin2"


def test_generic_hostname_pattern():
    msg = 'some device log line hostname="LAB-9" other stuff'
    assert extract_hints(msg)["hostname"] == "LAB-9"


def test_dhcp_takes_priority_over_generic_hostname():
    # Оба паттерна совпадают в одном сообщении — DHCP-хостнейм должен победить
    # (порядок проверки в extract_hints: DHCP сначала).
    msg = "DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (real-host) via eth0 hostname=fallback"
    assert extract_hints(msg)["hostname"] == "real-host"


def test_no_match_returns_none_for_both_honestly():
    msg = "completely unrelated log line with no recognizable pattern at all"
    assert extract_hints(msg) == {"hostname": None, "user": None}


def test_empty_string():
    assert extract_hints("") == {"hostname": None, "user": None}
