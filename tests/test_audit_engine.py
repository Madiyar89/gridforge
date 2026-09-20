from app.audit_engine import run_audit
from app.models import AuditCheckKind, AuditRule, Backup, Node


def _make_node(db, name="LAB-TEST", vendor=None) -> Node:
    node = Node(name=name, address="10.0.0.1", vendor=vendor)
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


def test_no_backup_at_all_gives_single_honest_finding(db):
    node = _make_node(db)
    findings = run_audit(db, node)
    assert len(findings) == 1
    assert findings[0].ok is False
    assert "нет успешного бэкапа" in findings[0].detail
    assert findings[0].rule_id is None


def test_must_contain_rule_passes_when_pattern_present(db):
    node = _make_node(db)
    db.add(Backup(node_id=node.id, content="banner motd ^C Authorized access only ^C", changed=True))
    db.add(AuditRule(name="banner", kind=AuditCheckKind.must_contain, pattern="banner motd", description="есть баннер"))
    db.commit()

    findings = run_audit(db, node)
    assert len(findings) == 1
    assert findings[0].ok is True
    assert "найдено" in findings[0].detail


def test_must_contain_rule_fails_when_pattern_absent(db):
    node = _make_node(db)
    db.add(Backup(node_id=node.id, content="hostname LAB-TEST\nno banner here", changed=True))
    db.add(AuditRule(name="banner", kind=AuditCheckKind.must_contain, pattern="banner motd", description="есть баннер"))
    db.commit()

    findings = run_audit(db, node)
    assert findings[0].ok is False
    assert "не найдено" in findings[0].detail


def test_must_not_contain_rule_flags_forbidden_pattern(db):
    node = _make_node(db)
    db.add(Backup(node_id=node.id, content="line vty 0 4\n transport input telnet", changed=True))
    db.add(AuditRule(name="no-telnet", kind=AuditCheckKind.must_not_contain, pattern="transport input telnet", description="telnet запрещён"))
    db.commit()

    findings = run_audit(db, node)
    assert findings[0].ok is False
    assert "найдено в конфиге" in findings[0].detail


def test_ignores_failed_backup_uses_latest_successful_one(db):
    node = _make_node(db)
    db.add(Backup(node_id=node.id, content="old good config with banner motd", changed=True, error=None))
    db.commit()
    # более свежий бэкап, но с ошибкой — не должен использоваться аудитом
    db.add(Backup(node_id=node.id, content="", changed=False, error="SSH timeout"))
    db.add(AuditRule(name="banner", kind=AuditCheckKind.must_contain, pattern="banner motd", description="есть баннер"))
    db.commit()

    findings = run_audit(db, node)
    assert findings[0].ok is True  # взял старый успешный бэкап, не пустой failed


def test_disabled_rule_is_skipped(db):
    node = _make_node(db)
    db.add(Backup(node_id=node.id, content="anything", changed=True))
    db.add(AuditRule(name="disabled-rule", kind=AuditCheckKind.must_contain, pattern="x", description="x", enabled=False))
    db.commit()

    findings = run_audit(db, node)
    assert findings == []


def test_vendor_specific_rule_only_applies_to_matching_vendor(db):
    from app.models import Vendor

    node_cisco = _make_node(db, name="cisco-node", vendor=Vendor.cisco_ios)
    db.add(Backup(node_id=node_cisco.id, content="anything", changed=True))
    db.add(AuditRule(name="junos-only", kind=AuditCheckKind.must_contain, pattern="x", description="x", vendor=Vendor.junos))
    db.commit()

    findings = run_audit(db, node_cisco)
    assert findings == []  # правило под junos не должно применяться к cisco-узлу


def test_vendor_agnostic_rule_applies_to_every_vendor(db):
    from app.models import Vendor

    node = _make_node(db, vendor=Vendor.cisco_ios)
    db.add(Backup(node_id=node.id, content="has-pattern", changed=True))
    db.add(AuditRule(name="universal", kind=AuditCheckKind.must_contain, pattern="has-pattern", description="x", vendor=None))
    db.commit()

    findings = run_audit(db, node)
    assert len(findings) == 1
    assert findings[0].ok is True


def test_rerun_overwrites_previous_findings_not_appends(db):
    node = _make_node(db)
    db.add(Backup(node_id=node.id, content="banner motd here", changed=True))
    db.add(AuditRule(name="banner", kind=AuditCheckKind.must_contain, pattern="banner motd", description="x"))
    db.commit()

    run_audit(db, node)
    findings_second_run = run_audit(db, node)
    assert len(findings_second_run) == 1  # не 2 — старые находки узла удаляются перед прогоном
