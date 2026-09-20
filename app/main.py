"""GridForge — точка входа. Своя реализация с нуля (см. README.md), не
основана на коде Zabbix. Планировщик опроса стартует фоновой задачей
вместе с приложением — не отдельный процесс/демон, см. scheduler.py."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, WebSocket
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.auth import bootstrap_first_key, generate_key, require_admin_key, require_api_key
from app.db import get_session, init_db
from app.ad_audit_engine import run_ad_audit
from app.audit_engine import run_audit
from app.capture_engine import CaptureValidationError, analyze_capture, run_capture
from app.console_ws import handle_console
from app.ip_lookup import extract_hints
from app.secrets_crypto import encrypt_secret
from app.backups_engine import diff_backups, run_backup
from app.models import (
    Action,
    ActionRun,
    AdAuditRun,
    AdFinding,
    ApiKey,
    AuditFinding,
    AuditRule,
    Backup,
    Capture,
    CaptureStatus,
    Channel,
    Group,
    Incident,
    Node,
    Probe,
    Sample,
    Scan,
    ScanHost,
    SyslogMessage,
    Template,
    Watch,
)
from app.scan_engine import ScanValidationError, run_scan
from app.scheduler import Scheduler
from app.syslog_server import DEFAULT_SYSLOG_PORT, start_syslog_server
from app.schemas import (
    ActionIn,
    AdAuditIn,
    ApiKeyIn,
    AuditRuleIn,
    BackupTriggerIn,
    CaptureIn,
    ChannelIn,
    GroupIn,
    NodeIn,
    ProbeIn,
    ScanHostToNodeIn,
    ScanIn,
    TemplateApplyIn,
    TemplateIn,
    WatchIn,
)
from app.templates_engine import TemplateValidationError, apply_template, validate_probe_defs

_scheduler = Scheduler()


def _db() -> Session:
    db = get_session()
    try:
        yield db
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = get_session()
    try:
        raw_key = bootstrap_first_key(db)
    finally:
        db.close()
    if raw_key:
        print(
            "\n"
            "=================================================================\n"
            f"  Первый API-ключ GridForge, роль admin (сохрани — второй раз не покажется):\n"
            f"  {raw_key}\n"
            "  Использовать: заголовок 'X-API-Key: <ключ>' на каждый /api/ запрос.\n"
            "=================================================================\n"
        )
    task = asyncio.create_task(_scheduler.run_forever())
    syslog_transport = await start_syslog_server()
    yield
    syslog_transport.close()
    _scheduler.stop()
    await task


app = FastAPI(title="GridForge", lifespan=lifespan)

# read: любой действующий ключ (admin или viewer). write: только admin —
# viewer может смотреть Node/Probe/Sample/Watch/Incident/Channel, но не
# создавать/удалять их и не управлять ключами (см. app/auth.py).
api_read = APIRouter(dependencies=[Depends(require_api_key)])
api_write = APIRouter(dependencies=[Depends(require_admin_key)])


@api_write.post("/api/groups", status_code=201)
def create_group(payload: GroupIn, db: Session = Depends(_db)):
    if db.query(Group).filter(Group.name == payload.name).first() is not None:
        raise HTTPException(status_code=409, detail="Группа с таким именем уже есть")
    group = Group(name=payload.name)
    db.add(group)
    db.commit()
    db.refresh(group)
    return {"id": group.id}


@api_read.get("/api/groups")
def list_groups(db: Session = Depends(_db)):
    return [
        {"id": g.id, "name": g.name, "node_count": len(g.nodes)}
        for g in db.query(Group).order_by(Group.name).all()
    ]


@api_write.delete("/api/groups/{group_id}", status_code=204)
def delete_group(group_id: int, db: Session = Depends(_db)):
    """Только пустую группу — те же основания, что и NetworkGroup в
    NetOpsHub (409, не тихое удаление вместе с узлами)."""
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Группа не найдена")
    if group.nodes:
        raise HTTPException(status_code=409, detail=f"В группе ещё {len(group.nodes)} узел(ов) — сначала перенеси/удали их")
    db.delete(group)
    db.commit()


@api_write.post("/api/nodes", status_code=201)
def create_node(payload: NodeIn, db: Session = Depends(_db)):
    if payload.group_id is not None and db.get(Group, payload.group_id) is None:
        raise HTTPException(status_code=404, detail="Group не найдена")
    node = Node(
        name=payload.name,
        address=payload.address,
        tags=payload.tags,
        group_id=payload.group_id,
        vendor=payload.vendor,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return {"id": node.id}


@api_read.get("/api/nodes")
def list_nodes(group_id: int | None = None, db: Session = Depends(_db)):
    query = db.query(Node)
    if group_id is not None:
        query = query.filter(Node.group_id == group_id)
    return [
        {
            "id": n.id,
            "name": n.name,
            "address": n.address,
            "tags": n.tags,
            "group_id": n.group_id,
            "group_name": n.group.name if n.group else None,
            "vendor": n.vendor.value if n.vendor else None,
            "active": n.active,
        }
        for n in query.order_by(Node.name).all()
    ]


@api_write.post("/api/probes", status_code=201)
def create_probe(payload: ProbeIn, db: Session = Depends(_db)):
    if db.get(Node, payload.node_id) is None:
        raise HTTPException(status_code=404, detail="Node не найден")
    params = dict(payload.params)
    for secret_field in ("password", "auth_password", "priv_password"):
        if params.get(secret_field):
            params[secret_field] = encrypt_secret(params[secret_field])
    probe = Probe(
        node_id=payload.node_id,
        kind=payload.kind,
        params=params,
        interval_seconds=payload.interval_seconds,
        timeout_seconds=payload.timeout_seconds,
    )
    db.add(probe)
    db.commit()
    db.refresh(probe)
    return {"id": probe.id}


@api_read.get("/api/nodes/{node_id}/probes")
def list_node_probes(node_id: int, db: Session = Depends(_db)):
    """Для веб-интерфейса (static/app.js) — Probe каждого Node вместе с
    последней Sample, чтобы не делать по отдельному запросу на probe."""
    probes = db.query(Probe).filter(Probe.node_id == node_id).all()
    result = []
    for p in probes:
        latest = (
            db.query(Sample)
            .filter(Sample.probe_id == p.id)
            .order_by(desc(Sample.taken_at))
            .first()
        )
        result.append(
            {
                "id": p.id,
                "kind": p.kind.value,
                "interval_seconds": p.interval_seconds,
                "enabled": p.enabled,
                "latest_sample": (
                    {"ok": latest.ok, "value": latest.value, "detail": latest.detail, "taken_at": latest.taken_at.isoformat()}
                    if latest
                    else None
                ),
            }
        )
    return result


@api_read.get("/api/probes/{probe_id}/samples")
def probe_samples(probe_id: int, limit: int = 50, db: Session = Depends(_db)):
    rows = (
        db.query(Sample)
        .filter(Sample.probe_id == probe_id)
        .order_by(desc(Sample.taken_at))
        .limit(limit)
        .all()
    )
    return [
        {"taken_at": s.taken_at.isoformat(), "ok": s.ok, "value": s.value, "detail": s.detail}
        for s in rows
    ]


@api_write.post("/api/watches", status_code=201)
def create_watch(payload: WatchIn, db: Session = Depends(_db)):
    if db.get(Probe, payload.probe_id) is None:
        raise HTTPException(status_code=404, detail="Probe не найден")
    watch = Watch(
        probe_id=payload.probe_id,
        operator=payload.operator,
        threshold=payload.threshold,
        streak_required=payload.streak_required,
        severity=payload.severity,
        label=payload.label,
    )
    db.add(watch)
    db.commit()
    db.refresh(watch)
    return {"id": watch.id}


@api_read.get("/api/probes/{probe_id}/watches")
def list_probe_watches(probe_id: int, db: Session = Depends(_db)):
    """Для инвентаря на сайте (static/inventory.js) — список условий под
    каждой проверкой, с количеством уже настроенных действий (Action), не
    только сам факт существования Watch."""
    watches = db.query(Watch).filter(Watch.probe_id == probe_id).all()
    result = []
    for w in watches:
        action_count = db.query(Action).filter(Action.watch_id == w.id).count()
        result.append(
            {
                "id": w.id,
                "label": w.label,
                "operator": w.operator.value,
                "threshold": w.threshold,
                "severity": w.severity.value,
                "action_count": action_count,
            }
        )
    return result


@api_read.get("/api/incidents")
def list_incidents(include_resolved: bool = False, db: Session = Depends(_db)):
    query = db.query(Incident)
    if not include_resolved:
        query = query.filter(Incident.resolved_at.is_(None))
    rows = query.order_by(desc(Incident.opened_at)).all()
    result = []
    for i in rows:
        result.append(
            {
                "id": i.id,
                "watch_id": i.watch_id,
                "severity": i.watch.severity.value,
                "label": i.watch.label,
                "detail": i.detail,
                "opened_at": i.opened_at.isoformat(),
                "last_seen_at": i.last_seen_at.isoformat(),
                "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
            }
        )
    return result


@api_write.post("/api/channels", status_code=201)
def create_channel(payload: ChannelIn, db: Session = Depends(_db)):
    channel = Channel(kind=payload.kind, config=payload.config, min_severity=payload.min_severity)
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return {"id": channel.id}


@api_read.get("/api/channels")
def list_channels(db: Session = Depends(_db)):
    return [
        {"id": c.id, "kind": c.kind.value, "config": c.config, "enabled": c.enabled, "min_severity": c.min_severity.value}
        for c in db.query(Channel).all()
    ]


@api_write.delete("/api/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: int, db: Session = Depends(_db)):
    channel = db.get(Channel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel не найден")
    db.delete(channel)
    db.commit()


@api_write.post("/api/templates", status_code=201)
def create_template(payload: TemplateIn, db: Session = Depends(_db)):
    if db.query(Template).filter(Template.name == payload.name).first() is not None:
        raise HTTPException(status_code=409, detail="Шаблон с таким именем уже есть")
    try:
        validate_probe_defs(payload.probe_defs)
    except TemplateValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    template = Template(name=payload.name, vendor=payload.vendor, probe_defs=payload.probe_defs)
    db.add(template)
    db.commit()
    db.refresh(template)
    return {"id": template.id}


@api_read.get("/api/templates")
def list_templates(db: Session = Depends(_db)):
    return [
        {
            "id": t.id,
            "name": t.name,
            "vendor": t.vendor.value if t.vendor else None,
            "probe_count": len(t.probe_defs),
        }
        for t in db.query(Template).order_by(Template.name).all()
    ]


@api_write.delete("/api/templates/{template_id}", status_code=204)
def delete_template(template_id: int, db: Session = Depends(_db)):
    template = db.get(Template, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    db.delete(template)
    db.commit()


@api_write.post("/api/templates/{template_id}/apply")
def apply_template_endpoint(template_id: int, payload: TemplateApplyIn, db: Session = Depends(_db)):
    template = db.get(Template, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    if db.get(Node, payload.node_id) is None:
        raise HTTPException(status_code=404, detail="Node не найден")
    return apply_template(db, template, payload.node_id)


@api_write.post("/api/actions", status_code=201)
def create_action(payload: ActionIn, db: Session = Depends(_db)):
    if db.get(Watch, payload.watch_id) is None:
        raise HTTPException(status_code=404, detail="Watch не найден")
    config = dict(payload.config)
    if config.get("password"):
        config["password"] = encrypt_secret(config["password"])
    action = Action(watch_id=payload.watch_id, kind=payload.kind, config=config)
    db.add(action)
    db.commit()
    db.refresh(action)
    return {"id": action.id}


@api_read.get("/api/actions")
def list_actions(watch_id: int | None = None, db: Session = Depends(_db)):
    query = db.query(Action)
    if watch_id is not None:
        query = query.filter(Action.watch_id == watch_id)
    def _safe_config(config: dict) -> dict:
        return {k: ("***" if k == "password" else v) for k, v in config.items()}

    return [
        {"id": a.id, "watch_id": a.watch_id, "kind": a.kind.value, "config": _safe_config(a.config), "enabled": a.enabled}
        for a in query.all()
    ]


@api_write.delete("/api/actions/{action_id}", status_code=204)
def delete_action(action_id: int, db: Session = Depends(_db)):
    action = db.get(Action, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="Action не найден")
    db.delete(action)
    db.commit()


@api_read.get("/api/incidents/{incident_id}/action-runs")
def list_action_runs(incident_id: int, db: Session = Depends(_db)):
    rows = db.query(ActionRun).filter(ActionRun.incident_id == incident_id).order_by(ActionRun.started_at.desc()).all()
    return [
        {"id": r.id, "action_id": r.action_id, "started_at": r.started_at.isoformat(), "ok": r.ok, "output": r.output}
        for r in rows
    ]


@api_write.post("/api/nodes/{node_id}/backup", status_code=201)
async def trigger_backup(node_id: int, payload: BackupTriggerIn, db: Session = Depends(_db)):
    node = db.get(Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node не найден")
    backup = await run_backup(
        db, node,
        username=payload.username, command=payload.command,
        key_path=payload.key_path, password=payload.password, port=payload.port,
    )
    return {"id": backup.id, "changed": backup.changed, "error": backup.error}


@api_read.get("/api/nodes/{node_id}/backups")
def list_backups(node_id: int, db: Session = Depends(_db)):
    rows = (
        db.query(Backup)
        .filter(Backup.node_id == node_id)
        .order_by(desc(Backup.taken_at))
        .all()
    )
    return [
        {"id": b.id, "taken_at": b.taken_at.isoformat(), "changed": b.changed, "error": b.error, "size": len(b.content)}
        for b in rows
    ]


@api_read.get("/api/backups/{backup_id}")
def get_backup(backup_id: int, db: Session = Depends(_db)):
    backup = db.get(Backup, backup_id)
    if backup is None:
        raise HTTPException(status_code=404, detail="Бэкап не найден")
    return {"id": backup.id, "node_id": backup.node_id, "taken_at": backup.taken_at.isoformat(), "content": backup.content, "changed": backup.changed, "error": backup.error}


@api_read.get("/api/backups/{backup_id}/diff")
def get_backup_diff(backup_id: int, db: Session = Depends(_db)):
    """Diff против предыдущего УСПЕШНОГО снимка того же узла (см.
    backups_engine.run_backup — та же логика поиска "previous")."""
    backup = db.get(Backup, backup_id)
    if backup is None:
        raise HTTPException(status_code=404, detail="Бэкап не найден")
    previous = (
        db.query(Backup)
        .filter(Backup.node_id == backup.node_id, Backup.error.is_(None), Backup.taken_at < backup.taken_at)
        .order_by(desc(Backup.taken_at))
        .first()
    )
    if previous is None:
        return {"diff": None, "detail": "Это первый снимок узла — сравнивать не с чем"}
    return {"diff": diff_backups(previous.content, backup.content)}


@api_write.post("/api/audit-rules", status_code=201)
def create_audit_rule(payload: AuditRuleIn, db: Session = Depends(_db)):
    rule = AuditRule(
        name=payload.name, vendor=payload.vendor, kind=payload.kind,
        pattern=payload.pattern, severity=payload.severity, description=payload.description,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {"id": rule.id}


@api_read.get("/api/audit-rules")
def list_audit_rules(db: Session = Depends(_db)):
    return [
        {
            "id": r.id, "name": r.name, "vendor": r.vendor.value if r.vendor else None,
            "kind": r.kind.value, "pattern": r.pattern, "severity": r.severity.value,
            "description": r.description, "enabled": r.enabled,
        }
        for r in db.query(AuditRule).order_by(AuditRule.name).all()
    ]


@api_write.delete("/api/audit-rules/{rule_id}", status_code=204)
def delete_audit_rule(rule_id: int, db: Session = Depends(_db)):
    rule = db.get(AuditRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Правило не найдено")
    db.delete(rule)
    db.commit()


@api_write.post("/api/nodes/{node_id}/audit")
def trigger_audit(node_id: int, db: Session = Depends(_db)):
    node = db.get(Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="Node не найден")
    findings = run_audit(db, node)
    rules_by_id = {r.id: r for r in db.query(AuditRule).all()}
    result = []
    for f in findings:
        rule = rules_by_id.get(f.rule_id) if f.rule_id else None
        result.append(
            {
                "id": f.id, "rule_name": rule.name if rule else "нет бэкапа",
                "severity": rule.severity.value if rule else "critical",
                "ok": f.ok, "detail": f.detail,
            }
        )
    return result


@api_read.get("/api/nodes/{node_id}/audit")
def get_audit_findings(node_id: int, db: Session = Depends(_db)):
    findings = db.query(AuditFinding).filter(AuditFinding.node_id == node_id).order_by(AuditFinding.checked_at.desc()).all()
    rules_by_id = {r.id: r for r in db.query(AuditRule).all()}
    result = []
    for f in findings:
        rule = rules_by_id.get(f.rule_id) if f.rule_id else None
        result.append(
            {
                "id": f.id, "rule_name": rule.name if rule else "нет бэкапа",
                "severity": rule.severity.value if rule else "critical",
                "ok": f.ok, "detail": f.detail, "checked_at": f.checked_at.isoformat(),
            }
        )
    return result


@api_write.post("/api/scans", status_code=201)
async def create_scan(payload: ScanIn, db: Session = Depends(_db)):
    try:
        scan = await run_scan(db, payload.cidr, payload.ports)
    except ScanValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": scan.id, "status": scan.status.value, "error": scan.error, "host_count": len(scan.hosts)}


@api_read.get("/api/scans")
def list_scans(db: Session = Depends(_db)):
    return [
        {
            "id": s.id, "cidr": s.cidr, "status": s.status.value,
            "started_at": s.started_at.isoformat(),
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "error": s.error, "host_count": len(s.hosts),
        }
        for s in db.query(Scan).order_by(desc(Scan.started_at)).all()
    ]


@api_read.get("/api/scans/{scan_id}/hosts")
def list_scan_hosts(scan_id: int, db: Session = Depends(_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Скан не найден")
    existing_addresses = {n.address for n in db.query(Node).all()}
    return [
        {
            "id": h.id, "address": h.address, "hostname": h.hostname,
            "open_ports": h.open_ports, "already_node": h.address in existing_addresses,
        }
        for h in scan.hosts
    ]


@api_write.post("/api/scan-hosts/{host_id}/create-node", status_code=201)
def create_node_from_scan_host(host_id: int, payload: ScanHostToNodeIn, db: Session = Depends(_db)):
    host = db.get(ScanHost, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Хост не найден")
    node = Node(
        name=payload.name or host.hostname or host.address,
        address=host.address,
        group_id=payload.group_id,
        vendor=payload.vendor,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return {"id": node.id}


@api_write.post("/api/ad-audit", status_code=201)
async def trigger_ad_audit(payload: AdAuditIn, db: Session = Depends(_db)):
    """Учётка для LDAP-подключения нигде не сохраняется — используется
    один раз для этого прогона и не попадает в БД (см. AdAuditRun)."""
    run = await run_ad_audit(db, payload.server, payload.bind_dn, payload.bind_password, payload.search_base, payload.port)
    findings = db.query(AdFinding).filter(AdFinding.run_id == run.id).all()
    return {
        "id": run.id, "ok": run.ok, "error": run.error,
        "findings": [
            {"id": f.id, "check_name": f.check_name, "severity": f.severity.value, "dn": f.dn, "detail": f.detail}
            for f in findings
        ],
    }


@api_read.get("/api/ad-audit/runs")
def list_ad_audit_runs(db: Session = Depends(_db)):
    return [
        {
            "id": r.id, "server": r.server, "search_base": r.search_base,
            "started_at": r.started_at.isoformat(), "ok": r.ok, "error": r.error,
            "finding_count": len(r.findings),
        }
        for r in db.query(AdAuditRun).order_by(AdAuditRun.started_at.desc()).all()
    ]


@api_read.get("/api/ad-audit/runs/{run_id}/findings")
def get_ad_audit_findings(run_id: int, db: Session = Depends(_db)):
    findings = db.query(AdFinding).filter(AdFinding.run_id == run_id).all()
    return [
        {"id": f.id, "check_name": f.check_name, "severity": f.severity.value, "dn": f.dn, "detail": f.detail}
        for f in findings
    ]


@api_write.post("/api/api-keys", status_code=201)
def create_api_key(payload: ApiKeyIn, db: Session = Depends(_db)):
    """Только admin создаёт новые ключи (в т.ч. другие admin-ключи или
    viewer-ключи для read-only интеграций). Сырое значение показывается
    ровно здесь и один раз, дальше — только хеш в БД."""
    raw_key = generate_key(db, label=payload.label, role=payload.role)
    return {"key": raw_key, "label": payload.label, "role": payload.role.value}


@api_read.get("/api/api-keys")
def list_api_keys(admin: ApiKey = Depends(require_admin_key), db: Session = Depends(_db)):
    """Список без самих ключей (необратимо хешированы) — только метаданные.
    Явный Depends(require_admin_key) поверх api_read: viewer видит другие
    эндпоинты этого роутера, но не список ключей доступа."""
    return [
        {"id": k.id, "label": k.label, "role": k.role.value, "created_at": k.created_at.isoformat(), "revoked": k.revoked}
        for k in db.query(ApiKey).all()
    ]


@api_write.post("/api/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: int, db: Session = Depends(_db)):
    key = db.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(status_code=404, detail="Ключ не найден")
    key.revoked = True
    db.commit()
    return {"status": "revoked"}


@api_read.get("/api/syslog")
def list_syslog(node_id: int | None = None, source_ip: str | None = None, limit: int = 100, db: Session = Depends(_db)):
    query = db.query(SyslogMessage)
    if node_id is not None:
        query = query.filter(SyslogMessage.node_id == node_id)
    if source_ip is not None:
        query = query.filter(SyslogMessage.source_ip == source_ip)
    rows = query.order_by(desc(SyslogMessage.received_at)).limit(min(limit, 500)).all()
    return [
        {
            "id": m.id, "node_id": m.node_id, "source_ip": m.source_ip,
            "received_at": m.received_at.isoformat(), "facility": m.facility,
            "severity": m.severity, "message": m.message,
        }
        for m in rows
    ]


@api_read.get("/api/ip-lookup")
def ip_lookup(q: str, limit: int = 50, db: Session = Depends(_db)):
    """Своя версия Graylog IP-лукапа из NetOpsHub — поиск по уже принятым
    SyslogMessage (см. app/ip_lookup.py). q — IP (точное совпадение
    source_ip) или произвольный текст (подстрока в message)."""
    query = db.query(SyslogMessage).filter(
        (SyslogMessage.source_ip == q) | (SyslogMessage.message.contains(q))
    )
    rows = query.order_by(desc(SyslogMessage.received_at)).limit(min(limit, 200)).all()

    hostnames: set[str] = set()
    users: set[str] = set()
    matches = []
    for m in rows:
        hints = extract_hints(m.message)
        if hints["hostname"]:
            hostnames.add(hints["hostname"])
        if hints["user"]:
            users.add(hints["user"])
        matches.append(
            {
                "id": m.id, "source_ip": m.source_ip, "node_id": m.node_id,
                "received_at": m.received_at.isoformat(), "message": m.message,
                "hostname_hint": hints["hostname"], "user_hint": hints["user"],
            }
        )

    return {
        "query": q,
        "match_count": len(matches),
        "hostnames": sorted(hostnames),
        "users": sorted(users),
        "matches": matches,
    }


@api_write.post("/api/captures", status_code=201)
async def create_capture(payload: CaptureIn, db: Session = Depends(_db)):
    try:
        capture = await run_capture(db, payload.interface, payload.bpf_filter, payload.duration_seconds)
    except CaptureValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": capture.id, "status": capture.status.value, "packet_count": capture.packet_count, "error": capture.error}


@api_read.get("/api/captures")
def list_captures(db: Session = Depends(_db)):
    return [
        {
            "id": c.id, "interface": c.interface, "bpf_filter": c.bpf_filter,
            "duration_seconds": c.duration_seconds, "status": c.status.value,
            "started_at": c.started_at.isoformat(), "packet_count": c.packet_count, "error": c.error,
        }
        for c in db.query(Capture).order_by(desc(Capture.started_at)).all()
    ]


@api_read.get("/api/captures/{capture_id}/analyze")
async def analyze_capture_endpoint(capture_id: int, method: str = "protocols", db: Session = Depends(_db)):
    capture = db.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail="Захват не найден")
    if capture.status != CaptureStatus.done:
        raise HTTPException(status_code=409, detail=f"Захват в статусе {capture.status.value}, анализировать нечего")
    output = await analyze_capture(capture, method)
    return {"method": method, "output": output}


@app.get("/api/health")
def health():
    return {"status": "ok"}


app.include_router(api_read)
app.include_router(api_write)


@app.websocket("/ws/console")
async def ws_console(websocket: WebSocket):
    """Авторизация — внутри handle_console (первое сообщение, не
    HTTP-заголовок — WebSocket из браузера не даёт произвольных заголовков
    без ручного клиента), см. app/console_ws.py."""
    await handle_console(websocket)

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="static")
