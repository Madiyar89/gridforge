"""GridForge — точка входа. Своя реализация с нуля (см. README.md), не
основана на коде Zabbix. Планировщик опроса стартует фоновой задачей
вместе с приложением — не отдельный процесс/демон, см. scheduler.py."""

from __future__ import annotations

import asyncio
import secrets
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import APIRouter, Cookie, Depends, FastAPI, HTTPException, Response, WebSocket
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.auth import (
    bootstrap_first_key,
    generate_key,
    Principal,
    key_sees_group,
    require_admin_key,
    require_api_key,
    require_backup_access,
    require_node_access,
    require_operator_key,
    require_probe_access,
    scope_nodes,
)
from app.db import get_session, init_db
from app.scenario_catalog import seed_default_scenarios
from app.ad_audit_engine import run_ad_audit, run_ad_audit_fleet_report
from app.network_audit_engine import build_network_audit_fleet_report
from app.ad_auth import ad_enabled, check_ad_credentials, sync_ad_user
from app.audit_engine import run_audit
from app.dashboard_engine import build_dashboard
from app.capture_engine import CaptureValidationError, analyze_capture, run_capture
from app.console_ws import handle_console
from app.ip_lookup import extract_hints
from app.passwords import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    hash_password,
    is_default_password,
    password_problem,
    verify_password,
)
from app.secrets_crypto import encrypt_secret
from app.sessions import (
    COOKIE_NAME,
    SESSION_TTL,
    bootstrap_first_user,
    create_session,
    revoke_all_for_user,
    revoke_session,
)
from app.signal import encrypt_channel_config, mask_channel_config
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
    Credential,
    EscalationStep,
    Group,
    Incident,
    Integration,
    LdapConnection,
    Node,
    Probe,
    Sample,
    Scan,
    ScanHost,
    Scenario,
    ScenarioResult,
    ScenarioRun,
    Sweep,
    SweepResult,
    SyslogMessage,
    Template,
    User,
    Watch,
    iso,
)
from app.inventory_engine import delete_node, delete_probe, delete_watch
from app.retention_engine import run_retention
from app.port_security import parse_port_protection, parse_stp_global, protection_summary
from app.port_commands import PortCommandError, apply_port, bounce_port
from app.stp_protection import StpProtectionError, apply_stp_protection
from app.credentials_engine import encrypt_password, mask_credential, resolve_credential
from app.integrations_engine import INTEGRATION_REGISTRY, IntegrationTestError, encrypt_token
from app.ldap_engine import LdapTestError, mask_connection, test_bind
from app.ldap_engine import encrypt_password as encrypt_ldap_password
from app.ports_engine import Port, collect_ports, group_ports, latest_snapshot
from app.scan_engine import ScanValidationError, run_scan
from app.sweep_commands import CommandRejected, command_for_node, preset_catalog, validate_custom_command
from app.sweep_engine import run_sweep, sweep_progress
from app.scenarios_engine import ScenarioParamError, render_command, run_scenario, scenario_run_progress
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
    CredentialIn,
    EscalationStepIn,
    GroupIn,
    IntegrationIn,
    LdapConnectionIn,
    LoginIn,
    NodeIn,
    NodeUpdateIn,
    PasswordChangeIn,
    PortApplyIn,
    PortBounceIn,
    PortRefreshIn,
    ProbeIn,
    ScanHostToNodeIn,
    ScanIn,
    ScenarioIn,
    ScenarioRunIn,
    StpProtectionApplyIn,
    SweepIn,
    TemplateApplyIn,
    TemplateIn,
    UserIn,
    WatchIn,
)
from app.templates_engine import TemplateValidationError, apply_template, validate_probe_defs

_scheduler = Scheduler()

# Хеш заведомо недостижимого пароля. Нужен, чтобы вход с НЕсуществующим
# логином занимал столько же времени, сколько с существующим: иначе по
# скорости ответа перебором выясняются заведённые логины, не зная ни
# одного пароля. Считается один раз при импорте — scrypt небесплатный.
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def _db() -> Session:
    db = get_session()
    try:
        yield db
    finally:
        db.close()


def _resolve_node_credential(db: Session, node: Node, payload) -> tuple[str, str | None, str | None]:
    """username/password/key_path для запроса к одному узлу: явно
    переданные в теле запроса — в приоритете (ручной override как
    раньше), иначе центральная учётка (Credential, см.
    credentials_engine.resolve_credential). 422, если нет ни того, ни
    другого — тот же текст ошибки везде, где вызывается."""
    if payload.username:
        return payload.username, payload.password, payload.key_path
    cred = resolve_credential(db, node)
    if cred is None:
        raise HTTPException(
            status_code=422,
            detail="нужен логин — укажи явно или настрой центральную учётку в Настройки → Учётки",
        )
    return cred["username"], cred["password"], cred["key_path"]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = get_session()
    seed_default_scenarios(db)
    try:
        raw_key = bootstrap_first_key(db)
        created_admin = bootstrap_first_user(db)
        default_password_still_set = any(
            is_default_password(u.password_hash)
            for u in db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).all()
        )
    finally:
        db.close()
    if created_admin:
        print(
            "\n"
            "=================================================================\n"
            f"  Вход в веб-интерфейс: логин {DEFAULT_ADMIN_USERNAME}, пароль {DEFAULT_ADMIN_PASSWORD}\n"
            "  СМЕНИ ПАРОЛЬ СРАЗУ ПОСЛЕ ПЕРВОГО ВХОДА — он общеизвестен.\n"
            "=================================================================\n",
            flush=True,
        )
    elif default_password_still_set:
        # Напоминаем при каждом старте, пока пароль не сменён: одно
        # сообщение при установке слишком легко пролистать, а учётка с
        # общеизвестным паролем — это открытая дверь в сеть.
        print(
            f"\n  ВНИМАНИЕ: у пользователя {DEFAULT_ADMIN_USERNAME} всё ещё стоит пароль по умолчанию. Смени его.\n",
            flush=True,
        )
    if raw_key:
        # Реальный найденный баг (2026-09-20): под nohup/systemd/Docker
        # (stdout не TTY) print() без flush=True может не долетать до
        # лога вообще — проверено полным циклом старт→graceful shutdown
        # против реальной MariaDB, строка не появилась ни разу, хотя
        # остальные (uvicorn, через logging) появлялись. Не полагаемся
        # только на консоль — тот же ключ пишется в файл, читаемый только
        # владельцем; убрать файл после того, как ключ сохранён.
        print(
            "\n"
            "=================================================================\n"
            f"  Первый API-ключ GridForge, роль admin (сохрани — второй раз не покажется):\n"
            f"  {raw_key}\n"
            "  Использовать: заголовок 'X-API-Key: <ключ>' на каждый /api/ запрос.\n"
            "=================================================================\n",
            flush=True,
        )
        bootstrap_key_path = Path(__file__).resolve().parent.parent / "data" / "BOOTSTRAP_ADMIN_KEY_DELETE_ME.txt"
        bootstrap_key_path.write_text(raw_key + "\n", encoding="utf-8")
        bootstrap_key_path.chmod(0o600)
    task = asyncio.create_task(_scheduler.run_forever())
    syslog_transport = await start_syslog_server()
    yield
    syslog_transport.close()
    _scheduler.stop()
    await task


app = FastAPI(title="GridForge", lifespan=lifespan)

# Три уровня доступа (см. app/auth.py, ROLE_RANK):
#   api_read    — любой действующий ключ: смотреть Node/Probe/Sample/
#                 Watch/Incident/Channel и историю.
#   api_operate — operator и выше: ЗАПУСК операций на оборудовании (снять
#                 бэкап, прогнать аудит, скан сети, захват трафика). Сами
#                 по себе ничего не меняют в конфигурации GridForge, но
#                 лезут на боевые устройства — viewer'у их давать нельзя.
#   api_write   — только admin: инвентарь, правила, каналы, шаблоны,
#                 действия и выдача ключей доступа.
api_read = APIRouter(dependencies=[Depends(require_api_key)])
api_operate = APIRouter(dependencies=[Depends(require_operator_key)])
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


@api_write.post("/api/credentials", status_code=201)
def upsert_credential(payload: CredentialIn, db: Session = Depends(_db)):
    """Заводит или заменяет центральную учётку — на конкретный узел
    (node_id), на группу (group_id), на вендор (vendor) или по умолчанию
    (все три None). Ровно одна учётка на каждую область — новый POST с
    теми же node_id/group_id/vendor заменяет старую, а не плодит
    дубликаты (иначе resolve_credential получал бы неоднозначный выбор
    между несколькими записями)."""
    scopes_set = sum(x is not None for x in (payload.node_id, payload.group_id, payload.vendor))
    if scopes_set > 1:
        raise HTTPException(status_code=422, detail="Укажи только одно из node_id/group_id/vendor")
    if payload.node_id is not None and db.get(Node, payload.node_id) is None:
        raise HTTPException(status_code=404, detail="Узел не найден")
    if payload.group_id is not None and db.get(Group, payload.group_id) is None:
        raise HTTPException(status_code=404, detail="Группа не найдена")
    existing = db.query(Credential).filter(
        Credential.node_id == payload.node_id,
        Credential.group_id == payload.group_id,
        Credential.vendor == payload.vendor,
    ).first()
    if existing is not None:
        db.delete(existing)
        db.flush()
    cred = Credential(
        group_id=payload.group_id,
        node_id=payload.node_id,
        vendor=payload.vendor,
        label=payload.label,
        username=payload.username,
        password=encrypt_password(payload.password),
        key_path=payload.key_path,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return mask_credential(cred)


@api_write.get("/api/credentials")
def list_credentials(db: Session = Depends(_db)):
    """Права admin, не обычный api_read — пароли не отдаются (см.
    mask_credential), но сам факт "у этого узла/группы есть общая учётка X"
    уже чувствительная информация, как у ApiKey."""
    creds = db.query(Credential).order_by(
        Credential.node_id.is_(None), Credential.group_id.is_(None).desc(), Credential.label
    ).all()
    return [mask_credential(c) for c in creds]


@api_write.delete("/api/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: int, db: Session = Depends(_db)):
    cred = db.get(Credential, credential_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="Учётка не найдена")
    db.delete(cred)
    db.commit()


@api_read.get("/api/integrations")
def list_integrations(db: Session = Depends(_db)):
    """Фиксированный список ключей (INTEGRATION_REGISTRY) — не то, что
    реально в БД, чтобы показать "не настроено" даже для интеграций,
    которые ещё никто не заводил, а не молчать про них."""
    existing = {i.key: i for i in db.query(Integration).all()}
    return [
        {
            "key": key,
            "label": spec.label,
            "url_placeholder": spec.url_placeholder,
            "configured": key in existing,
            "url": existing[key].url if key in existing else None,
        }
        for key, spec in INTEGRATION_REGISTRY.items()
    ]


@api_write.put("/api/integrations/{key}", status_code=204)
async def set_integration(key: str, payload: IntegrationIn, db: Session = Depends(_db)):
    spec = INTEGRATION_REGISTRY.get(key)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"неизвестная интеграция: {key}")
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL не может быть пустым")
    if not payload.api_token:
        raise HTTPException(status_code=422, detail="токен не может быть пустым")

    existing = db.query(Integration).filter(Integration.key == key).first()
    if existing is not None:
        db.delete(existing)
        db.flush()
    integration = Integration(key=key, url=url, api_token=encrypt_token(payload.api_token))
    db.add(integration)
    db.commit()

    try:
        await spec.test(url, payload.api_token)
    except IntegrationTestError as exc:
        # Настройки уже сохранены (зашифрованы) — не откатываем запись из-за
        # неудачной проверки, тот же принцип, что и у NetOpsHub: честно
        # сообщаем, что похоже на неверный URL/токен, можно тут же поправить.
        raise HTTPException(status_code=400, detail=f"Настройки сохранены, но проверка не прошла: {exc}")


@api_write.delete("/api/integrations/{key}", status_code=204)
def delete_integration(key: str, db: Session = Depends(_db)):
    integration = db.query(Integration).filter(Integration.key == key).first()
    if integration is not None:
        db.delete(integration)
        db.commit()


@api_read.get("/api/ldap-connections")
def list_ldap_connections(db: Session = Depends(_db)):
    return [mask_connection(c) for c in db.query(LdapConnection).order_by(LdapConnection.label).all()]


@api_write.post("/api/ldap-connections", status_code=201)
def create_ldap_connection(payload: LdapConnectionIn, db: Session = Depends(_db)):
    try:
        test_bind(
            dc_host=payload.dc_host,
            port=payload.port,
            domain=payload.domain,
            username=payload.username,
            password=payload.password,
            use_ssl=payload.use_ssl,
        )
    except LdapTestError as exc:
        raise HTTPException(status_code=400, detail=f"Не удалось подключиться: {exc}")
    conn = LdapConnection(
        label=payload.label,
        dc_host=payload.dc_host,
        port=payload.port,
        domain=payload.domain,
        base_dn=payload.base_dn,
        username=payload.username,
        password=encrypt_ldap_password(payload.password),
        use_ssl=payload.use_ssl,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return mask_connection(conn)


@api_write.delete("/api/ldap-connections/{connection_id}", status_code=204)
def delete_ldap_connection(connection_id: int, db: Session = Depends(_db)):
    conn = db.get(LdapConnection, connection_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="Подключение не найдено")
    db.delete(conn)
    db.commit()


@api_write.post("/api/nodes", status_code=201)
def create_node(payload: NodeIn, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    if payload.group_id is not None and db.get(Group, payload.group_id) is None:
        raise HTTPException(status_code=404, detail="Group не найдена")
    if not key_sees_group(key, payload.group_id):
        # Иначе admin, ограниченный своей группой, создавал бы узлы в чужой
        # (или вне групп) и тем самым выходил бы за свою область.
        raise HTTPException(status_code=403, detail="Ключ ограничен другой группой")
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
def list_nodes(
    group_id: int | None = None,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    query = scope_nodes(db.query(Node), key)
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


@api_write.patch("/api/nodes/{node_id}")
def update_node(
    node_id: int,
    payload: NodeUpdateIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    node = require_node_access(db, key, node_id)
    fields = payload.model_dump(exclude_unset=True)
    if "group_id" in fields:
        if fields["group_id"] is not None and db.get(Group, fields["group_id"]) is None:
            raise HTTPException(status_code=404, detail="Group не найдена")
        # Перенос узла в группу, которой ключ не видит, увёл бы узел из-под
        # собственного доступа — и вернуть его назад было бы уже нечем.
        if not key_sees_group(key, fields["group_id"]):
            raise HTTPException(status_code=403, detail="Ключ ограничен другой группой")
    for field, value in fields.items():
        setattr(node, field, value)
    db.commit()
    return {"id": node.id}


@api_write.delete("/api/nodes/{node_id}")
def delete_node_endpoint(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Возвращает, что именно удалено: узел тянет за собой проверки,
    измерения, инциденты и бэкапы — делать это молча неправильно."""
    node = require_node_access(db, key, node_id)
    return delete_node(db, node)


@api_write.delete("/api/probes/{probe_id}", status_code=204)
def delete_probe_endpoint(probe_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    probe = require_probe_access(db, key, probe_id)
    delete_probe(db, probe)


@api_write.delete("/api/watches/{watch_id}", status_code=204)
def delete_watch_endpoint(watch_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    watch = db.get(Watch, watch_id)
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch не найден")
    require_probe_access(db, key, watch.probe_id)
    delete_watch(db, watch)


@api_write.post("/api/probes", status_code=201)
def create_probe(payload: ProbeIn, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    require_node_access(db, key, payload.node_id)
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
def list_node_probes(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Для веб-интерфейса (static/app.js) — Probe каждого Node вместе с
    последней Sample, чтобы не делать по отдельному запросу на probe."""
    require_node_access(db, key, node_id)
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
                    {"ok": latest.ok, "value": latest.value, "detail": latest.detail, "taken_at": iso(latest.taken_at)}
                    if latest
                    else None
                ),
            }
        )
    return result


@api_read.get("/api/probes/{probe_id}/samples")
def probe_samples(
    probe_id: int,
    limit: int = 50,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    require_probe_access(db, key, probe_id)
    rows = (
        db.query(Sample)
        .filter(Sample.probe_id == probe_id)
        .order_by(desc(Sample.taken_at))
        .limit(limit)
        .all()
    )
    return [
        {"taken_at": iso(s.taken_at), "ok": s.ok, "value": s.value, "detail": s.detail}
        for s in rows
    ]


@api_write.post("/api/watches", status_code=201)
def create_watch(payload: WatchIn, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    require_probe_access(db, key, payload.probe_id)
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
def list_probe_watches(probe_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Для инвентаря на сайте (static/inventory.js) — список условий под
    каждой проверкой, с количеством уже настроенных действий (Action), не
    только сам факт существования Watch."""
    require_probe_access(db, key, probe_id)
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


@api_read.get("/api/dashboard")
def dashboard(db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Всё для главной страницы одним запросом — она обновляется каждые
    5 секунд, и десяток отдельных вызовов на виджет тут заметен."""
    return build_dashboard(db, key)


@api_read.get("/api/incidents")
def list_incidents(
    include_resolved: bool = False,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    query = db.query(Incident)
    if not include_resolved:
        query = query.filter(Incident.resolved_at.is_(None))
    if key.group_id is not None:
        # Incident → Watch → Probe → Node: инциденты чужих групп не должны
        # быть видны даже в виде «что-то где-то упало».
        query = query.join(Incident.watch).join(Watch.probe).join(Probe.node).filter(
            Node.group_id == key.group_id
        )
    rows = query.order_by(desc(Incident.opened_at)).all()
    result = []
    for i in rows:
        result.append(
            {
                "id": i.id,
                "watch_id": i.watch_id,
                # Без имени узла список инцидентов отвечал на вопрос «что
                # сломалось», но не «где» — а на дашборде нужно именно это.
                "node_id": i.watch.probe.node_id,
                "node_name": i.watch.probe.node.name,
                "node_address": i.watch.probe.node.address,
                "severity": i.watch.severity.value,
                "label": i.watch.label,
                "detail": i.detail,
                "opened_at": iso(i.opened_at),
                "last_seen_at": iso(i.last_seen_at),
                "resolved_at": iso(i.resolved_at) if i.resolved_at else None,
            }
        )
    return result


@api_write.post("/api/channels", status_code=201)
def create_channel(payload: ChannelIn, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    if payload.node_id is not None:
        require_node_access(db, key, payload.node_id)
    if payload.watch_id is not None:
        watch = db.get(Watch, payload.watch_id)
        if watch is None:
            raise HTTPException(status_code=404, detail="Watch не найден")
        require_probe_access(db, key, watch.probe_id)
    channel = Channel(
        kind=payload.kind,
        config=encrypt_channel_config(payload.config),
        min_severity=payload.min_severity,
        node_id=payload.node_id,
        watch_id=payload.watch_id,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return {"id": channel.id}


@api_read.get("/api/channels")
def list_channels(db: Session = Depends(_db)):
    return [
        {
            "id": c.id,
            "kind": c.kind.value,
            "config": mask_channel_config(c.config),
            "enabled": c.enabled,
            "min_severity": c.min_severity.value,
            "node_id": c.node_id,
            "watch_id": c.watch_id,
        }
        for c in db.query(Channel).all()
    ]


@api_write.delete("/api/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: int, db: Session = Depends(_db)):
    channel = db.get(Channel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Channel не найден")
    db.delete(channel)
    db.commit()


@api_write.post("/api/escalation-steps", status_code=201)
def create_escalation_step(payload: EscalationStepIn, db: Session = Depends(_db)):
    if payload.delay_minutes <= 0:
        raise HTTPException(status_code=422, detail="delay_minutes должен быть положительным")
    if db.get(Channel, payload.channel_id) is None:
        raise HTTPException(status_code=404, detail="Channel не найден")
    step = EscalationStep(delay_minutes=payload.delay_minutes, channel_id=payload.channel_id)
    db.add(step)
    db.commit()
    db.refresh(step)
    return {"id": step.id}


@api_read.get("/api/escalation-steps")
def list_escalation_steps(db: Session = Depends(_db)):
    return [
        {"id": s.id, "delay_minutes": s.delay_minutes, "channel_id": s.channel_id, "enabled": s.enabled}
        for s in db.query(EscalationStep).order_by(EscalationStep.delay_minutes).all()
    ]


@api_write.delete("/api/escalation-steps/{step_id}", status_code=204)
def delete_escalation_step(step_id: int, db: Session = Depends(_db)):
    step = db.get(EscalationStep, step_id)
    if step is None:
        raise HTTPException(status_code=404, detail="Шаг эскалации не найден")
    db.delete(step)
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
        {"id": r.id, "action_id": r.action_id, "started_at": iso(r.started_at), "ok": r.ok, "output": r.output}
        for r in rows
    ]


@api_operate.post("/api/nodes/{node_id}/backup", status_code=201)
async def trigger_backup(
    node_id: int,
    payload: BackupTriggerIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    node = require_node_access(db, key, node_id)
    username, password, key_path = _resolve_node_credential(db, node, payload)
    backup = await run_backup(
        db, node,
        username=username, command=payload.command,
        key_path=key_path, password=password, port=payload.port,
    )
    return {"id": backup.id, "changed": backup.changed, "error": backup.error}


@api_read.get("/api/nodes/{node_id}/backups")
def list_backups(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    require_node_access(db, key, node_id)
    rows = (
        db.query(Backup)
        .filter(Backup.node_id == node_id)
        .order_by(desc(Backup.taken_at))
        .all()
    )
    return [
        {"id": b.id, "taken_at": iso(b.taken_at), "changed": b.changed, "error": b.error, "size": len(b.content)}
        for b in rows
    ]


@api_read.get("/api/backups/{backup_id}")
def get_backup(backup_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    backup = require_backup_access(db, key, backup_id)
    return {"id": backup.id, "node_id": backup.node_id, "taken_at": iso(backup.taken_at), "content": backup.content, "changed": backup.changed, "error": backup.error}


@api_read.get("/api/backups/{backup_id}/diff")
def get_backup_diff(backup_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Diff против предыдущего УСПЕШНОГО снимка того же узла (см.
    backups_engine.run_backup — та же логика поиска "previous")."""
    backup = require_backup_access(db, key, backup_id)
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


@api_operate.post("/api/nodes/{node_id}/audit")
def trigger_audit(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    node = require_node_access(db, key, node_id)
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
def get_audit_findings(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    require_node_access(db, key, node_id)
    findings = db.query(AuditFinding).filter(AuditFinding.node_id == node_id).order_by(AuditFinding.checked_at.desc()).all()
    rules_by_id = {r.id: r for r in db.query(AuditRule).all()}
    result = []
    for f in findings:
        rule = rules_by_id.get(f.rule_id) if f.rule_id else None
        result.append(
            {
                "id": f.id, "rule_name": rule.name if rule else "нет бэкапа",
                "severity": rule.severity.value if rule else "critical",
                "ok": f.ok, "detail": f.detail, "checked_at": iso(f.checked_at),
            }
        )
    return result


@api_operate.post("/api/scans", status_code=201)
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
            "started_at": iso(s.started_at),
            "finished_at": iso(s.finished_at) if s.finished_at else None,
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


@api_operate.post("/api/ad-audit", status_code=201)
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
            "started_at": iso(r.started_at), "ok": r.ok, "error": r.error,
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


@api_read.get("/api/ad-audit/report")
async def get_ad_audit_report(db: Session = Depends(_db)):
    """Безстейтовый флот-отчёт по всем LdapConnection — 25 правил, риск-скор
    по категориям (см. ad_audit_engine.run_ad_audit_fleet_report). Считается
    заново на каждый запрос, ничего не пишет в БД."""
    return await run_ad_audit_fleet_report(db)


@api_read.get("/api/network-audit/report")
def get_network_audit_report(db: Session = Depends(_db)):
    """Безстейтовый флот-отчёт по узлам Cisco/Junos с бэкапом — 26 правил,
    риск-скор по категориям (см. network_audit_engine). Синхронный (нет
    сетевого I/O — работает по уже снятым Backup.content), в отличие от
    AD-аудита не нужен await."""
    return build_network_audit_fleet_report(db)


@api_write.post("/api/retention/run")
def trigger_retention(db: Session = Depends(_db)):
    """Ручной запуск очистки. Планировщик и так делает её раз в сутки, но
    ждать сутки, когда место на диске кончается сейчас, неудобно."""
    return run_retention(db)


@app.post("/api/login")
def login(payload: LoginIn, response: Response, db: Session = Depends(_db)):
    """Вход по логину и паролю. Намеренно НЕ на api_read: чтобы войти,
    ещё нечем авторизоваться."""
    user = db.query(User).filter(User.username == payload.username).first()
    # Проверяем пароль даже для несуществующего пользователя — иначе по
    # времени ответа можно было бы перебором выяснить, какие логины
    # заведены, не зная ни одного пароля.
    stored_hash = user.password_hash if user and user.password_hash else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(payload.password, stored_hash)

    if user is not None and user.password_hash and password_ok and user.active:
        pass  # локальный пароль подошёл
    elif ad_enabled() and (user is None or user.source == "ad") and check_ad_credentials(
        payload.username, payload.password
    ):
        # Домен подтвердил пароль. Локальная запись нужна, чтобы хранить
        # роль и область по группе — в AD их взять неоткуда.
        user = sync_ad_user(db, payload.username)
        if not user.active:
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    else:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    raw_token = create_session(db, user)
    response.set_cookie(
        COOKIE_NAME,
        raw_token,
        httponly=True,   # недоступна JavaScript: XSS не сможет украсть сессию
        samesite="lax",  # не уходит на сторонние сайты — защита от CSRF
        max_age=int(SESSION_TTL.total_seconds()),
        path="/",
    )
    return {"username": user.username, "role": user.role.value, "group_id": user.group_id}


@app.post("/api/logout")
def logout(response: Response, gridforge_session: str | None = Cookie(default=None), db: Session = Depends(_db)):
    revoke_session(db, gridforge_session)
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "logged_out"}


@api_write.post("/api/users", status_code=201)
def create_user(payload: UserIn, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    if db.query(User).filter(User.username == payload.username).first() is not None:
        raise HTTPException(status_code=409, detail="Пользователь с таким логином уже есть")
    problem = password_problem(payload.password)
    if problem:
        raise HTTPException(status_code=422, detail=f"Пароль не принят: {problem}")
    if payload.group_id is not None and db.get(Group, payload.group_id) is None:
        raise HTTPException(status_code=404, detail="Group не найдена")
    if not key_sees_group(key, payload.group_id):
        # Иначе admin, ограниченный группой, завёл бы пользователя с
        # доступом шире собственного.
        raise HTTPException(status_code=403, detail="Ключ ограничен другой группой")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        group_id=payload.group_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role.value}


@api_read.get("/api/users")
def list_users(db: Session = Depends(_db), admin: Principal = Depends(require_admin_key)):
    """Без хешей паролей — наружу они не нужны никогда."""
    return [
        {
            "id": u.id,
            "username": u.username,
            "source": u.source,
            "role": u.role.value,
            "group_id": u.group_id,
            "active": u.active,
            "last_login_at": iso(u.last_login_at) if u.last_login_at else None,
        }
        for u in db.query(User).order_by(User.username).all()
    ]


@api_write.post("/api/users/{user_id}/password")
def change_user_password(user_id: int, payload: PasswordChangeIn, db: Session = Depends(_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.source == "ad":
        # Иначе мы завели бы локальный пароль в обход домена: у учётки
        # появилось бы два разных пароля, и отзыв доступа в AD перестал
        # бы закрывать вход в GridForge.
        raise HTTPException(status_code=409, detail="Пароль доменной учётки меняется в Active Directory")
    problem = password_problem(payload.password)
    if problem:
        raise HTTPException(status_code=422, detail=f"Пароль не принят: {problem}")
    user.password_hash = hash_password(payload.password)
    db.commit()
    # Смена пароля обязана выгнать уже открытые сессии — иначе тот, из-за
    # кого пароль меняют, остался бы внутри.
    closed = revoke_all_for_user(db, user.id)
    return {"status": "updated", "sessions_closed": closed}


@api_write.delete("/api/users/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    revoke_all_for_user(db, user.id)
    db.delete(user)
    db.commit()


@api_operate.post("/api/nodes/{node_id}/ports/refresh", status_code=201)
async def refresh_ports(
    node_id: int,
    payload: PortRefreshIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    """Снять состояние портов узла. Читающая команда, права operator —
    как у бэкапа: лезет на оборудование, ничего не меняет.

    Команда сюда не передаётся — её выбирает сервер по вендору узла,
    иначе через это поле можно было бы выполнить произвольную."""
    node = require_node_access(db, key, node_id)
    username, password, key_path = _resolve_node_credential(db, node, payload)
    snapshot = await collect_ports(
        db,
        node,
        username=username,
        password=password,
        key_path=key_path,
        port=payload.port,
        timeout_seconds=payload.timeout_seconds,
    )
    return {"id": snapshot.id, "ok": snapshot.ok, "ports": len(snapshot.ports), "error": snapshot.error}


@api_read.get("/api/nodes/{node_id}/ports")
def get_ports(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Последний снимок портов узла, сгруппированный по модулям."""
    require_node_access(db, key, node_id)
    snapshot = latest_snapshot(db, node_id)
    if snapshot is None:
        return {"taken_at": None, "ok": None, "groups": [], "error": None, "summary": {}}

    ports = [
        Port(
            name=p.get("name", ""),
            state=p.get("state", "unknown"),
            description=p.get("description", ""),
            vlan=p.get("vlan", ""),
            speed=p.get("speed", ""),
            is_trunk=bool(p.get("is_trunk")),
        )
        for p in (snapshot.ports or [])
    ]
    summary: dict[str, int] = {}
    for port in ports:
        summary[port.state] = summary.get(port.state, 0) + 1

    return {
        "taken_at": iso(snapshot.taken_at),
        "ok": snapshot.ok,
        "error": snapshot.error,
        "command": snapshot.command,
        "summary": summary,
        "groups": [
            {
                "prefix": group["prefix"],
                "ports": [
                    {
                        "name": p.name,
                        "state": p.state,
                        "description": p.description,
                        "vlan": p.vlan,
                        "speed": p.speed,
                        "is_trunk": p.is_trunk,
                    }
                    for p in group["ports"]
                ],
            }
            for group in group_ports(ports)
        ],
    }


@api_operate.post("/api/nodes/{node_id}/ports/{port_name:path}/apply")
async def apply_port_endpoint(
    node_id: int,
    port_name: str,
    payload: PortApplyIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    """Изменить описание/VLAN/состояние (up-down)/Port Security одного
    порта — перенесено из карточки устройства NetOpsHub, та же логика
    построения команд (см. port_commands.py), но напрямую по SSH/Telnet,
    без Ansible. Права operator — реально меняет конфигурацию боевого
    оборудования, как и Scenario.

    port_name — через путь, а не query/body: содержит "/" (Gi1/0/5),
    отсюда {port_name:path} в маршруте."""
    node = require_node_access(db, key, node_id)
    username, password, key_path = _resolve_node_credential(db, node, payload)
    try:
        result = await apply_port(
            node,
            port_name,
            description=payload.description,
            vlan=payload.vlan,
            state=payload.state,
            port_security=payload.port_security,
            port_security_maximum=payload.port_security_maximum,
            username=username,
            password=password,
            key_path=key_path,
            conn_port=payload.port,
            timeout_seconds=payload.timeout_seconds,
        )
    except PortCommandError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result


@api_operate.post("/api/nodes/{node_id}/ports/{port_name:path}/bounce")
async def bounce_port_endpoint(
    node_id: int,
    port_name: str,
    payload: PortBounceIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    """Отбить порт: shutdown -> пауза -> no shutdown — перенесено из
    bounce_port_cisco.yml/bounce_port_juniper.yml NetOpsHub."""
    node = require_node_access(db, key, node_id)
    username, password, key_path = _resolve_node_credential(db, node, payload)
    return await bounce_port(
        node,
        port_name,
        username=username,
        password=password,
        key_path=key_path,
        conn_port=payload.port,
        timeout_seconds=payload.timeout_seconds,
        delay_seconds=payload.delay_seconds,
    )


@api_operate.post("/api/nodes/{node_id}/stp-protection/apply")
async def apply_stp_protection_endpoint(
    node_id: int,
    payload: StpProtectionApplyIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    """Root bridge + BPDU Guard (access) + Loop Guard (trunk) сразу на
    группе портов — перенесено из stp_protection_cisco.yml/
    stp_protection_juniper.yml NetOpsHub. access_ports/trunk_ports обычно
    берутся из последнего снимка портов (GET /api/nodes/{id}/ports,
    is_trunk на каждом порту), клиент может их поправить перед отправкой."""
    node = require_node_access(db, key, node_id)
    username, password, key_path = _resolve_node_credential(db, node, payload)
    try:
        return await apply_stp_protection(
            node,
            access_ports=payload.access_ports,
            trunk_ports=payload.trunk_ports,
            set_root_bridge=payload.set_root_bridge,
            root_bridge_vlans=payload.root_bridge_vlans,
            bpdu_guard=payload.bpdu_guard,
            loop_guard=payload.loop_guard,
            username=username,
            password=password,
            key_path=key_path,
            conn_port=payload.port,
            timeout_seconds=payload.timeout_seconds,
        )
    except StpProtectionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@api_read.get("/api/nodes/{node_id}/protection")
def get_protection(node_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    """Port Security и защита STP по последнему снимку конфигурации.

    Читается сохранённый бэкап, а не живое устройство: конфигурации и так
    снимаются регулярно, а лишний поход на старый коммутатор ради того же
    текста — лишняя нагрузка."""
    require_node_access(db, key, node_id)
    backup = (
        db.query(Backup)
        .filter(Backup.node_id == node_id, Backup.error.is_(None))
        .order_by(desc(Backup.taken_at))
        .first()
    )
    if backup is None:
        return {"taken_at": None, "ports": {}, "summary": None,
                "detail": "нет снимка конфигурации — сначала сними бэкап"}

    ports = parse_port_protection(backup.content)
    stp = parse_stp_global(backup.content)
    return {
        "taken_at": iso(backup.taken_at),
        "summary": protection_summary(ports, stp),
        "ports": {
            name: {
                "port_security": p.port_security,
                "max_mac": p.max_mac,
                "violation": p.violation,
                "sticky": p.sticky,
                "bpdu_guard": p.bpdu_guard,
                "bpdu_filter": p.bpdu_filter,
                "portfast": p.portfast,
                "guard_root": p.guard_root,
                "guard_loop": p.guard_loop,
                "is_trunk": p.is_trunk,
                # Защита выключена, но настройки остались в конфигурации.
                # Показываем явно: это не «защищён», но и не «чисто».
                "leftover_settings": (not p.port_security)
                and (p.max_mac is not None or p.sticky or bool(p.violation)),
            }
            for name, p in ports.items()
        },
    }


@api_read.get("/api/sweep-presets")
def list_sweep_presets():
    """Кнопки готовых команд. Сами строки команд наружу не отдаются —
    какая уйдёт на устройство, решается по вендору узла в момент запуска,
    иначе клиент мог бы подменить её на произвольную."""
    return preset_catalog()


@api_operate.post("/api/sweeps", status_code=201)
async def create_sweep(
    payload: SweepIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    """Запускает читающую команду сразу на наборе узлов.

    Права operator, как у бэкапа и аудита: команда лезет на боевое
    оборудование, но ничего в нём не меняет (см. белый список в
    sweep_commands — туда не попадает ничего изменяющего)."""
    if bool(payload.preset_key) == bool(payload.command):
        raise HTTPException(status_code=422, detail="Нужно указать либо готовую команду, либо свой запрос")
    if not payload.node_ids:
        raise HTTPException(status_code=422, detail="Не выбрано ни одного узла")

    # Каждый узел проверяется на доступность этому ключу отдельно: иначе
    # массовый запуск стал бы дырой в ограничении по группам.
    nodes = [require_node_access(db, key, node_id) for node_id in payload.node_ids]

    custom_command = None
    if payload.command:
        try:
            custom_command = validate_custom_command(payload.command)
        except CommandRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        label = custom_command
    else:
        try:
            command_for_node(payload.preset_key, None)  # проверяем, что такая кнопка существует
        except CommandRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        label = next(p["label"] for p in preset_catalog() if p["key"] == payload.preset_key)

    sweep = Sweep(preset_key=payload.preset_key, label=label, started_by=key.label)
    db.add(sweep)
    db.commit()
    db.refresh(sweep)

    # Учётка — явная на все узлы разом (как раньше), либо у каждого узла
    # своя центральная (разные группы могут иметь разные учётки) —
    # разрешаем по узлу, не одну на весь прогон.
    tasks = []
    skipped = []
    for node in nodes:
        if payload.username:
            username, password, node_key_path = payload.username, payload.password, payload.key_path
        else:
            cred = resolve_credential(db, node)
            if cred is None:
                skipped.append(node.name)
                continue
            username, password, node_key_path = cred["username"], cred["password"], cred["key_path"]
        command = custom_command or command_for_node(payload.preset_key, node.vendor)
        result = SweepResult(sweep_id=sweep.id, node_id=node.id, command=command)
        db.add(result)
        db.commit()
        db.refresh(result)
        tasks.append(
            {
                "result_id": result.id,
                "address": node.address,
                "command": command,
                "vendor": node.vendor,
                "username": username,
                "password": password,
                "key_path": node_key_path,
            }
        )

    if not tasks:
        db.delete(sweep)
        db.commit()
        raise HTTPException(
            status_code=422,
            detail=f"Ни для одного узла нет учётки (явной или центральной): {', '.join(skipped)}",
        )

    # Прогон уходит в фон: десятки SSH-сессий не должны держать HTTP-запрос
    # открытым, интерфейс опрашивает прогресс отдельно.
    asyncio.create_task(run_sweep(sweep.id, tasks, port=payload.port, timeout_seconds=payload.timeout_seconds))
    return {"id": sweep.id, "label": sweep.label, "nodes": len(tasks), "skipped": skipped}


@api_read.get("/api/sweeps")
def list_sweeps(limit: int = 20, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    sweeps = db.query(Sweep).order_by(desc(Sweep.started_at)).limit(min(limit, 100)).all()
    visible = []
    for sweep in sweeps:
        # Прогон показываем, только если ключу доступен хоть один его узел —
        # иначе journal выдавал бы имена чужих узлов.
        if key.group_id is not None and not any(
            key_sees_group(key, r.node.group_id) for r in sweep.results
        ):
            continue
        progress = sweep_progress(db, sweep)
        visible.append(
            {
                "id": sweep.id,
                "label": sweep.label,
                "status": sweep.status.value,
                "started_at": iso(sweep.started_at),
                "started_by": sweep.started_by,
                **progress,
            }
        )
    return visible


@api_read.get("/api/sweeps/{sweep_id}")
def get_sweep(sweep_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    sweep = db.get(Sweep, sweep_id)
    if sweep is None:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    results = [r for r in sweep.results if key_sees_group(key, r.node.group_id)]
    if not results and sweep.results:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    return {
        "id": sweep.id,
        "label": sweep.label,
        "status": sweep.status.value,
        "started_at": iso(sweep.started_at),
        "started_by": sweep.started_by,
        **sweep_progress(db, sweep),
        "results": [
            {
                "node_id": r.node_id,
                "node_name": r.node.name,
                "node_address": r.node.address,
                "command": r.command,
                "ok": r.ok,
                "output": r.output,
                "error": r.error,
                "finished_at": iso(r.finished_at) if r.finished_at else None,
            }
            for r in sorted(results, key=lambda r: r.node.name)
        ],
    }


@api_read.get("/api/scenarios")
def list_scenarios(db: Session = Depends(_db)):
    scenarios = db.query(Scenario).order_by(Scenario.category, Scenario.label).all()
    return [
        {
            "id": s.id,
            "key": s.key,
            "label": s.label,
            "category": s.category,
            "vendors": list(s.commands_by_vendor.keys()),
            "params": s.params,
        }
        for s in scenarios
    ]


@api_write.post("/api/scenarios", status_code=201)
def create_scenario(payload: ScenarioIn, db: Session = Depends(_db)):
    if db.query(Scenario).filter(Scenario.key == payload.key).first() is not None:
        raise HTTPException(status_code=409, detail="Сценарий с таким key уже существует")
    scenario = Scenario(
        key=payload.key,
        label=payload.label,
        category=payload.category,
        commands_by_vendor=payload.commands_by_vendor,
        params=payload.params,
    )
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return {"id": scenario.id, "key": scenario.key}


@api_write.delete("/api/scenarios/{scenario_id}", status_code=204)
def delete_scenario(scenario_id: int, db: Session = Depends(_db)):
    scenario = db.get(Scenario, scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Сценарий не найден")
    db.delete(scenario)
    db.commit()


@api_operate.post("/api/scenarios/{scenario_id}/run", status_code=201)
async def run_scenario_endpoint(
    scenario_id: int,
    payload: ScenarioRunIn,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    """Запускает меняющий конфигурацию сценарий сразу на наборе узлов —
    аналог "рубки" NetOpsHub (выбор устройств + плейбук + запуск на всех),
    но команды свои и без Ansible (см. Scenario в models.py). Права
    operator, как у Sweep/Backup: команда реально меняет конфигурацию
    боевого оборудования."""
    scenario = db.get(Scenario, scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Сценарий не найден")
    if not payload.node_ids:
        raise HTTPException(status_code=422, detail="Не выбрано ни одного узла")

    nodes = [require_node_access(db, key, node_id) for node_id in payload.node_ids]

    run = ScenarioRun(scenario_id=scenario.id, label=scenario.label, started_by=key.label)
    db.add(run)
    db.commit()
    db.refresh(run)

    tasks = []
    skipped = []
    for node in nodes:
        vendor_key = node.vendor.value if node.vendor else None
        template = scenario.commands_by_vendor.get(vendor_key)
        if template is None:
            skipped.append(f"{node.name} (нет команды под вендор)")
            continue
        if payload.username:
            username, password, node_key_path = payload.username, payload.password, payload.key_path
        else:
            cred = resolve_credential(db, node)
            if cred is None:
                skipped.append(f"{node.name} (нет учётки)")
                continue
            username, password, node_key_path = cred["username"], cred["password"], cred["key_path"]
        try:
            command = render_command(template, payload.params)
        except ScenarioParamError as exc:
            db.delete(run)
            db.commit()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        result = ScenarioResult(run_id=run.id, node_id=node.id, command=command)
        db.add(result)
        db.commit()
        db.refresh(result)
        tasks.append(
            {
                "result_id": result.id,
                "address": node.address,
                "command": command,
                "vendor": node.vendor,
                "username": username,
                "password": password,
                "key_path": node_key_path,
            }
        )

    if not tasks:
        db.delete(run)
        db.commit()
        raise HTTPException(
            status_code=422,
            detail=f"Ни один из выбранных узлов не подходит: {', '.join(skipped)}",
        )

    asyncio.create_task(run_scenario(run.id, tasks, port=payload.port, timeout_seconds=payload.timeout_seconds))
    return {"id": run.id, "label": run.label, "nodes": len(tasks), "skipped": skipped}


@api_read.get("/api/scenario-runs")
def list_scenario_runs(limit: int = 20, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    runs = db.query(ScenarioRun).order_by(desc(ScenarioRun.started_at)).limit(min(limit, 100)).all()
    visible = []
    for run in runs:
        if key.group_id is not None and not any(
            key_sees_group(key, r.node.group_id) for r in run.results
        ):
            continue
        visible.append(
            {
                "id": run.id,
                "label": run.label,
                "status": run.status.value,
                "started_at": iso(run.started_at),
                "started_by": run.started_by,
                **scenario_run_progress(run),
            }
        )
    return visible


@api_read.get("/api/scenario-runs/{run_id}")
def get_scenario_run(run_id: int, db: Session = Depends(_db), key: Principal = Depends(require_api_key)):
    run = db.get(ScenarioRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    results = [r for r in run.results if key_sees_group(key, r.node.group_id)]
    if not results and run.results:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    return {
        "id": run.id,
        "label": run.label,
        "status": run.status.value,
        "started_at": iso(run.started_at),
        "started_by": run.started_by,
        **scenario_run_progress(run),
        "results": [
            {
                "node_id": r.node_id,
                "node_name": r.node.name,
                "node_address": r.node.address,
                "command": r.command,
                "ok": r.ok,
                "output": r.output,
                "error": r.error,
                "finished_at": iso(r.finished_at) if r.finished_at else None,
            }
            for r in sorted(results, key=lambda r: r.node.name)
        ],
    }


@api_read.get("/api/whoami")
def whoami(key: Principal = Depends(require_api_key), db: Session = Depends(_db)):
    """Роль текущего ключа. Нужен интерфейсу: раньше роль угадывалась по
    тому, прошёл ли GET /api/api-keys (получилось → admin, иначе viewer)
    — с появлением operator такое угадывание врало бы, показывая
    operator как viewer."""
    # Интерфейс показывает предупреждение, пока встроенный пароль не
    # сменён: видеть его должен любой вошедший, а не только тот, кто
    # читал логи при установке.
    default_password = False
    if key.kind == "user":
        user = db.query(User).filter(User.username == key.label).first()
        default_password = bool(user and is_default_password(user.password_hash))
    return {
        "label": key.label,
        "role": key.role.value,
        "group_id": key.group_id,
        "kind": key.kind,
        "default_password": default_password,
    }


@api_write.post("/api/api-keys", status_code=201)
def create_api_key(payload: ApiKeyIn, db: Session = Depends(_db)):
    """Только admin создаёт новые ключи (в т.ч. другие admin-ключи или
    viewer-ключи для read-only интеграций). Сырое значение показывается
    ровно здесь и один раз, дальше — только хеш в БД."""
    if payload.group_id is not None and db.get(Group, payload.group_id) is None:
        raise HTTPException(status_code=404, detail="Group не найдена")
    raw_key = generate_key(db, label=payload.label, role=payload.role, group_id=payload.group_id)
    return {
        "key": raw_key,
        "label": payload.label,
        "role": payload.role.value,
        "group_id": payload.group_id,
    }


@api_read.get("/api/api-keys")
def list_api_keys(admin: Principal = Depends(require_admin_key), db: Session = Depends(_db)):
    """Список без самих ключей (необратимо хешированы) — только метаданные.
    Явный Depends(require_admin_key) поверх api_read: viewer видит другие
    эндпоинты этого роутера, но не список ключей доступа."""
    return [
        {
            "id": k.id,
            "label": k.label,
            "role": k.role.value,
            "group_id": k.group_id,
            "created_at": iso(k.created_at),
            "revoked": k.revoked,
        }
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
def list_syslog(
    node_id: int | None = None,
    source_ip: str | None = None,
    limit: int = 100,
    db: Session = Depends(_db),
    key: Principal = Depends(require_api_key),
):
    query = db.query(SyslogMessage)
    if key.group_id is not None:
        # Сообщения с нераспознанным источником (node_id IS NULL) ключу с
        # группой не показываем: неизвестно, от чьего устройства они, а
        # содержимое syslog бывает чувствительным.
        query = query.join(Node, SyslogMessage.node_id == Node.id).filter(Node.group_id == key.group_id)
    if node_id is not None:
        query = query.filter(SyslogMessage.node_id == node_id)
    if source_ip is not None:
        query = query.filter(SyslogMessage.source_ip == source_ip)
    rows = query.order_by(desc(SyslogMessage.received_at)).limit(min(limit, 500)).all()
    return [
        {
            "id": m.id, "node_id": m.node_id, "source_ip": m.source_ip,
            "received_at": iso(m.received_at), "facility": m.facility,
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
                "received_at": iso(m.received_at), "message": m.message,
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


@api_operate.post("/api/captures", status_code=201)
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
            "started_at": iso(c.started_at), "packet_count": c.packet_count, "error": c.error,
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
app.include_router(api_operate)
app.include_router(api_write)


@app.websocket("/ws/console")
async def ws_console(websocket: WebSocket):
    """Авторизация — внутри handle_console (первое сообщение, не
    HTTP-заголовок — WebSocket из браузера не даёт произвольных заголовков
    без ручного клиента), см. app/console_ws.py."""
    await handle_console(websocket)

class _NoCacheStaticFiles(StaticFiles):
    """Статика отдаётся с запретом кеширования.

    Реальная проблема, а не перестраховка: после обновления GridForge
    браузер на другой машине продолжал показывать СТАРЫЙ интерфейс —
    без новых пунктов меню и без перенаправления на страницу входа, —
    потому что держал прежние .js и .html в кеше. Выглядит это как
    «ничего не изменилось» или как сломанный сайт, а причина невидима.

    Здесь нет сборки с хешами в именах файлов (весь фронтенд — обычные
    .html/.js без шага сборки), поэтому самый честный вариант —
    no-cache: браузер каждый раз переспрашивает, не изменился ли файл.
    Трафик мизерный, а интерфейс всегда соответствует установленной
    версии.
    """

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/", _NoCacheStaticFiles(directory=_STATIC_DIR, html=True), name="static")
