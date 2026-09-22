"""Выполнение Action по вновь открытым Incident. Вызывается из
scheduler.py тем же способом, что и signal.dispatch — сразу после
evaluate_probe(), на том же списке newly_opened, без отдельного прохода
по базе."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.credentials_engine import resolve_credential
from app.models import Action, ActionKind, ActionRun, Incident, Node
from app.secrets_crypto import decrypt_secret
from app.ssh_client import run_ssh_command

logger = logging.getLogger("gridforge.actions")

DEFAULT_ACTION_TIMEOUT_SECONDS = 15.0


async def _run_ssh_action(db: Session, action: Action, node: Node) -> tuple[bool, str]:
    cfg = action.config
    command = cfg.get("command")
    if not command:
        return False, "config.command обязателен"

    # username/key_path/password в форме действия — явный override (как
    # раньше, обязателен). Не указан — падаем на центральную учётку узла
    # (Credential, тот же resolve_credential, что уже использует Рубка/
    # Сценарии/бэкап), по прямому запросу пользователя: раньше Action был
    # единственным местом в GridForge, где учётку всегда приходилось
    # печатать руками, даже если для этого узла уже есть центральная.
    username = cfg.get("username")
    key_path = cfg.get("key_path")
    password = decrypt_secret(cfg["password"]) if cfg.get("password") else None
    if not username:
        cred = resolve_credential(db, node)
        if cred is None:
            return False, "нет ни username в действии, ни центральной учётки для этого узла"
        username, key_path, password = cred["username"], cred["key_path"], cred["password"]

    result = await run_ssh_command(
        host=node.address,
        port=int(cfg.get("port", 22)),
        username=username,
        command=command,
        timeout_seconds=float(cfg.get("timeout_seconds", DEFAULT_ACTION_TIMEOUT_SECONDS)),
        key_path=key_path,
        password=password,
        known_hosts=cfg.get("known_hosts"),
    )
    if result.ok:
        return True, result.stdout[:2000]
    output = result.error or "неизвестная ошибка"
    if result.stdout:
        output = f"{output}: {result.stdout[:1000]}"
    return False, output


async def dispatch(db: Session, incidents: list[Incident]) -> None:
    if not incidents:
        return
    for incident in incidents:
        actions = (
            db.query(Action)
            .filter(Action.watch_id == incident.watch_id, Action.enabled.is_(True))
            .all()
        )
        if not actions:
            continue
        node = incident.watch.probe.node
        for action in actions:
            if action.kind == ActionKind.ssh_command:
                ok, output = await _run_ssh_action(db, action, node)
            else:
                ok, output = False, f"неизвестный ActionKind: {action.kind}"
            db.add(ActionRun(action_id=action.id, incident_id=incident.id, ok=ok, output=output))
            if not ok:
                logger.warning("action_id=%s incident_id=%s: %s", action.id, incident.id, output)
    db.commit()
