"""Выполнение Action по вновь открытым Incident. Вызывается из
scheduler.py тем же способом, что и signal.dispatch — сразу после
evaluate_probe(), на том же списке newly_opened, без отдельного прохода
по базе."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models import Action, ActionKind, ActionRun, Incident
from app.secrets_crypto import decrypt_secret
from app.ssh_client import run_ssh_command

logger = logging.getLogger("gridforge.actions")

DEFAULT_ACTION_TIMEOUT_SECONDS = 15.0


async def _run_ssh_action(action: Action, node_address: str) -> tuple[bool, str]:
    cfg = action.config
    username = cfg.get("username")
    command = cfg.get("command")
    if not username or not command:
        return False, "config.username и config.command обязательны"
    result = await run_ssh_command(
        host=node_address,
        port=int(cfg.get("port", 22)),
        username=username,
        command=command,
        timeout_seconds=float(cfg.get("timeout_seconds", DEFAULT_ACTION_TIMEOUT_SECONDS)),
        key_path=cfg.get("key_path"),
        password=decrypt_secret(cfg["password"]) if cfg.get("password") else None,
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
        node_address = incident.watch.probe.node.address
        for action in actions:
            if action.kind == ActionKind.ssh_command:
                ok, output = await _run_ssh_action(action, node_address)
            else:
                ok, output = False, f"неизвестный ActionKind: {action.kind}"
            db.add(ActionRun(action_id=action.id, incident_id=incident.id, ok=ok, output=output))
            if not ok:
                logger.warning("action_id=%s incident_id=%s: %s", action.id, incident.id, output)
    db.commit()
