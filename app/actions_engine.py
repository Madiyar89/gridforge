"""Выполнение Action по вновь открытым Incident. Вызывается из
scheduler.py тем же способом, что и signal.dispatch — сразу после
evaluate_probe(), на том же списке newly_opened, без отдельного прохода
по базе."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.credentials_engine import resolve_credential
from app.models import Action, ActionKind, ActionRun, Credential, Incident, Node
from app.secrets_crypto import decrypt_secret
from app.ssh_client import run_ssh_command

logger = logging.getLogger("gridforge.actions")

DEFAULT_ACTION_TIMEOUT_SECONDS = 15.0


async def _run_ssh_action(db: Session, action: Action, node: Node) -> tuple[bool, str]:
    cfg = action.config
    command = cfg.get("command")
    if not command:
        return False, "config.command обязателен"

    # Три источника учётки, по приоритету (по прямому запросу
    # пользователя — раньше Action был единственным местом в GridForge,
    # где логин/пароль всегда приходилось печатать руками):
    #   1. username в config — явный ручной override, как было раньше.
    #   2. credential_id в config — КОНКРЕТНАЯ учётка из Настройки →
    #      Учётки, выбранная в форме действия явно (не обязательно та,
    #      что резолвится по узлу — иногда для действия нужен другой
    #      логин, чем для обычного опроса).
    #   3. Ничего не указано — та же учётка, что резолвилась бы для
    #      этого узла везде (resolve_credential: узел -> группа ->
    #      вендор -> дефолт).
    username = cfg.get("username")
    key_path = cfg.get("key_path")
    password = decrypt_secret(cfg["password"]) if cfg.get("password") else None
    if not username:
        cred_id = cfg.get("credential_id")
        if cred_id:
            cred_row = db.get(Credential, int(cred_id))
            if cred_row is None:
                return False, f"учётка id={cred_id} не найдена (удалена?)"
            username = cred_row.username
            key_path = cred_row.key_path
            password = decrypt_secret(cred_row.password) if cred_row.password else None
        else:
            cred = resolve_credential(db, node)
            if cred is None:
                return False, "нет ни username в действии, ни центральной учётки для этого узла"
            username, key_path, password = cred["username"], cred["key_path"], cred["password"]

    # known_hosts, явно заданный в config — обычная проверка asyncssh по
    # этому файлу, TOFU ниже не участвует (см. ssh_client.open_ssh_
    # connection: явный known_hosts всегда в приоритете). Иначе — TOFU по
    # Node.ssh_host_key_fingerprint: node уже загружен из этой же db-
    # сессии, поэтому колбэки замыкаются прямо на него, отдельная сессия
    # (как в probes.py/node_fingerprint_callbacks) не нужна.
    known_hosts = cfg.get("known_hosts")

    def _get_fingerprint() -> str | None:
        return node.ssh_host_key_fingerprint

    def _store_fingerprint(fingerprint: str) -> None:
        node.ssh_host_key_fingerprint = fingerprint
        db.add(node)
        db.commit()

    result = await run_ssh_command(
        host=node.address,
        port=int(cfg.get("port", 22)),
        username=username,
        command=command,
        timeout_seconds=float(cfg.get("timeout_seconds", DEFAULT_ACTION_TIMEOUT_SECONDS)),
        key_path=key_path,
        password=password,
        known_hosts=known_hosts,
        host_key_fingerprint_getter=None if known_hosts is not None else _get_fingerprint,
        host_key_fingerprint_setter=None if known_hosts is not None else _store_fingerprint,
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
