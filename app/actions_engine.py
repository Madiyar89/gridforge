"""Выполнение Action по вновь открытым Incident. Вызывается из
scheduler.py тем же способом, что и signal.dispatch — сразу после
evaluate_probe(), на том же списке newly_opened, без отдельного прохода
по базе."""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.credentials_engine import resolve_credential
from app.models import Action, ActionKind, ActionRun, Credential, Incident, Node, as_aware
from app.secrets_crypto import (
    MIN_REDACTABLE_SECRET_LENGTH,
    collect_known_secrets,
    decrypt_secret,
    redact_known_secrets,
)
from app.ssh_client import run_ssh_command

logger = logging.getLogger("gridforge.actions")

DEFAULT_ACTION_TIMEOUT_SECONDS = 15.0

# Cooldown по умолчанию для Action, если админ не указал своё значение при
# создании (см. Action.cooldown_seconds в models.py) — защита от аудитом
# найденного риска "мигающий Watch может перезапускать сервис по кругу":
# Incident может закрыться и переоткрыться много раз за флаппинг, и без
# cooldown Action срабатывал бы на каждое переоткрытие. 5 минут — типичный
# дефолт для такого рода рейт-лимита (достаточно, чтобы погасить быстрый
# дребезг типа рестартующегося сервиса, не настолько долго, чтобы реальный
# повторный инцидент остался без действия надолго). 0 — явный opt-out,
# действие срабатывает каждый раз (для тех, кому это осознанно нужно).
DEFAULT_ACTION_COOLDOWN_SECONDS = 300

# С переходом scheduler.py на asyncio.create_task() для dispatch() (Action
# больше не сериализуется через единственный цикл опроса) несколько
# Incident могут открыться в одном тике и запустить SSH-команды
# параллельно. Ограничиваем число одновременных SSH-подключений по
# Action — лимит вводим сразу вместе с переходом на конкурентную модель,
# а не оставляем неограниченным. Переопределяется переменной окружения по
# тому же принципу, что и GRIDFORGE_SYNC_INTERVAL_MIN в scheduler.py.
MAX_CONCURRENT_ACTIONS = int(os.environ.get("GRIDFORGE_ACTION_MAX_CONCURRENCY", "8"))
_action_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ACTIONS)


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
    # Node.ssh_key_fingerprint: node уже загружен из этой же db-
    # сессии, поэтому колбэки замыкаются прямо на него, отдельная сессия
    # (как в probes.py/node_fingerprint_callbacks) не нужна.
    known_hosts = cfg.get("known_hosts")

    def _get_fingerprint() -> str | None:
        return node.ssh_key_fingerprint

    def _store_fingerprint(fingerprint: str) -> None:
        node.ssh_key_fingerprint = fingerprint
        db.add(node)
        db.commit()

    # Семафор — см. MAX_CONCURRENT_ACTIONS выше: с конкурентным dispatch()
    # несколько Action могут дойти до этой точки одновременно, семафор не
    # даёт открыть больше MAX_CONCURRENT_ACTIONS SSH-подключений разом.
    async with _action_semaphore:
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
    # Редактируем известные GridForge секреты в выводе ПЕРЕД обрезкой по
    # длине (см. secrets_crypto.redact_known_secrets) — если резать
    # сначала, секрет может оказаться разорван пополам обрезкой и
    # перестать совпасть целиком, оставшись частично видимым. Набор
    # секретов — все, что GridForge знает сам (Credential/Integration/
    # Channel из БД), плюс пароль САМОГО этого SSH-подключения: даже если
    # он передан вручную в config.password (не через центральную
    # Credential), он всё равно секрет, и команда может случайно
    # напечатать его (напр. echo $PASSWORD в verbose-отладке) — редактируем
    # его наравне со всеми остальными, без исключений по происхождению.
    known_secrets = collect_known_secrets(db)
    if password and len(password) >= MIN_REDACTABLE_SECRET_LENGTH:
        known_secrets.add(password)

    if result.ok:
        stdout = redact_known_secrets(result.stdout, known_secrets) or ""
        return True, stdout[:2000]
    output = result.error or "неизвестная ошибка"
    if result.stdout:
        stdout = redact_known_secrets(result.stdout, known_secrets) or ""
        output = f"{output}: {stdout[:1000]}"
    return False, output


def _seconds_since_last_run(db: Session, action_id: int) -> float | None:
    """Секунд с последнего РЕАЛЬНОГО (не skipped) запуска этого Action, или
    None, если такого запуска ещё не было. Пропущенные из-за cooldown
    записи не считаются "последним запуском" — иначе cooldown откладывался
    бы заново на каждой проверке, вместо того чтобы отсчитываться от
    момента, когда Action фактически что-то выполнил."""
    last_run = (
        db.query(ActionRun)
        .filter(ActionRun.action_id == action_id, ActionRun.skipped.is_(False))
        .order_by(ActionRun.started_at.desc())
        .first()
    )
    if last_run is None:
        return None
    return (datetime.now(timezone.utc) - as_aware(last_run.started_at)).total_seconds()


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
            # cooldown_seconds == 0 — явный opt-out (см. DEFAULT_ACTION_
            # COOLDOWN_SECONDS выше), всегда срабатывает без проверки.
            if action.cooldown_seconds:
                elapsed = _seconds_since_last_run(db, action.id)
                if elapsed is not None and elapsed < action.cooldown_seconds:
                    remaining = action.cooldown_seconds - elapsed
                    logger.info(
                        "action_id=%s incident_id=%s: пропуск — cooldown активен "
                        "(последний запуск %.0fс назад, ещё %.0fс из %sс)",
                        action.id,
                        incident.id,
                        elapsed,
                        remaining,
                        action.cooldown_seconds,
                    )
                    db.add(
                        ActionRun(
                            action_id=action.id,
                            incident_id=incident.id,
                            ok=False,
                            output=(
                                f"пропущено: cooldown {action.cooldown_seconds}с, "
                                f"последний запуск {elapsed:.0f}с назад"
                            ),
                            skipped=True,
                        )
                    )
                    continue
            if action.kind == ActionKind.ssh_command:
                ok, output = await _run_ssh_action(db, action, node)
            else:
                ok, output = False, f"неизвестный ActionKind: {action.kind}"
            db.add(ActionRun(action_id=action.id, incident_id=incident.id, ok=ok, output=output))
            if not ok:
                logger.warning("action_id=%s incident_id=%s: %s", action.id, incident.id, output)
    db.commit()
