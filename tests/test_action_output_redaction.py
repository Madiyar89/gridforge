"""Редактирование известных секретов в ActionRun.output — по задаче
аудита: stdout SSH-команды Action сохраняется как есть, а историю
ActionRun может прочитать ЛЮБОЙ действующий API-ключ (api_read, не
только admin — см. GET /api/incidents/{id}/action-runs в main.py).
Проверяем actions_engine._run_ssh_action()/dispatch() напрямую, тем же
стилем фикстур, что test_action_dispatch.py/test_action_cooldown.py.

(a) секрет, случайно попавший в stdout, редактируется в сохранённом
    ActionRun.output;
(b) вывод без совпадений с известными секретами не меняется;
(c) несколько разных известных секретов в одном выводе — редактируются
    все;
(d) короткий (< MIN_REDACTABLE_SECRET_LENGTH) секрет НЕ редактируется —
    осознанное ограничение подхода (слишком высок риск ложных
    срабатываний на коротких строках), задокументировано в
    secrets_crypto.py."""

from __future__ import annotations

import asyncio

from app import actions_engine
from app.models import (
    Action,
    ActionKind,
    ActionRun,
    Credential,
    Incident,
    Node,
    Probe,
    ProbeKind,
    Watch,
    WatchOperator,
    WatchSeverity,
)
from app.secrets_crypto import REDACTED_PLACEHOLDER, encrypt_secret


def _make_watch_with_action(db, *, config: dict) -> tuple[Watch, Action]:
    node = Node(name="node-a", address="10.0.0.1")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping, interval_seconds=60, timeout_seconds=5)
    db.add(probe)
    db.commit()
    watch = Watch(
        probe_id=probe.id,
        operator=WatchOperator.probe_failed,
        streak_required=1,
        severity=WatchSeverity.critical,
        label="down",
    )
    db.add(watch)
    db.commit()
    action = Action(watch_id=watch.id, kind=ActionKind.ssh_command, config=config, cooldown_seconds=0)
    db.add(action)
    db.commit()
    return watch, action


def _open_incident(db, watch: Watch) -> Incident:
    incident = Incident(watch_id=watch.id, detail="узел не отвечает")
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def _stub_run_ssh_command(stdout: str):
    async def _run(**kwargs):
        from app.ssh_client import SshResult

        return SshResult(ok=True, exit_status=0, stdout=stdout, error=None)

    return _run


def test_known_secret_in_output_gets_redacted(db, monkeypatch):
    """(a) Credential.password, случайно напечатанный командой, не
    попадает в ActionRun.output в открытом виде."""
    secret_password = "sup3r-secret-pass"  # 17 символов, выше порога
    cred = Credential(username="admin", password=encrypt_secret(secret_password))
    db.add(cred)
    db.commit()

    monkeypatch.setattr(
        actions_engine,
        "run_ssh_command",
        _stub_run_ssh_command(f"config dump:\npassword={secret_password}\nend"),
    )
    watch, action = _make_watch_with_action(
        db, config={"credential_id": cred.id, "command": "show run"}
    )
    incident = _open_incident(db, watch)

    asyncio.run(actions_engine.dispatch(db, [incident]))

    run = db.query(ActionRun).filter(ActionRun.action_id == action.id).one()
    assert run.ok is True
    assert secret_password not in run.output
    assert REDACTED_PLACEHOLDER in run.output


def test_output_without_secret_matches_is_unchanged(db, monkeypatch):
    """(b) Ничего не совпало с известными секретами — вывод сохраняется
    как есть, без ложных срабатываний."""
    cred = Credential(username="admin", password=encrypt_secret("totally-unrelated-secret"))
    db.add(cred)
    db.commit()

    plain_output = "interface GigabitEthernet0/1 is up, line protocol is up"
    monkeypatch.setattr(actions_engine, "run_ssh_command", _stub_run_ssh_command(plain_output))
    watch, action = _make_watch_with_action(
        db, config={"credential_id": cred.id, "command": "show interface"}
    )
    incident = _open_incident(db, watch)

    asyncio.run(actions_engine.dispatch(db, [incident]))

    run = db.query(ActionRun).filter(ActionRun.action_id == action.id).one()
    assert run.output == plain_output


def test_multiple_known_secrets_all_redacted(db, monkeypatch):
    """(c) Несколько разных известных секретов (Credential.password и
    Integration.api_token) в одном выводе — редактируются оба."""
    from app.models import Integration

    cred_secret = "cred-password-value"
    token_secret = "integration-api-token-xyz"
    cred = Credential(username="admin", password=encrypt_secret(cred_secret))
    integration = Integration(key="graylog", url="https://graylog.local", api_token=encrypt_secret(token_secret))
    db.add_all([cred, integration])
    db.commit()

    stdout = f"debug dump:\ncred={cred_secret}\ntoken={token_secret}\ndone"
    monkeypatch.setattr(actions_engine, "run_ssh_command", _stub_run_ssh_command(stdout))
    watch, action = _make_watch_with_action(
        db, config={"credential_id": cred.id, "command": "debug dump"}
    )
    incident = _open_incident(db, watch)

    asyncio.run(actions_engine.dispatch(db, [incident]))

    run = db.query(ActionRun).filter(ActionRun.action_id == action.id).one()
    assert cred_secret not in run.output
    assert token_secret not in run.output
    assert run.output.count(REDACTED_PLACEHOLDER) == 2


def test_short_secret_below_threshold_is_not_redacted(db, monkeypatch):
    """(d) Секрет короче MIN_REDACTABLE_SECRET_LENGTH (8 символов) не
    редактируется — осознанное ограничение (см. secrets_crypto.py):
    короткие строки слишком часто случайно совпадают с обычным выводом,
    массовая замена дала бы больше вреда (искажённый вывод), чем пользы."""
    short_secret = "abc12"  # 5 символов, ниже порога в 8
    cred = Credential(username="admin", password=encrypt_secret(short_secret))
    db.add(cred)
    db.commit()

    stdout = f"code={short_secret} ok"
    monkeypatch.setattr(actions_engine, "run_ssh_command", _stub_run_ssh_command(stdout))
    watch, action = _make_watch_with_action(
        db, config={"credential_id": cred.id, "command": "show code"}
    )
    incident = _open_incident(db, watch)

    asyncio.run(actions_engine.dispatch(db, [incident]))

    run = db.query(ActionRun).filter(ActionRun.action_id == action.id).one()
    assert run.output == stdout
    assert REDACTED_PLACEHOLDER not in run.output


def test_own_connection_password_in_config_is_redacted(db, monkeypatch):
    """Пароль самого SSH-подключения, заданный вручную в Action.config
    (не через центральную Credential), тоже редактируется в выводе —
    см. решение в actions_engine._run_ssh_action: секрет редактируется
    независимо от происхождения, без исключения для "своего" пароля."""
    ad_hoc_password = "ad-hoc-config-password"
    monkeypatch.setattr(
        actions_engine,
        "run_ssh_command",
        _stub_run_ssh_command(f"connecting with password={ad_hoc_password}"),
    )
    watch, action = _make_watch_with_action(
        db,
        config={"username": "admin", "password": encrypt_secret(ad_hoc_password), "command": "show run"},
    )
    incident = _open_incident(db, watch)

    asyncio.run(actions_engine.dispatch(db, [incident]))

    run = db.query(ActionRun).filter(ActionRun.action_id == action.id).one()
    assert ad_hoc_password not in run.output
    assert REDACTED_PLACEHOLDER in run.output
