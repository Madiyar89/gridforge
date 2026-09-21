"""Выполнение Scenario — массовое изменение конфигурации сразу на
наборе узлов. Тот же исполнительный слой, что у Sweep (см.
sweep_engine.py): параллельно, не больше MAX_PARALLEL сессий разом,
результат каждого узла пишется в БД по готовности. Отличие только в
одном месте — команда меняет конфигурацию устройства, поэтому источник
команды не белый список глаголов (sweep_commands.py), а фиксированный
каталог Scenario, который редактирует только администратор."""

from __future__ import annotations

import asyncio
import logging

from app.db import get_session
from app.device_client import run_device_config
from app.models import ScenarioResult, ScenarioRun, SweepStatus, _now

logger = logging.getLogger("gridforge.scenarios")

MAX_PARALLEL = 5
MAX_OUTPUT_CHARS = 20000


class ScenarioParamError(ValueError):
    """Не хватает значения для плейсхолдера команды ({{param}}) — видно
    пользователю до того, как что-то ушло на устройство."""


def render_command(template: str, params: dict) -> str:
    try:
        return template.format(**params)
    except KeyError as exc:
        raise ScenarioParamError(f"не хватает параметра: {exc.args[0]}") from exc


async def _run_one(
    semaphore: asyncio.Semaphore,
    result_id: int,
    address: str,
    command: str,
    vendor,
    *,
    username: str,
    password: str | None,
    key_path: str | None,
    port: int,
    timeout_seconds: float,
) -> None:
    async with semaphore:
        # Сценарии всегда меняют конфигурацию (см. scenario_catalog.py) —
        # многострочный блок нельзя послать одним exec-запросом (реальный
        # баг на боевых Cisco/Junos, см. ssh_client.run_ssh_config_lines),
        # поэтому построчно через интерактивную сессию, не run_device_command.
        outcome = await run_device_config(
            vendor=vendor,
            host=address,
            lines=command.split("\n"),
            username=username,
            password=password,
            key_path=key_path,
            port=port,
            timeout_seconds=timeout_seconds,
        )

    db = get_session()
    try:
        result = db.get(ScenarioResult, result_id)
        if result is None:
            return
        result.ok = outcome.ok
        result.output = (outcome.stdout or "")[:MAX_OUTPUT_CHARS] or None
        result.error = outcome.error if not outcome.ok else None
        result.finished_at = _now()
        db.commit()
    finally:
        db.close()


async def run_scenario(
    run_id: int,
    tasks: list[dict],
    *,
    port: int,
    timeout_seconds: float,
) -> None:
    """Фоновая часть — вызывается через asyncio.create_task так же, как
    run_sweep. tasks: [{result_id, address, command, vendor, username,
    password, key_path}, ...], подготовленные вызывающей стороной (учётка
    уже разрешена на узел — явная или центральная, см. run_scenario_endpoint
    в main.py) в её (уже закрытой к этому моменту) сессии."""
    semaphore = asyncio.Semaphore(MAX_PARALLEL)
    await asyncio.gather(
        *(
            _run_one(
                semaphore,
                task["result_id"],
                task["address"],
                task["command"],
                task.get("vendor"),
                username=task["username"],
                password=task.get("password"),
                key_path=task.get("key_path"),
                port=port,
                timeout_seconds=timeout_seconds,
            )
            for task in tasks
        ),
        return_exceptions=True,
    )

    db = get_session()
    try:
        run = db.get(ScenarioRun, run_id)
        if run is not None:
            run.status = SweepStatus.done
            run.finished_at = _now()
            db.commit()
    finally:
        db.close()


def scenario_run_progress(run: ScenarioRun) -> dict:
    total = len(run.results)
    finished = [r for r in run.results if r.ok is not None]
    failed = [r for r in finished if not r.ok]
    return {
        "total": total,
        "done": len(finished),
        "failed": len(failed),
        "pending": total - len(finished),
    }
