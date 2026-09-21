"""Выполнение массового прогона команды по узлам.

Узлы опрашиваются параллельно, но не все разом: одновременных SSH-сессий
не больше MAX_PARALLEL. Ограничение не из вежливости — при запуске на
несколько десятков коммутаторов разом упирается и файловый дескриптор, и
канал (владелец работает в том числе через USB-модем), а часть устройств
в этом парке — старые 2950/2960, которым тяжело даются параллельные
подключения.

Результат каждого узла пишется в БД сразу по готовности, а не пачкой в
конце: интерфейс показывает прогресс по мере выполнения, и если прогон
прервётся на середине, уже собранное не пропадёт.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Node, Sweep, SweepResult, SweepStatus, _now
from app.device_client import default_port, run_device_command

logger = logging.getLogger("gridforge.sweep")

MAX_PARALLEL = 8
MAX_OUTPUT_CHARS = 20000  # вывод show running-config бывает огромным


async def _run_one(
    semaphore: asyncio.Semaphore,
    sweep_id: int,
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
        # Транспорт выбирается по вендору: часть парка только по Telnet.
        outcome = await run_device_command(
            vendor=vendor,
            host=address,
            command=command,
            username=username,
            password=password,
            key_path=key_path,
            port=port if port not in (0, 22) else default_port(vendor),
            timeout_seconds=timeout_seconds,
        )

    # Своя сессия на запись: задачи идут параллельно, а сессия SQLAlchemy
    # не рассчитана на одновременное использование из нескольких мест.
    db = get_session()
    try:
        result = db.get(SweepResult, result_id)
        if result is None:
            return
        result.ok = outcome.ok
        result.output = (outcome.stdout or "")[:MAX_OUTPUT_CHARS] or None
        result.error = outcome.error if not outcome.ok else None
        result.finished_at = _now()
        db.commit()
    finally:
        db.close()


async def run_sweep(
    sweep_id: int,
    tasks: list[dict],
    *,
    username: str,
    password: str | None,
    key_path: str | None,
    port: int,
    timeout_seconds: float,
) -> None:
    """Фоновая часть: опрашивает узлы и закрывает прогон.

    `tasks` — список словарей {result_id, address, command, vendor}, подготовленных
    вызывающей стороной в её сессии. Сюда не передаются объекты ORM: они
    принадлежат чужой сессии, которая к этому моменту уже закрыта.
    """
    semaphore = asyncio.Semaphore(MAX_PARALLEL)
    await asyncio.gather(
        *(
            _run_one(
                semaphore,
                sweep_id,
                task["result_id"],
                task["address"],
                task["command"],
                task.get("vendor"),
                username=username,
                password=password,
                key_path=key_path,
                port=port,
                timeout_seconds=timeout_seconds,
            )
            for task in tasks
        ),
        return_exceptions=True,  # один недоступный узел не должен ронять весь прогон
    )

    db = get_session()
    try:
        sweep = db.get(Sweep, sweep_id)
        if sweep is not None:
            sweep.status = SweepStatus.done
            sweep.finished_at = _now()
            db.commit()
    finally:
        db.close()


def sweep_progress(db: Session, sweep: Sweep) -> dict:
    """Сводка для интерфейса: сколько готово, сколько с ошибкой."""
    total = len(sweep.results)
    finished = [r for r in sweep.results if r.ok is not None]
    failed = [r for r in finished if not r.ok]
    return {
        "total": total,
        "done": len(finished),
        "failed": len(failed),
        "pending": total - len(finished),
    }
