"""Плановые фоновые задачи run_forever() (vuln/cable/discovery-schedule,
geoip-refresh, sync-push, flow-alerts, см. Scheduler._track_periodic и
_run_due_*_safe в app/scheduler.py) должны быть отслежены и корректно
остановлены на shutdown — тот же класс проблемы, что был у Action-задач
до фикса в этом же файле (см. tests/test_action_dispatch.py, откуда
взят паттерн через asyncio.Event вместо sleep-based таймингов).

До фикса asyncio.create_task(self._run_due_vuln_schedules_safe()) и
аналоги вызывались без единой ссылки после создания — на остановке
планировщика (run_forever() возвращается) эти задачи никак не
отслеживались и не ожидались/отменялись. Проверяем здесь:

  (a) задача, поставленная через _track_periodic, реально попадает в
      Scheduler._periodic_tasks и вычищается из множества после
      завершения (тот же add_done_callback-паттерн, что у _action_tasks);
  (b) _shutdown_periodic_tasks() ждёт короткое "grace"-окно, затем явно
      cancel()-ит всё ещё не завершившиеся задачи и дожидается отмены —
      после return в Scheduler._periodic_tasks ничего не остаётся;
  (c) cancel() реально долетает до тела задачи (CancelledError не
      проглатывается — в _run_due_*_safe перехватывается только
      `except Exception`, не BaseException).
"""

from __future__ import annotations

import asyncio

import pytest

from app.scheduler import Scheduler


def test_track_periodic_adds_and_autodiscards_task():
    scheduler = Scheduler()

    async def _quick() -> None:
        return None

    async def _run() -> None:
        task = asyncio.create_task(_quick())
        scheduler._track_periodic(task)
        assert task in scheduler._periodic_tasks
        await task
        # add_done_callback(discard) снимает задачу из множества сама —
        # без явного участия run_forever()/shutdown-кода.
        await asyncio.sleep(0)  # даём done-callback'у отработать
        assert task not in scheduler._periodic_tasks

    asyncio.run(_run())


def test_shutdown_periodic_tasks_cancels_hanging_task_after_grace_window():
    scheduler = Scheduler()

    started = asyncio.Event()
    cancelled_seen = False

    async def _hanging_periodic() -> None:
        nonlocal cancelled_seen
        started.set()
        try:
            await asyncio.sleep(3600)  # "зависла" — например сеть недоступна
        except asyncio.CancelledError:
            cancelled_seen = True
            raise  # обязательное поведение — не проглатывать отмену

    async def _run() -> None:
        task = asyncio.create_task(_hanging_periodic())
        scheduler._track_periodic(task)
        await started.wait()

        assert scheduler._periodic_tasks  # задача реально отслеживается

        # grace_seconds=0 — не ждём произвольное время в тесте, сразу
        # переходим к принудительной отмене (то, что происходит после
        # истечения grace-окна в проде).
        await scheduler._shutdown_periodic_tasks(grace_seconds=0)

        assert cancelled_seen, "CancelledError должен долететь до тела задачи"
        assert not scheduler._periodic_tasks, "задача должна быть вычищена после shutdown"

    asyncio.run(_run())


def test_shutdown_periodic_tasks_lets_fast_task_finish_within_grace_window():
    """Задача, успевающая завершиться сама в течение grace-окна, не
    должна быть отменена — cancel() только для того, что реально
    зависло дольше отведённого времени."""
    scheduler = Scheduler()
    completed = False

    async def _fast_periodic() -> None:
        nonlocal completed
        await asyncio.sleep(0.05)
        completed = True

    async def _run() -> None:
        task = asyncio.create_task(_fast_periodic())
        scheduler._track_periodic(task)

        await scheduler._shutdown_periodic_tasks(grace_seconds=2)

        assert completed, "быстрая задача должна была успеть завершиться сама"
        assert not task.cancelled()
        assert not scheduler._periodic_tasks

    asyncio.run(_run())


def test_shutdown_periodic_tasks_is_noop_when_nothing_tracked():
    """Не должно падать/зависать, если фоновых задач в момент shutdown
    просто нет (обычный путь для короткого запуска в тестах/CI)."""
    scheduler = Scheduler()

    async def _run() -> None:
        await scheduler._shutdown_periodic_tasks(grace_seconds=1)

    asyncio.run(_run())  # не должно бросить исключение или зависнуть
