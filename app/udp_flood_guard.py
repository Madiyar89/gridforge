"""Общий rate-limiter для UDP-приёмников GridForge (syslog_server.py,
netflow_server.py) — оба неаутентифицированные UDP-слушателя, source IP в
датаграмме тривиально подделывается (нет handshake, в отличие от TCP),
поэтому не полагаемся только на "один нарушитель = один настоящий IP":
считаем и по source_ip (чтобы один шумный/подделанный источник не топил
остальных), и глобально (чтобы много разных подделанных IP суммарно не
устроили то же самое).

Пороги по умолчанию в syslog_server.py/netflow_server.py — generously
above нормальной нагрузки на масштабе проекта (десятки-сотни узлов, см.
docs/landscape-report.md): это предохранитель от реального флуда/спуфинга,
не рутинный троттлинг легитимного трафика (см. задачу аудита).

Скользящее окно фиксированного размера (не token bucket) — проще и
достаточно для цели "оборвать явный флуд", не пытается сглаживать burst
трафика в разумных пределах."""

from __future__ import annotations

import logging
import time
from typing import Callable


class RateLimiter:
    def __init__(
        self,
        *,
        per_source_limit: int,
        global_limit: int,
        window_seconds: float = 1.0,
        log_interval_seconds: float = 60.0,
        logger: logging.Logger | None = None,
        label: str = "UDP",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_source_limit = per_source_limit
        self._global_limit = global_limit
        self._window_seconds = window_seconds
        self._log_interval_seconds = log_interval_seconds
        self._logger = logger or logging.getLogger("gridforge.udp_flood_guard")
        self._label = label
        self._clock = clock

        self._window_start = clock()
        self._global_count = 0
        self._per_source_count: dict[str, int] = {}

        # Троттлинг собственного логирования сброшенных сообщений — иначе
        # при реальном флуде лог сам становится новым источником нагрузки
        # (одна строка на каждое отброшенное сообщение — тот же класс
        # проблемы, от которой защищаемся).
        self._dropped_since_log = 0
        self._last_log = clock()

    def allow(self, source_ip: str) -> bool:
        now = self._clock()
        if now - self._window_start >= self._window_seconds:
            self._window_start = now
            self._global_count = 0
            self._per_source_count.clear()

        self._global_count += 1
        source_count = self._per_source_count.get(source_ip, 0) + 1
        self._per_source_count[source_ip] = source_count

        if self._global_count > self._global_limit or source_count > self._per_source_limit:
            self._dropped_since_log += 1
            self._maybe_log(now)
            return False
        return True

    def _maybe_log(self, now: float) -> None:
        if now - self._last_log < self._log_interval_seconds:
            return
        self._logger.warning(
            "%s rate-limit: отброшено %d сообщений за последние ~%.0fс "
            "(лимит на source=%d/с, глобальный=%d/с)",
            self._label,
            self._dropped_since_log,
            now - self._last_log,
            self._per_source_limit,
            self._global_limit,
        )
        self._dropped_since_log = 0
        self._last_log = now
