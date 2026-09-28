"""RateLimiter (app/udp_flood_guard.py), общий для syslog_server.py и
netflow_server.py. Используем инжектируемый clock (параметр `clock`),
а не реальный time.sleep — тот же принцип, что в
tests/test_action_dispatch.py/tests/test_scheduler_shutdown.py: тест не
должен зависеть от реального времени выполнения, чтобы не быть
"flaky" под нагрузкой CI."""

from __future__ import annotations

from app.udp_flood_guard import RateLimiter


class _FakeClock:
    """Управляемые тестом "часы" — .advance(seconds) двигает время вперёд
    без реального sleep()."""

    def __init__(self) -> None:
        self._now = 0.0

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def test_allows_traffic_under_both_limits():
    clock = _FakeClock()
    limiter = RateLimiter(per_source_limit=10, global_limit=100, clock=clock)

    for _ in range(10):
        assert limiter.allow("10.0.0.1") is True


def test_drops_when_per_source_limit_exceeded_within_window():
    clock = _FakeClock()
    limiter = RateLimiter(per_source_limit=5, global_limit=1000, clock=clock)

    allowed = [limiter.allow("10.0.0.1") for _ in range(8)]
    assert allowed == [True, True, True, True, True, False, False, False]


def test_per_source_limit_does_not_affect_other_sources():
    """Один шумный/подделанный source_ip не должен топить остальных —
    это весь смысл считать по source_ip, а не только глобально."""
    clock = _FakeClock()
    limiter = RateLimiter(per_source_limit=3, global_limit=1000, clock=clock)

    for _ in range(3):
        assert limiter.allow("10.0.0.1") is True
    assert limiter.allow("10.0.0.1") is False  # этот источник исчерпал лимит

    # Другой источник в том же окне — не задет.
    assert limiter.allow("10.0.0.2") is True


def test_drops_when_global_limit_exceeded_even_across_many_sources():
    """Много разных (в т.ч. подделанных) source_ip суммарно не должны
    обойти защиту через один только per-source лимит."""
    clock = _FakeClock()
    limiter = RateLimiter(per_source_limit=1000, global_limit=5, clock=clock)

    allowed = [limiter.allow(f"10.0.0.{i}") for i in range(8)]
    assert allowed == [True, True, True, True, True, False, False, False]


def test_window_resets_after_window_seconds_elapsed():
    clock = _FakeClock()
    limiter = RateLimiter(per_source_limit=2, global_limit=1000, window_seconds=1.0, clock=clock)

    assert limiter.allow("10.0.0.1") is True
    assert limiter.allow("10.0.0.1") is True
    assert limiter.allow("10.0.0.1") is False  # лимит окна исчерпан

    clock.advance(1.0)  # окно истекло

    assert limiter.allow("10.0.0.1") is True  # новое окно — счётчик с нуля


def test_dropped_log_is_throttled_not_one_line_per_drop():
    """Собственное логирование сброшенных сообщений не должно само стать
    источником флуда — warning пишется не чаще log_interval_seconds, даже
    если allow() вызывается тысячи раз и каждый раз превышает лимит."""
    calls: list[tuple] = []

    class _FakeLogger:
        def warning(self, *args, **kwargs) -> None:
            calls.append(args)

    clock = _FakeClock()
    limiter = RateLimiter(
        per_source_limit=0,
        global_limit=0,
        clock=clock,
        logger=_FakeLogger(),
        log_interval_seconds=60.0,
    )

    for _ in range(500):
        limiter.allow("10.0.0.1")
    assert len(calls) == 0  # log_interval_seconds (60с) ещё не прошло с момента создания лимитера

    clock.advance(30)
    for _ in range(500):
        limiter.allow("10.0.0.1")
    assert len(calls) == 0  # всё ещё не прошло log_interval_seconds — новой строки нет

    clock.advance(31)  # суммарно 61с с момента создания лимитера
    limiter.allow("10.0.0.1")
    assert len(calls) == 1  # интервал истёк — ровно одна строка на всю накопленную (1001 сброс) пачку


def test_env_var_override_of_thresholds(monkeypatch):
    """GRIDFORGE_SYSLOG_RATE_LIMIT_PER_SOURCE/_GLOBAL и
    GRIDFORGE_NETFLOW_RATE_LIMIT_PER_SOURCE/_GLOBAL читаются на импорт
    модуля — проверяем, что переопределение через переменные окружения
    реально долетает до модульных констант."""
    monkeypatch.setenv("GRIDFORGE_SYSLOG_RATE_LIMIT_PER_SOURCE", "7")
    monkeypatch.setenv("GRIDFORGE_SYSLOG_RATE_LIMIT_GLOBAL", "42")
    monkeypatch.setenv("GRIDFORGE_NETFLOW_RATE_LIMIT_PER_SOURCE", "9")
    monkeypatch.setenv("GRIDFORGE_NETFLOW_RATE_LIMIT_GLOBAL", "99")
    monkeypatch.setenv("GRIDFORGE_SYSLOG_BATCH_SIZE", "3")
    monkeypatch.setenv("GRIDFORGE_NETFLOW_BATCH_SIZE", "4")

    import importlib

    import app.syslog_server as syslog_server
    import app.netflow_server as netflow_server

    importlib.reload(syslog_server)
    importlib.reload(netflow_server)
    try:
        assert syslog_server.SYSLOG_RATE_LIMIT_PER_SOURCE == 7
        assert syslog_server.SYSLOG_RATE_LIMIT_GLOBAL == 42
        assert syslog_server.SYSLOG_BATCH_SIZE == 3
        assert netflow_server.NETFLOW_RATE_LIMIT_PER_SOURCE == 9
        assert netflow_server.NETFLOW_RATE_LIMIT_GLOBAL == 99
        assert netflow_server.NETFLOW_BATCH_SIZE == 4
    finally:
        # Модульные константы читаются один раз на импорт — перезагружаем
        # обратно к дефолтам, чтобы не протащить переопределение в
        # остальные тесты модуля/файла (monkeypatch сам откатит env, но
        # не переимпортирует модуль автоматически).
        monkeypatch.undo()
        importlib.reload(syslog_server)
        importlib.reload(netflow_server)
