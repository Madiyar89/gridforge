"""SQLite WAL/busy_timeout PRAGMA-настройки и составные индексы
(Sample.probe_id+taken_at, Incident.watch_id+resolved_at,
Incident.resolved_at) — реальный аудит нашёл оба пробела: конкурентная
запись в один SQLite-файл (scheduler.py/syslog_server.py/
netflow_server.py/API одновременно) без busy_timeout рискует
"database is locked", а Sample/Incident без нужных индексов означают
полное сканирование таблицы на каждый частый запрос (см. db.py/
models.py).

Индексные тесты диалект-независимы (запускаются и на SQLite, и на MySQL/
MariaDB, см. docs/specs/000-platform-foundations.md, переход на MySQL,
2026-09-30) — но `DROP INDEX` пришлось сделать диалект-осознанным
(`DROP INDEX name ON table` на MySQL, `DROP INDEX name` на SQLite) И
учесть реальную находку живой проверки на MySQL: `ix_samples_probe_id_
taken_at`/`ix_incidents_watch_id_resolved_at` — единственные индексы,
покрывающие FK-колонки (`probe_id`/`watch_id`), а InnoDB не даёт дропнуть
индекс, если это оставит FK без покрывающего индекса (ошибка 1553).
Тест эмулирует "старую" БД без составного индекса, поэтому на MySQL
временно подменяет его обычным одноколоночным индексом на время дропа —
сам продакшен-код (`_migrate_missing_indexes`) индексы никогда не дропает,
это только тестовая симуляция "как будто миграция ещё не применена".
PRAGMA-тест — честно SQLite-специфичный (PRAGMA не существует в MySQL),
пропускается на других диалектах."""

import pytest
from sqlalchemy import inspect, text

from app.db import _IS_SQLITE, SQLITE_BUSY_TIMEOUT_MS, _migrate_missing_indexes, engine


def _drop_index(conn, name: str, table: str, fk_column: str | None = None) -> None:
    if _IS_SQLITE:
        conn.exec_driver_sql(f"DROP INDEX {name}")
        return
    tmp_name = f"{name}__fk_tmp"
    if fk_column:
        # InnoDB требует хотя бы один индекс, покрывающий FK-колонку —
        # без временной замены DROP ниже упадёт с "needed in a foreign
        # key constraint" (см. докстринг файла).
        conn.exec_driver_sql(f"CREATE INDEX {tmp_name} ON {table} ({fk_column})")
    conn.exec_driver_sql(f"DROP INDEX {name} ON {table}")


def _drop_temp_fk_index(conn, name: str, table: str) -> None:
    if not _IS_SQLITE:
        conn.exec_driver_sql(f"DROP INDEX {name}__fk_tmp ON {table}")


@pytest.mark.skipif(not _IS_SQLITE, reason="PRAGMA — синтаксис, специфичный для SQLite")
def test_wal_mode_and_busy_timeout_applied_on_connect(db):
    # `db` (conftest.py) уже открыл соединение через тот же engine — те же
    # PRAGMA, что event-листенер применяет на КАЖДОЕ новое соединение пула.
    journal_mode = db.execute(text("PRAGMA journal_mode")).scalar()
    busy_timeout = db.execute(text("PRAGMA busy_timeout")).scalar()
    assert journal_mode == "wal"
    assert busy_timeout == SQLITE_BUSY_TIMEOUT_MS


def test_sample_and_incident_indexes_exist_on_fresh_schema(db):
    # conftest._fresh_schema уже прогнал Base.metadata.create_all() перед
    # этим тестом — составные индексы объявлены прямо в __table_args__
    # моделей (models.py), значит на СВЕЖЕЙ базе они должны попасть в
    # schema без отдельной миграции.
    inspector = inspect(engine)
    sample_indexes = {ix["name"] for ix in inspector.get_indexes("samples")}
    incident_indexes = {ix["name"] for ix in inspector.get_indexes("incidents")}

    assert "ix_samples_probe_id_taken_at" in sample_indexes
    assert "ix_incidents_watch_id_resolved_at" in incident_indexes
    assert "ix_incidents_resolved_at" in incident_indexes


def test_migrate_missing_indexes_is_idempotent_on_existing_db(db):
    # Симулируем "старую" БД, заведённую до появления составных индексов:
    # схема (таблицы) уже есть (conftest создал их через create_all), но
    # сами новые индексы у неё отсутствуют — как было бы у реального
    # gridforge.db, созданного до этой правки.
    with engine.begin() as conn:
        _drop_index(conn, "ix_samples_probe_id_taken_at", "samples", fk_column="probe_id")
        _drop_index(conn, "ix_incidents_watch_id_resolved_at", "incidents", fk_column="watch_id")
        _drop_index(conn, "ix_incidents_resolved_at", "incidents")

    inspector = inspect(engine)
    assert "ix_samples_probe_id_taken_at" not in {ix["name"] for ix in inspector.get_indexes("samples")}

    # Первый прогон — должен создать отсутствующие индексы.
    _migrate_missing_indexes()

    inspector = inspect(engine)
    sample_indexes = {ix["name"] for ix in inspector.get_indexes("samples")}
    incident_indexes = {ix["name"] for ix in inspector.get_indexes("incidents")}
    assert "ix_samples_probe_id_taken_at" in sample_indexes
    assert "ix_incidents_watch_id_resolved_at" in incident_indexes
    assert "ix_incidents_resolved_at" in incident_indexes

    # Реальный составной индекс уже снова покрывает FK — временную замену
    # можно убрать (иначе она просто лишний индекс, ничему не мешает, но
    # незачем оставлять мусор от симуляции).
    with engine.begin() as conn:
        _drop_temp_fk_index(conn, "ix_samples_probe_id_taken_at", "samples")
        _drop_temp_fk_index(conn, "ix_incidents_watch_id_resolved_at", "incidents")

    # Повторный прогон на уже смигрированной БД — не должен падать
    # (идемпотентность: индексы уже есть, ничего заново не создаётся).
    _migrate_missing_indexes()
