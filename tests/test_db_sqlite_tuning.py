"""SQLite WAL/busy_timeout PRAGMA-настройки и составные индексы
(Sample.probe_id+taken_at, Incident.watch_id+resolved_at,
Incident.resolved_at) — реальный аудит нашёл оба пробела: конкурентная
запись в один SQLite-файл (scheduler.py/syslog_server.py/
netflow_server.py/API одновременно) без busy_timeout рискует
"database is locked", а Sample/Incident без нужных индексов означают
полное сканирование таблицы на каждый частый запрос (см. db.py/
models.py)."""

from sqlalchemy import inspect, text

from app.db import SQLITE_BUSY_TIMEOUT_MS, _migrate_missing_indexes, engine


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
        conn.exec_driver_sql("DROP INDEX ix_samples_probe_id_taken_at")
        conn.exec_driver_sql("DROP INDEX ix_incidents_watch_id_resolved_at")
        conn.exec_driver_sql("DROP INDEX ix_incidents_resolved_at")

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

    # Повторный прогон на уже смигрированной БД — не должен падать
    # (идемпотентность: индексы уже есть, ничего заново не создаётся).
    _migrate_missing_indexes()
