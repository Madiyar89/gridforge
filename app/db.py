"""Хранилище GridForge — своя схема, не имеет отношения к схеме Zabbix
(hosts/items/history) и не переиспользует схему NetOpsHub (Device/Alert):
у GridForge собственная терминология (Node/Probe/Sample/Watch/Incident),
см. models.py.

По умолчанию — SQLite-файл (удобно для разработки/тестов, не нужен
отдельный сервер БД). Для боевого сайта — MySQL/MariaDB через
`GRIDFORGE_DATABASE_URL` (2026-09-20, по прямому запросу — "как в Zabbix",
но своя схема, не их SQL). SQLite — не убран, оставлен как fallback,
не требующий поднятого сервера БД; при переходе на MySQL код ниже не
меняется, меняется только это одно значение."""

import os
from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
# Переопределяется тестами (GRIDFORGE_DB_PATH) — иначе pytest писал бы в
# тот же файл, что боевой сервер, включая уже реальный узел LAB-1. Тот
# же паттерн, что уже применяется для GRIDFORGE_SYSLOG_PORT (см. syslog_server.py).
DB_PATH = Path(os.environ.get("GRIDFORGE_DB_PATH") or (DATA_DIR / "gridforge.db"))

# GRIDFORGE_DATABASE_URL — полный SQLAlchemy URL, например:
#   mysql+pymysql://gridforge:PASSWORD@127.0.0.1:3306/gridforge?charset=utf8mb4
# Не задан — используется SQLite-файл (см. DB_PATH выше), как раньше.
_DATABASE_URL = os.environ.get("GRIDFORGE_DATABASE_URL") or f"sqlite:///{DB_PATH}"
_IS_SQLITE = _DATABASE_URL.startswith("sqlite")

# check_same_thread — специфичен для SQLite-драйвера (позволяет делить
# соединение между потоками asyncio-обработчиков); MySQL-драйвер (pymysql)
# такого аргумента не знает и упадёт, если передать его туда тоже.
#
# pool_size/max_overflow — реальный инцидент на проде (2026-09-23):
# дефолтные 5+10=15 соединений исчерпались под обычной нагрузкой (24 узла
# в планировщике + syslog UDP + несколько открытых вкладок, каждая
# опрашивает API раз в 5с) — сайт встал целиком на 504, а не деградировал
# частично, потому что pool_timeout по умолчанию 30с: каждый новый запрос
# ждал свободное соединение все 30с вместо быстрого отказа, и очередь
# только росла. Симптомов утечки (незакрытых сессий) в коде не нашлось —
# все get_session() в scheduler.py/syslog_server.py/console_ws.py
# закрываются в finally. Пул просто был мал для реальной параллельной
# нагрузки. pool_timeout короче — чтобы при повторном исчерпании сайт
# быстро отдавал ошибку отдельным запросам, а не вис целиком минутами.
engine = create_engine(
    _DATABASE_URL,
    connect_args={"check_same_thread": False} if _IS_SQLITE else {},
    pool_size=20,
    max_overflow=30,
    pool_timeout=10,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def _migrate_missing_columns() -> None:
    """`Base.metadata.create_all()` создаёт только ОТСУТСТВУЮЩИЕ таблицы —
    новую колонку в уже существующей таблице (без Alembic) он не добавит.
    Раньше проверка "есть ли колонка" шла через `PRAGMA table_info`
    (SQLite-специфичный синтаксис) — не работает на MySQL. Заменено на
    `sqlalchemy.inspect`, диалект-независимо (работает и на SQLite, и на
    MySQL/MariaDB без правок). Сам `ALTER TABLE ... ADD COLUMN ...` —
    синтаксис одинаковый у обоих. Идемпотентно, безопасно гонять при
    каждом старте."""
    additions = {
        "nodes": [
            ("group_id", "INTEGER"),
            ("vendor", "TEXT"),
            ("active", "BOOLEAN DEFAULT 1"),
            ("ssh_host_key_fingerprint", "TEXT"),
        ],
        "channels": [
            ("node_id", "INTEGER"),
            ("watch_id", "INTEGER"),
        ],
        "incidents": [
            ("last_escalated_minutes", "INTEGER DEFAULT 0"),
        ],
        "api_keys": [
            ("group_id", "INTEGER"),
        ],
        "samples": [
            ("raw_value", "FLOAT"),
        ],
        "users": [
            ("source", "VARCHAR(16) DEFAULT 'local'"),
            ("must_change_password", "BOOLEAN DEFAULT 0"),
            ("allowed_pages", "TEXT"),
        ],
        "credentials": [
            ("node_id", "INTEGER"),
            ("vendor", "VARCHAR(32)"),
        ],
        "domain_scan_hosts": [
            ("manufacturer", "VARCHAR(255)"),
            ("model", "VARCHAR(255)"),
            ("http_banner", "VARCHAR(500)"),
        ],
        "cable_links": [
            ("source", "VARCHAR(16) DEFAULT 'manual'"),
        ],
        "scans": [
            ("vlan_id", "INTEGER"),
        ],
        "credential_check_runs": [
            ("vlan_id", "INTEGER"),
        ],
    }
    inspector = inspect(engine)
    with engine.connect() as conn:
        for table, columns in additions.items():
            existing = {col["name"] for col in inspector.get_columns(table)}
            for name, coltype in columns:
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")
        conn.commit()


def _migrate_renamed_columns() -> None:
    """Колонка уже существует, но под старым именем — не ADD COLUMN (это
    была бы вторая, пустая), а RENAME COLUMN. Тоже идемпотентно: после
    первого запуска старого имени в инспекторе уже нет, условие ложно,
    строка не выполняется повторно.

    2026-09-25: `dc_host`/`live_hosts` поймал tests/test_naming_purity.py
    (общеанглийское "host" здесь означало "адрес сервера"/"живой адрес в
    подсети", не сущность Node — но тест смотрит на текст объявления, не
    на смысл, и по духу этого теста сигнал "переименовать", а не
    "ослабить проверку", см. докстринг models.py)."""
    renames = {
        "ldap_connections": [("dc_host", "dc_address")],
        "domain_scans": [("live_hosts", "live_addresses")],
    }
    inspector = inspect(engine)
    with engine.connect() as conn:
        for table, columns in renames.items():
            if not inspector.has_table(table):
                continue
            existing = {col["name"] for col in inspector.get_columns(table)}
            for old_name, new_name in columns:
                if old_name in existing and new_name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}")
        conn.commit()


def init_db() -> None:
    from app import models  # noqa: F401  — регистрирует таблицы в Base.metadata

    Base.metadata.create_all(engine)
    _migrate_renamed_columns()
    _migrate_missing_columns()


def get_session() -> Session:
    return SessionLocal()
