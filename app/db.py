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

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Таймаут (в миллисекундах), который SQLite ждёт освобождения залоченной
# базы, прежде чем вернуть "database is locked", вместо немедленного
# отказа (см. PRAGMA busy_timeout ниже). 5с — типичный дефолт для
# однофайловой SQLite под умеренной конкурентной нагрузкой (планировщик +
# syslog_server + netflow_server + API-запросы пишут в один и тот же
# файл) — достаточно, чтобы пережить короткую запись другого писателя, не
# настолько много, чтобы подвисший запрос копил очередь неопределённо.
SQLITE_BUSY_TIMEOUT_MS = 5000

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


if _IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record) -> None:
        """Гоняется на КАЖДОЕ новое соединение пула (идиоматичный способ
        SQLAlchemy применять PRAGMA к SQLite — PRAGMA живёт на уровне
        соединения, не файла, и pool_size=20 в этом файле означает до 20
        независимых соединений, каждое из которых иначе осталось бы на
        journal_mode по умолчанию (rollback journal, не WAL) без
        busy_timeout).

        journal_mode=WAL — читатели не блокируют писателя и наоборот (в
        отличие от journal_mode по умолчанию, где пишущая транзакция
        блокирует всех читателей), критично при нескольких независимых
        engine-потребителях одного файла (scheduler.py/syslog_server.py/
        netflow_server.py/API-запросы, см. комментарий выше про
        pool_size/max_overflow — тот же инцидент 2026-09-23, WAL и
        busy_timeout снижают шанс "database is locked" при этой же
        конкурентной нагрузке, но не заменяют сам пул).

        busy_timeout — вместо немедленного "database is locked" ждёт до
        SQLITE_BUSY_TIMEOUT_MS освобождения перед отказом.

        Специфично для SQLite (PRAGMA — не стандартный SQL, MySQL/
        MariaDB такого не поймёт) — весь блок под `if _IS_SQLITE`, тот же
        принцип, что уже применяется в ask_engine.py."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        finally:
            cursor.close()


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
            ("ssh_key_fingerprint", "TEXT"),
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
        "flow_records": [
            ("tcp_flags", "INTEGER"),
        ],
        "actions": [
            # DEFAULT 300 (не 0!) — существующие Action, заведённые до
            # появления cooldown, получают ту же защиту от дребезга, что
            # и новые: поведение улучшается по умолчанию, а не остаётся
            # молча незащищённым. См. DEFAULT_ACTION_COOLDOWN_SECONDS в
            # actions_engine.py и Action.cooldown_seconds в models.py.
            ("cooldown_seconds", "INTEGER DEFAULT 300"),
            # Аудит-трейл (см. Action.created_by/updated_by/updated_at в
            # models.py) — существующие Action, заведённые до появления
            # этих полей, получают пустой created_by (кто их реально
            # завёл, неизвестно и восстановить нельзя) и NULL
            # updated_by/updated_at (ещё не редактировались этой веткой
            # кода).
            ("created_by", "VARCHAR(128) DEFAULT ''"),
            ("updated_by", "VARCHAR(128)"),
            ("updated_at", "DATETIME"),
        ],
        "action_runs": [
            ("skipped", "BOOLEAN DEFAULT 0"),
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


def _migrate_missing_indexes() -> None:
    """Как и с колонками (см. `_migrate_missing_columns` выше),
    `Base.metadata.create_all()` создаёт индексы только для ТАБЛИЦ,
    которых ещё не было — если таблица `samples`/`incidents` уже
    существует на диске с прошлой версии схемы (до появления составных
    индексов в models.py, 2026-09-28), новый `Index(...)` из
    `__table_args__` туда сам не долетит. `CREATE INDEX` (без `IF NOT
    EXISTS` — не гарантирован на MySQL/MariaDB старых версий, тогда как
    сама проверка через `sqlalchemy.inspect` диалект-независима и уже
    используется тем же приёмом в `_migrate_missing_columns`) — тоже
    синтаксис, одинаковый у SQLite и MySQL/MariaDB. Идемпотентно:
    повторный запуск видит индекс уже существующим в инспекторе и
    ничего не делает."""
    additions = {
        "samples": [("ix_samples_probe_id_taken_at", ["probe_id", "taken_at"])],
        "incidents": [
            ("ix_incidents_watch_id_resolved_at", ["watch_id", "resolved_at"]),
            ("ix_incidents_resolved_at", ["resolved_at"]),
        ],
    }
    inspector = inspect(engine)
    with engine.connect() as conn:
        for table, indexes in additions.items():
            if not inspector.has_table(table):
                continue
            existing = {ix["name"] for ix in inspector.get_indexes(table)}
            for name, columns in indexes:
                if name not in existing:
                    cols = ", ".join(columns)
                    conn.exec_driver_sql(f"CREATE INDEX {name} ON {table} ({cols})")
        conn.commit()


def init_db() -> None:
    from app import models  # noqa: F401  — регистрирует таблицы в Base.metadata

    Base.metadata.create_all(engine)
    _migrate_renamed_columns()
    _migrate_missing_columns()
    _migrate_missing_indexes()
    if _IS_SQLITE and DB_PATH.exists():
        # По умолчанию create_all создаёт файл с правами процесса (обычно
        # 644 — читаемо любым локальным пользователем). Файл содержит
        # хэши паролей/API-ключей/сессий и (хоть и зашифрованные) секреты
        # интеграций — тот же уровень строгости, что уже применён к
        # data/secret.key (secrets_crypto.py). Выставляется на каждый
        # старт (идемпотентно), не только при первом создании — если
        # права были ослаблены снаружи, следующий рестарт их вернёт.
        DB_PATH.chmod(0o600)


def get_session() -> Session:
    return SessionLocal()
