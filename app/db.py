"""Хранилище GridForge — своя SQLite-схема, не имеет отношения к схеме
Zabbix (hosts/items/history) и не переиспользует схему NetOpsHub (Device/
Alert): у GridForge собственная терминология (Node/Probe/Sample/Watch/
Incident), см. models.py."""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "gridforge.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def _migrate_missing_columns() -> None:
    """`Base.metadata.create_all()` создаёт только ОТСУТСТВУЮЩИЕ таблицы —
    новую колонку в уже существующей таблице (SQLite, без Alembic) он не
    добавит. Тот же приём, что уже применялся в NetOpsHub при похожей
    проблеме: PRAGMA table_info — если колонки нет, ALTER TABLE ADD COLUMN.
    Идемпотентно, безопасно гонять при каждом старте."""
    additions = {
        "nodes": [
            ("group_id", "INTEGER"),
            ("vendor", "TEXT"),
            ("active", "BOOLEAN DEFAULT 1"),
        ],
    }
    with engine.connect() as conn:
        for table, columns in additions.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            for name, coltype in columns:
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")
        conn.commit()


def init_db() -> None:
    from app import models  # noqa: F401  — регистрирует таблицы в Base.metadata

    Base.metadata.create_all(engine)
    _migrate_missing_columns()


def get_session() -> Session:
    return SessionLocal()
