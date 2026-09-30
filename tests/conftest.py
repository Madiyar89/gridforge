"""Фикстуры pytest. Критично: переменные окружения ниже должны быть
выставлены ДО первого импорта app.db/app.main — иначе тесты пишут прямо в
боевой data/gridforge.db (там уже реальный узел LAB-1, см. HANDOFF.md)
и бьются с уже слушающим syslog-портом реального сервера."""

import os
import sys
from pathlib import Path

os.environ.setdefault("GRIDFORGE_DB_PATH", "/tmp/gridforge-tests.db")
os.environ.setdefault("GRIDFORGE_SYSLOG_PORT", "15999")
os.environ.setdefault("GRIDFORGE_NETFLOW_PORT", "15998")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app import models  # noqa: E402, F401 — регистрирует таблицы в Base.metadata
from app.db import Base, SessionLocal, _IS_SQLITE, engine  # noqa: E402


def _reset_schema() -> None:
    """`drop_all`/`create_all` пересоздают схему перед/после каждого теста
    (маленькая тестовая БД, не боевая). На MySQL/MariaDB реальная находка
    живой проверки (переход на MySQL, 2026-09-30, docs/specs/000-platform-
    foundations.md): `Base.metadata.drop_all()` может попытаться дропнуть
    родительскую таблицу раньше дочерней, ссылающейся на неё по FK
    (`vuln_scans`/`vuln_scan_hosts` и т.п.) — InnoDB это не разрешает
    ("Cannot delete or update a parent row"). На SQLite того же кода
    никогда не падало: там FK по умолчанию не проверяются (нет `PRAGMA
    foreign_keys=ON` нигде в проекте), поэтому drop в любом порядке молча
    проходит — сама природа находки в том, что тесты ЭТО скрывали.
    Отключаем проверку FK на время пересоздания схемы — сам порядок
    таблиц роли не играет, а после `create_all` схема снова полностью
    консистентна."""
    if _IS_SQLITE:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        return
    with engine.begin() as conn:
        conn.execute(text("SET FOREIGN_KEY_CHECKS=0"))
    try:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
    finally:
        with engine.begin() as conn:
            conn.execute(text("SET FOREIGN_KEY_CHECKS=1"))


@pytest.fixture(autouse=True)
def _fresh_schema():
    """Пересоздаёт схему перед каждым тестом — маленькая тестовая БД
    (SQLite-файл в /tmp по умолчанию, либо MySQL/MariaDB — см.
    GRIDFORGE_DATABASE_URL), не тот файл/сервер, что использует боевой
    сервер."""
    _reset_schema()
    yield
    _reset_schema()


@pytest.fixture
def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
