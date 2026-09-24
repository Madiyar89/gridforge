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
from sqlalchemy.orm import Session  # noqa: E402

from app import models  # noqa: E402, F401 — регистрирует таблицы в Base.metadata
from app.db import Base, SessionLocal, engine  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_schema():
    """Пересоздаёт схему перед каждым тестом — маленькая SQLite-БД в /tmp,
    не тот файл, что использует боевой сервер."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
