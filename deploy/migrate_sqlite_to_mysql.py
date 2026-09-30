"""Одноразовый перенос данных SQLite → MySQL/MariaDB (docs/specs/000-platform-
foundations.md, п.3 плана перехода). Раньше такого скрипта в проекте не было
(проверено, `grep -rliE 'migrat'` по app//deploy/ ничего профильного не
находил) — вся текущая рабочая БД (`data/gridforge.db`, реальный узел LAB-1
и т.д.) жила только на SQLite.

НЕ через сырой SQL-дамп — типы данных между SQLite и MySQL не идентичны
(например `Boolean`/`JSON` хранятся по-разному), поэтому перенос идёт через
SQLAlchemy Core, таблица за таблицей, в порядке зависимостей внешних ключей
(`Base.metadata.sorted_tables`), теми же типами колонок, что уже описаны в
app/models.py.

Одноразовая ручная утилита в том же духе, что deploy/rotate_secret_key.py —
НЕ HTTP-эндпоинт, запускается руками один раз при переходе на MySQL.

Использование:
    venv/bin/python3 deploy/migrate_sqlite_to_mysql.py \\
        --sqlite-path data/gridforge.db \\
        --mysql-url "mysql+pymysql://gridforge:PASSWORD@127.0.0.1:3306/gridforge?charset=utf8mb4"

Если --mysql-url не передан, берётся GRIDFORGE_DATABASE_URL из окружения
(тот же URL, что использует сам gridforge при старте) — так перенос всегда
идёт именно туда, куда потом реально подключится приложение.

Идемпотентность: если целевая таблица уже НЕ пустая, перенос для неё
пропускается (с сообщением), чтобы повторный запуск случайно не задвоил
данные через INSERT. Флаг --truncate-target сначала чистит непустые целевые
таблицы (спрашивает подтверждение) — для повторного переноса после того,
как первая попытка не считается финальной.

После копирования каждой таблицы AUTO_INCREMENT на MySQL выставляется в
max(id)+1 — иначе следующая обычная вставка через ORM (autoincrement)
попытается переиспользовать уже занятый перенесёнными данными id.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import MetaData, create_engine, func, select, text  # noqa: E402

from app import models  # noqa: E402, F401 — регистрирует таблицы в Base.metadata
from app.db import Base  # noqa: E402


def _confirm(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes", "да")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sqlite-path",
        default=os.environ.get("GRIDFORGE_DB_PATH", "data/gridforge.db"),
        help="Путь к файлу-источнику SQLite (по умолчанию data/gridforge.db)",
    )
    parser.add_argument(
        "--mysql-url",
        default=os.environ.get("GRIDFORGE_DATABASE_URL"),
        help="SQLAlchemy URL цели MySQL/MariaDB (по умолчанию GRIDFORGE_DATABASE_URL из окружения)",
    )
    parser.add_argument(
        "--truncate-target",
        action="store_true",
        help="Очистить непустые целевые таблицы перед переносом (спросит подтверждение)",
    )
    args = parser.parse_args()

    sqlite_path = Path(args.sqlite_path)
    if not sqlite_path.exists():
        print(f"Источник не найден: {sqlite_path}")
        return 1

    if not args.mysql_url:
        print(
            "Не задан целевой URL — передайте --mysql-url или выставьте "
            "GRIDFORGE_DATABASE_URL в окружении."
        )
        return 1
    if not args.mysql_url.startswith("mysql"):
        print(f"--mysql-url не похож на MySQL/MariaDB URL: {args.mysql_url}")
        return 1

    source_engine = create_engine(f"sqlite:///{sqlite_path}")
    target_engine = create_engine(args.mysql_url)

    print(f"Источник: {sqlite_path}")
    print(f"Цель:     {args.mysql_url}")

    # Схема на цели — те же таблицы/колонки/индексы, что в текущих
    # app/models.py (это НЕ старая схема, которую тянула бы миграция
    # _migrate_missing_columns — свежий create_all покрывает всё).
    Base.metadata.create_all(target_engine)

    with target_engine.begin() as tconn:
        tconn.execute(text("SET FOREIGN_KEY_CHECKS=0"))

    total_copied = 0
    with source_engine.connect() as sconn, target_engine.connect() as tconn:
        for table in Base.metadata.sorted_tables:
            source_count = sconn.execute(select(func.count()).select_from(table)).scalar_one()
            target_count = tconn.execute(select(func.count()).select_from(table)).scalar_one()

            if target_count:
                if args.truncate_target:
                    if not _confirm(
                        f"{table.name}: цель уже содержит {target_count} строк — очистить перед переносом?"
                    ):
                        print(f"{table.name}: пропущено (отказ от очистки)")
                        continue
                    tconn.execute(table.delete())
                    tconn.commit()
                    target_count = 0
                else:
                    print(f"{table.name}: пропущено (цель уже содержит {target_count} строк)")
                    continue

            if not source_count:
                print(f"{table.name}: пусто в источнике, нечего переносить")
                continue

            rows = [dict(row._mapping) for row in sconn.execute(select(table))]
            tconn.execute(table.insert(), rows)
            tconn.commit()

            print(f"{table.name}: перенесено {len(rows)} строк")
            total_copied += len(rows)

            if "id" in table.c and table.c.id.autoincrement:
                max_id = tconn.execute(select(func.max(table.c.id))).scalar_one()
                if max_id is not None:
                    tconn.execute(text(f"ALTER TABLE {table.name} AUTO_INCREMENT = {max_id + 1}"))
                    tconn.commit()

    with target_engine.begin() as tconn:
        tconn.execute(text("SET FOREIGN_KEY_CHECKS=1"))

    print(f"\nГотово: перенесено всего {total_copied} строк.")
    print(
        "Дальше — живая проверка вручную: поднять gridforge-local на MySQL "
        "и пройтись по дашборду/инвентарю/аудиту, сверить с тем, что было на SQLite "
        "(см. docs/specs/000-platform-foundations.md, план перехода, шаг 5)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
