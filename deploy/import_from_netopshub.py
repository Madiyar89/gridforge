"""Перенос инвентаря и бэкапов из NetOpsHub в GridForge.

Одноразовая утилита миграции: GridForge заменяет NetOpsHub, и начинать
с пустого инвентаря, когда рядом лежат 56 заведённых устройств и сотни
снятых конфигураций, незачем.

Читает базу NetOpsHub ТОЛЬКО на чтение и ничего в ней не меняет.
Запускать можно повторно: узлы сопоставляются по имени, бэкапы — по
имени файла, повторный прогон ничего не задваивает.

    venv/bin/python3 deploy/import_from_netopshub.py [путь-к-NetOpsHub-project]
"""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import get_session, init_db  # noqa: E402
from app.models import Backup, Group, Node, Vendor  # noqa: E402

DEFAULT_SOURCE = Path.home() / "Desktop" / "Project" / "NetOpsHub-project"

# У NetOpsHub группа — это министерство + контур; в GridForge группа
# плоская, поэтому склеиваем в одно читаемое имя.
CONTOUR_LABEL = {"inet": "Интернет", "local": "ЕТС"}


def _group_name(ministry_label: str, contour: str) -> str:
    return f"{ministry_label} · {CONTOUR_LABEL.get(contour, contour)}"


def import_groups_and_nodes(db, source_db: sqlite3.Connection) -> tuple[int, int]:
    groups_by_source_id: dict[int, Group] = {}
    created_groups = 0
    for row in source_db.execute("SELECT id, ministry, contour, ministry_label FROM network_groups"):
        source_id, _ministry, contour, label = row
        name = _group_name(label, contour)
        group = db.query(Group).filter(Group.name == name).first()
        if group is None:
            group = Group(name=name)
            db.add(group)
            db.commit()
            db.refresh(group)
            created_groups += 1
        groups_by_source_id[source_id] = group

    created_nodes = 0
    for row in source_db.execute(
        "SELECT hostname, mgmt_ip, vendor, group_id, is_active, model FROM devices"
    ):
        hostname, mgmt_ip, vendor_raw, group_id, is_active, model = row
        try:
            vendor = Vendor(vendor_raw) if vendor_raw else None
        except ValueError:
            vendor = Vendor.generic

        node = db.query(Node).filter(Node.name == hostname).first()
        if node is None:
            node = Node(name=hostname)
            db.add(node)
            created_nodes += 1
        # Адрес и группу обновляем всегда: источник правды — NetOpsHub,
        # повторный прогон должен подтягивать изменения, а не плодить копии.
        node.address = mgmt_ip
        node.vendor = vendor
        node.active = bool(is_active)
        node.tags = model or None
        source_group = groups_by_source_id.get(group_id)
        if source_group is not None:
            node.group_id = source_group.id
    db.commit()
    return created_groups, created_nodes


def import_backups(db, backups_root: Path) -> int:
    """Импортирует .cfg как снимки конфигурации.

    Имя файла вида `LAB-23_2026-09-10_11-17-43.cfg` — из него берём и
    узел, и время снятия: иначе вся история слиплась бы в одну дату
    импорта и `diff` между версиями потерял бы смысл."""
    if not backups_root.exists():
        return 0

    nodes_by_name = {n.name: n for n in db.query(Node).all()}
    existing = {
        (b.node_id, b.taken_at.isoformat()[:19])
        for b in db.query(Backup).all()
    }

    imported = 0
    for path in sorted(backups_root.rglob("*.cfg")):
        stem = path.stem
        if "_" not in stem:
            continue
        node_name, _, timestamp_part = stem.partition("_")
        node = nodes_by_name.get(node_name)
        if node is None:
            continue
        try:
            taken_at = datetime.strptime(timestamp_part, "%Y-%m-%d_%H-%M-%S").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (node.id, taken_at.isoformat()[:19]) in existing:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        db.add(Backup(node_id=node.id, taken_at=taken_at, content=content, changed=True))
        existing.add((node.id, taken_at.isoformat()[:19]))
        imported += 1
        if imported % 100 == 0:
            db.commit()
    db.commit()
    return imported


def main() -> None:
    source_root = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SOURCE
    source_db_path = source_root / "data" / "db" / "netops.db"
    if not source_db_path.exists():
        raise SystemExit(f"не найдена база NetOpsHub: {source_db_path}")

    init_db()
    db = get_session()
    # Строго на чтение: боевой NetOpsHub продолжает работать, портить его
    # импортом нельзя.
    source_db = sqlite3.connect(f"file:{source_db_path}?mode=ro", uri=True)
    try:
        groups, nodes = import_groups_and_nodes(db, source_db)
        backups = import_backups(db, source_root / "data" / "backups")
    finally:
        source_db.close()
        db.close()

    print(f"групп создано: {groups}")
    print(f"узлов создано: {nodes}")
    print(f"бэкапов импортировано: {backups}")


if __name__ == "__main__":
    main()
