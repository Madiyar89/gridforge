"""Снятие и сравнение бэкапов конфигурации — см. models.py:Backup за
обоснованием "почему не git". Выполняется по кнопке/API-запросу (как и
refresh_alerts в NetOpsHub — не по расписанию само по себе на этом
этапе, см. README «Что дальше»)."""

from __future__ import annotations

import difflib

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import Backup, Node
from app.ssh_client import run_ssh_command

DEFAULT_BACKUP_TIMEOUT_SECONDS = 20.0


async def run_backup(db: Session, node: Node, *, username: str, command: str, key_path: str | None = None,
                      password: str | None = None, port: int = 22,
                      timeout_seconds: float = DEFAULT_BACKUP_TIMEOUT_SECONDS) -> Backup:
    result = await run_ssh_command(
        host=node.address,
        port=port,
        username=username,
        command=command,
        timeout_seconds=timeout_seconds,
        key_path=key_path,
        password=password,
    )

    # Сравниваем только с последним УСПЕШНЫМ снимком — неудачная попытка
    # (SSH недоступен и т.п.) не должна ни попадать в diff как "конфиг
    # опустел", ни маскировать реальное предыдущее состояние для
    # следующего сравнения.
    previous = (
        db.query(Backup)
        .filter(Backup.node_id == node.id, Backup.error.is_(None))
        .order_by(desc(Backup.taken_at))
        .first()
    )

    if not result.ok:
        backup = Backup(node_id=node.id, content="", changed=False, error=result.error)
        db.add(backup)
        db.commit()
        db.refresh(backup)
        return backup

    changed = previous is None or previous.content != result.stdout
    backup = Backup(node_id=node.id, content=result.stdout, changed=changed, error=None)
    db.add(backup)
    db.commit()
    db.refresh(backup)
    return backup


def diff_backups(older: str, newer: str) -> str:
    """Unified diff — тот же формат, что уже привычен из `git diff`/
    `backup_diff.py` в NetOpsHub, но считается на лету по двум текстам из
    БД, не по файлам на диске."""
    return "\n".join(
        difflib.unified_diff(
            older.splitlines(),
            newer.splitlines(),
            fromfile="предыдущий",
            tofile="текущий",
            lineterm="",
        )
    )
