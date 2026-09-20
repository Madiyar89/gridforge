"""Ретеншн: ограничение роста истории.

Sample пишется на каждый Probe раз в interval_seconds, syslog приходит
потоком от устройств, pcap — это файлы в десятки МБ. Без очистки БД и
диск растут неограниченно, и первым это замечает не мониторинг, а
кончившееся место на сервере.

Сроки задаются переменными окружения (значения ниже — по умолчанию), а
не в UI: это операционная настройка уровня развёртывания, у GridForge
нет таблицы общих настроек, и заводить её ради четырёх чисел незачем.

  GRIDFORGE_RETENTION_SAMPLES_DAYS   (30)  история измерений
  GRIDFORGE_RETENTION_SYSLOG_DAYS    (30)  принятые syslog-сообщения
  GRIDFORGE_RETENTION_CAPTURES_DAYS  (7)   захваты трафика + сами .pcap
  GRIDFORGE_RETENTION_BACKUPS_KEEP   (20)  снимков конфигурации НА УЗЕЛ

Бэкапы ограничены по количеству, а не по возрасту, сознательно: у редко
меняющегося узла снимки могут быть старше любого разумного срока, и
чистка по времени удалила бы единственную копию конфигурации — ровно то,
ради чего бэкапы и делаются. Самый свежий снимок узла не удаляется
никогда.

Агрегации в духе trends (часовые средние вместо сырых значений) здесь
нет: она имеет смысл на объёмах, которых у GridForge пока нет, и её
стоит делать по реальным данным, а не вслепую.
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import Backup, Capture, Sample, SyslogMessage, _now

logger = logging.getLogger("gridforge.retention")


def _days(env_name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(env_name, default)))
    except ValueError:
        logger.warning("%s не число — беру значение по умолчанию %s", env_name, default)
        return default


def _delete_old(db: Session, model, column, days: int) -> int:
    cutoff = _now() - timedelta(days=days)
    return db.query(model).filter(column < cutoff).delete(synchronize_session=False)


def _delete_old_captures(db: Session, days: int) -> int:
    """Захваты удаляются вместе с .pcap на диске — иначе в БД чисто, а
    место занято файлами, которые уже никак не открыть из интерфейса."""
    cutoff = _now() - timedelta(days=days)
    stale = db.query(Capture).filter(Capture.started_at < cutoff).all()
    for capture in stale:
        if capture.file_path:
            try:
                Path(capture.file_path).unlink(missing_ok=True)
            except OSError as exc:
                # Файл не удалился (права, занятость) — запись оставляем,
                # чтобы не потерять ссылку на мусор, который нужно убрать руками.
                logger.warning("не удалось удалить %s: %s", capture.file_path, exc)
                continue
        db.delete(capture)
    return len(stale)


def _trim_backups(db: Session, keep_per_node: int) -> int:
    """Оставить keep_per_node самых свежих снимков каждого узла."""
    removed = 0
    node_ids = [row[0] for row in db.query(Backup.node_id).distinct().all()]
    for node_id in node_ids:
        extra = (
            db.query(Backup)
            .filter(Backup.node_id == node_id)
            .order_by(Backup.taken_at.desc())
            .offset(keep_per_node)
            .all()
        )
        for backup in extra:
            db.delete(backup)
            removed += 1
    return removed


def run_retention(db: Session) -> dict[str, int]:
    """Разовый проход очистки. Возвращает, сколько чего удалено —
    планировщик это логирует, чтобы молчаливая чистка не выглядела как
    пропавшие данные."""
    result = {
        "samples": _delete_old(db, Sample, Sample.taken_at, _days("GRIDFORGE_RETENTION_SAMPLES_DAYS", 30)),
        "syslog": _delete_old(
            db, SyslogMessage, SyslogMessage.received_at, _days("GRIDFORGE_RETENTION_SYSLOG_DAYS", 30)
        ),
        "captures": _delete_old_captures(db, _days("GRIDFORGE_RETENTION_CAPTURES_DAYS", 7)),
        "backups": _trim_backups(db, _days("GRIDFORGE_RETENTION_BACKUPS_KEEP", 20)),
    }
    db.commit()
    if any(result.values()):
        logger.info(
            "очистка: samples=%s syslog=%s captures=%s backups=%s",
            result["samples"], result["syslog"], result["captures"], result["backups"],
        )
    return result
