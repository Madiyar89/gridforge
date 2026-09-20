"""Проверка лицензионной чистоты имён (HANDOFF.md, п.11).

GridForge — самостоятельная реализация, а не производная работа: идеи
взяты из общедоступного описания, код и схема свои. Практическая
опасность здесь не в коде (его никто не копировал), а в ИМЕНАХ: стоит
однажды назвать сущность `host`, `item` или `trigger` — и схема начинает
выглядеть как повторение чужой, независимо от того, как она написана.

Терминология GridForge: Node / Probe / Sample / Watch / Incident /
Signal. Терминология NetOpsHub (Device, Alert) тоже чужая — это другой
проект того же владельца, и смешивать их схемы не нужно.

`HANDOFF.md` предлагал «проверить вторым человеком — grep по характерным
именам». Человек забывает и устаёт, поэтому проверка живёт здесь и
выполняется на каждом прогоне тестов.
"""

import re
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# Запрещено в любом виде, даже внутри составного имени.
FORBIDDEN_ANYWHERE = {
    "zabbix": "прямое имя чужого продукта",
    "hostgroup": "host group Zabbix — у нас Group",
    "itemkey": "item key Zabbix — у нас Probe.params (JSON, не строковый ключ)",
}

# Запрещено только как ИМЯ СУЩНОСТИ целиком.
#
# «trigger» разбирается отдельно не из снисходительности: как имя
# сущности это прямая калька чужой модели (у нас Watch), но как глагол
# в имени действия — обычное английское слово. `trigger_backup` значит
# «запустить бэкап» и никакого отношения к чужой схеме не имеет.
# Поймано этой же проверкой на BackupTriggerIn: правило уточнено, а не
# отключено.
FORBIDDEN_AS_WHOLE_NAME = {
    "trigger": "триггер Zabbix — у нас Watch",
    "triggers": "таблица триггеров Zabbix — у нас watches",
    "host": "host Zabbix — у нас Node",
    "hosts": "таблица hosts Zabbix — у нас nodes",
    "item": "item Zabbix — у нас Probe",
    "items": "таблица items Zabbix — у нас probes",
    "history": "таблица history Zabbix — у нас samples",
}

# Эти слова законны в обычном коде (trigger в JS-событиях, item в
# итерации), поэтому ищем их только там, где они объявляют сущность:
# имя класса, таблицы, поля модели или пути API.
DECLARATION_PATTERNS = [
    re.compile(r"^class\s+(\w+)", re.MULTILINE),
    re.compile(r"__tablename__\s*=\s*[\"'](\w+)[\"']"),
    # Поле модели берётся вместе с объявленным типом: по нему видно
    # контекст. `hosts: Mapped[list["ScanHost"]]` — это результаты
    # сканирования, и без типа отличить их от узлов мониторинга нельзя.
    re.compile(r"^\s{4}(\w+:\s*Mapped\[[^\]]*\])", re.MULTILINE),
    re.compile(r"@api_\w+\.\w+\(\s*[\"']([^\"']+)[\"']"),
]


def _is_scan_context(name: str) -> bool:
    return "scan" in name.lower()


def _declared_names() -> list[tuple[Path, str]]:
    found = []
    for path in sorted(APP_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in DECLARATION_PATTERNS:
            for match in pattern.finditer(text):
                found.append((path, match.group(1)))
    return found


def test_no_foreign_entity_names():
    """Ни один класс, таблица, поле модели или путь API не должен носить
    имя из чужой терминологии."""
    declared = _declared_names()
    assert declared, "имена сущностей не найдены — проверка смотрела бы в пустоту"

    violations = []
    for path, name in declared:
        # У поля модели имя — до двоеточия, остальное тип (нужен для
        # контекста, см. DECLARATION_PATTERNS).
        bare_name = name.split(":", 1)[0].strip()
        squashed = bare_name.lower().replace("_", "").replace("/", "").replace("-", "")
        for forbidden, why in FORBIDDEN_ANYWHERE.items():
            if forbidden in squashed:
                violations.append(f"{path.name}: {name!r} — {why}")

        # Для имён-целиком сравниваем каждый сегмент пути API и само имя,
        # но не подстроки внутри составных слов.
        segments = {bare_name.lower()} | {part for part in re.split(r"[/_\-{}]", bare_name.lower()) if part}
        if _is_scan_context(name):  # по полному объявлению, вместе с типом
            # «host» в результатах сканирования сети — общепринятый
            # сетевой термин (так их называет и nmap), а не калька чужой
            # схемы: это найденный в подсети адрес, а не узел мониторинга.
            segments -= {"host", "hosts", "host_id"}
        for forbidden, why in FORBIDDEN_AS_WHOLE_NAME.items():
            if forbidden in segments:
                violations.append(f"{path.name}: {name!r} — {why}")
    assert not violations, "чужая терминология в именах:\n" + "\n".join(violations)


def test_own_vocabulary_is_actually_used():
    """Обратная сторона: собственные термины должны существовать. Если
    модель переименуют «для простоты» в Host/Item, предыдущий тест ничего
    не заметит — он проверяет только отсутствие чужого."""
    models = (APP_DIR / "models.py").read_text(encoding="utf-8")
    for expected in ("class Node(", "class Probe(", "class Sample(", "class Watch(", "class Incident("):
        assert expected in models, f"пропала собственная сущность: {expected}"


def test_netopshub_terms_are_not_mixed_in():
    """NetOpsHub — другой проект того же владельца. Оттуда перенесена
    функциональность, но не схема: Device/Alert здесь быть не должно."""
    violations = []
    for path, name in _declared_names():
        if name.lower() in {"device", "alert", "networkgroup", "siterole"}:
            violations.append(f"{path.name}: {name!r}")
    assert not violations, "терминология NetOpsHub в схеме GridForge:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    "marker",
    [
        "AGPL",          # лицензия Zabbix — её текста у нас быть не может
        "Zabbix SIA",    # правообладатель
        "zabbix_server", # имена их компонентов
        "zabbix_agentd",
    ],
)
def test_no_license_or_component_markers(marker):
    """Дословных следов чужого продукта быть не должно нигде в коде."""
    for path in APP_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert marker.lower() not in text.lower(), f"{path.name} содержит {marker!r}"
