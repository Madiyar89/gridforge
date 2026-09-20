"""Интеграционные проверки snmp_walk против НАСТОЯЩЕГО SNMP-агента.

Пропускаются, если агента нет — набор должен проходить на машине без
snmpd. Поднять для этих тестов:

    printf 'rocommunity public 127.0.0.1\\nagentaddress udp:127.0.0.1:1161\\n' > /tmp/snmpd-test.conf
    snmpd -f -Lo -C -c /tmp/snmpd-test.conf &

Эти тесты есть потому, что главный дефект walk модульными тестами не
ловился: обход не останавливался на границе поддерева и уходил гулять по
всему MIB устройства. Видно это только на живом агенте — по коду всё
выглядело правильно.
"""

import asyncio

import pytest

from app.models import ProbeKind
from app.probes import run_probe

AGENT = ("127.0.0.1", 1161)
BASE = {"community": "public", "version": "2c", "port": AGENT[1]}
IF_INDEX_OID = "1.3.6.1.2.1.2.2.1.1"   # таблица ifIndex
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"   # имена интерфейсов — СТРОКИ, не числа


def _agent_available() -> bool:
    """Проверяем настоящим SNMP-запросом, а не «отправился ли UDP-пакет».

    Первая версия делала socket.sendto() и считала успех доказательством:
    UDP не сообщает об ошибке синхронно, поэтому отправка «удавалась»
    всегда, тесты не пропускались и падали на машине без агента — ровно
    то, что skipif должен был предотвращать.
    """
    outcome = asyncio.run(
        run_probe(
            ProbeKind.snmp_get,
            AGENT[0],
            {**BASE, "oid": "1.3.6.1.2.1.1.3.0"},  # sysUpTime — есть у любого агента
            1.0,
        )
    )
    return outcome.ok


pytestmark = pytest.mark.skipif(
    not _agent_available(),
    reason="нет локального SNMP-агента на 127.0.0.1:1161 (см. docstring модуля)",
)


def _walk(oid: str, aggregate: str = "count", **extra):
    params = {**BASE, "oid": oid, "aggregate": aggregate, **extra}
    return asyncio.run(run_probe(ProbeKind.snmp_walk, AGENT[0], params, 5.0))


def test_walk_stops_at_subtree_boundary():
    """Регрессия: с lexicographicMode по умолчанию (True) обход уходил за
    границу таблицы и упирался в max_rows, возвращая 500 вместо реального
    числа интерфейсов."""
    outcome = _walk(IF_INDEX_OID, "count", max_rows=500)
    assert outcome.ok
    assert 0 < outcome.value < 500


def test_two_columns_of_one_table_have_equal_row_count():
    """Независимая сверка без знания точного числа интерфейсов: у ifIndex
    и ifDescr строк поровну — это одна и та же таблица."""
    assert _walk(IF_INDEX_OID).value == _walk(IF_DESCR_OID).value


def test_count_includes_non_numeric_rows():
    """ifDescr — строки. Для count это полноценные строки таблицы."""
    outcome = _walk(IF_DESCR_OID, "count")
    assert outcome.ok
    assert outcome.value > 0


def test_numeric_aggregate_over_string_column_is_honest():
    """А вот sum по строковой колонке посчитать нельзя — и вместо тихого
    нуля проверка должна прямо сказать, почему значения нет."""
    outcome = _walk(IF_DESCR_OID, "sum")
    assert outcome.ok
    assert outcome.value is None
    assert "числ" in outcome.detail


def test_max_is_not_greater_than_sum_on_counter_column():
    counter_oid = "1.3.6.1.2.1.2.2.1.10"  # ifInOctets
    assert _walk(counter_oid, "max").value <= _walk(counter_oid, "sum").value


def test_empty_subtree_returns_zero_not_error():
    outcome = _walk("1.3.6.1.2.1.2.2.1.99")  # такой колонки в таблице нет
    assert outcome.ok
    assert outcome.value == 0.0
