from datetime import timedelta

import pytest

from app.models import Node, Probe, ProbeKind, Sample, _now
from app.rate_engine import apply_rate, compute_rate, previous_rate_sample


def test_plain_increase_gives_units_per_second():
    rate, skipped = compute_rate(current_raw=2000, previous_raw=1000, seconds=10)
    assert rate == 100.0
    assert skipped is None


def test_counter32_wrap_is_corrected():
    """Счётчик почти дошёл до границы 2^32 и завернулся через ноль —
    это нормальный ход, а не авария: дельта должна считаться сквозь ноль."""
    just_below = 2**32 - 100
    after_wrap = 50  # прошло 150 единиц через границу
    rate, skipped = compute_rate(after_wrap, just_below, seconds=10, counter_bits=32)
    assert rate == 15.0
    assert skipped is None


def test_counter64_wrap_is_corrected():
    just_below = 2**64 - 100
    rate, skipped = compute_rate(50, just_below, seconds=10, counter_bits=64)
    assert rate == 15.0
    assert skipped is None


def test_implausible_rate_is_skipped_when_max_rate_given():
    """Устройство перезагрузилось: счётчик упал с большого значения почти
    в ноль. Арифметически это неотличимо от переполнения, поэтому отсечку
    даёт заданный потолок скорости — без него такой отсчёт выглядел бы
    как авария канала на графике."""
    gigabit_bytes_per_second = 125_000_000
    rate, skipped = compute_rate(
        current_raw=10, previous_raw=3_000_000_000, seconds=10,
        counter_bits=32, max_rate=gigabit_bytes_per_second,
    )
    assert rate is None
    assert "пропущено" in skipped


def test_high_but_plausible_rate_is_kept():
    """Обратная сторона: настоящий трафик на быстром линке не должен
    отбрасываться как «подозрительный» — ниже потолка он проходит."""
    rate, skipped = compute_rate(
        current_raw=1_000_000_000, previous_raw=0, seconds=10,
        counter_bits=32, max_rate=125_000_000,
    )
    assert rate == 100_000_000.0
    assert skipped is None


def test_zero_interval_is_rejected():
    rate, skipped = compute_rate(200, 100, seconds=0)
    assert rate is None
    assert "интервал" in skipped


def test_unknown_counter_bits_falls_back_to_32():
    just_below = 2**32 - 100
    rate, _ = compute_rate(50, just_below, seconds=10, counter_bits=48)
    assert rate == 15.0


@pytest.fixture()
def probe(db):
    node = Node(name="rate-node", address="10.0.0.1")
    db.add(node)
    db.commit()
    p = Probe(node_id=node.id, kind=ProbeKind.snmp_counter_rate, params={"oid": "1.3.6.1", "counter_bits": 32})
    db.add(p)
    db.commit()
    return p


def test_first_measurement_has_no_rate_but_keeps_raw(db, probe):
    """Первое измерение: скорости ещё нет, но сырое показание обязано
    сохраниться — иначе следующий опрос тоже не сможет посчитать дельту."""
    sample = Sample(probe_id=probe.id, ok=True, value=1000.0, taken_at=_now())
    apply_rate(None, sample, probe)

    assert sample.raw_value == 1000.0
    assert sample.value is None
    assert "первое измерение" in sample.detail


def test_second_measurement_becomes_rate(db, probe):
    earlier = Sample(probe_id=probe.id, ok=True, value=None, raw_value=1000.0, taken_at=_now() - timedelta(seconds=60))
    db.add(earlier)
    db.commit()

    sample = Sample(probe_id=probe.id, ok=True, value=7000.0, taken_at=_now())
    apply_rate(earlier, sample, probe)

    assert sample.raw_value == 7000.0
    assert sample.value == pytest.approx(100.0, rel=0.01)  # 6000 единиц за 60 с


def test_previous_sample_lookup_ignores_rows_without_raw(db, probe):
    """Неудачный опрос (счётчик не прочитался) не годится как база для
    дельты — иначе скорость считалась бы от пустоты."""
    db.add(Sample(probe_id=probe.id, ok=True, raw_value=500.0, taken_at=_now() - timedelta(seconds=120)))
    db.add(Sample(probe_id=probe.id, ok=False, raw_value=None, detail="timeout", taken_at=_now() - timedelta(seconds=60)))
    db.commit()

    found = previous_rate_sample(db, probe.id)
    assert found is not None
    assert found.raw_value == 500.0


def test_failed_probe_leaves_no_raw_value(db, probe):
    sample = Sample(probe_id=probe.id, ok=False, value=None, detail="timeout", taken_at=_now())
    apply_rate(None, sample, probe)
    assert sample.raw_value is None
    assert sample.value is None
