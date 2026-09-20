"""Счётчики → скорость.

SNMP-счётчики (ifInOctets, ifHCInOctets и подобные) монотонно растут и
сами по себе бесполезны для мониторинга: «переданo 4 812 993 001 байт»
ничего не говорит, интересна скорость. Скорость = дельта показаний,
делённая на дельту времени, а значит нужны ДВА измерения — поэтому она
считается здесь, при сохранении Sample, а не в probes.py, где предыдущего
измерения просто нет.

Про переполнение. Counter32 оборачивается через 2^32, Counter64 — через
2^64. При дельте < 0 это либо переполнение, либо сброс счётчика
(перезагрузка устройства), и по двум числам эти случаи неотличимы в
принципе. Делаем стандартную коррекцию на переполнение, а защиту от
ложного всплеска даёт необязательный params.max_rate — потолок
правдоподобной скорости (скорость порта), выше которого измерение
считается недостоверным и пропускается. Без него сброс счётчика даст
один завышенный отсчёт: это осознанный размен, потому что эвристика
«похоже на сброс» по одним лишь числам молча теряла бы настоящий трафик
на быстрых линках.

Важное ограничение Counter32: на гигабитном линке под полной нагрузкой
он переполняется примерно за 34 секунды, то есть между опросами может
обернуться НЕСКОЛЬКО раз, и тогда корректная дельта невычислима в
принципе. Для быстрых интерфейсов надо брать 64-битные ifHC-счётчики
(counter_bits=64) — это не недоработка здесь, а свойство самого SNMP.
"""

from __future__ import annotations

import logging

from app.models import Probe, Sample, as_aware

logger = logging.getLogger("gridforge.rate")

_COUNTER_MAX = {32: 2**32, 64: 2**64}


def compute_rate(
    current_raw: float,
    previous_raw: float,
    seconds: float,
    counter_bits: int = 32,
    max_rate: float | None = None,
) -> tuple[float | None, str | None]:
    """Возвращает (скорость в единицах/сек, пояснение при пропуске).

    `max_rate` — правдоподобный потолок скорости для этого счётчика
    (например, байт/с у скорости порта). Если задан и результат его
    превышает, измерение считается недостоверным и пропускается.
    """
    if seconds <= 0:
        return None, "нулевой интервал между измерениями"

    delta = current_raw - previous_raw
    if delta < 0:
        # Счётчик пошёл назад — либо обернулся через границу разрядности,
        # либо был сброшен перезагрузкой устройства. По двум числам эти
        # случаи НЕОТЛИЧИМЫ в принципе: сброс с большого значения даёт
        # ровно такую же арифметику, что и переполнение при высокой
        # скорости. Поэтому здесь применяется стандартная коррекция на
        # переполнение, а отсечка неправдоподобного результата — дело
        # max_rate ниже; выдумывать эвристику «похоже на сброс» по одним
        # лишь числам значило бы молча терять настоящий трафик на быстрых
        # линках.
        delta += _COUNTER_MAX.get(counter_bits, _COUNTER_MAX[32])

    rate = delta / seconds
    if max_rate is not None and rate > max_rate:
        return None, f"скорость {rate:.0f}/с выше предела {max_rate:.0f}/с — счётчик сброшен? измерение пропущено"
    return rate, None


def apply_rate(db_previous: Sample | None, sample: Sample, probe: Probe) -> None:
    """Превращает сырое показание в скорость прямо в объекте Sample.

    До вызова: sample.value — сырой счётчик (как отдал probes.py).
    После:     sample.raw_value — сырой счётчик,
               sample.value     — скорость (или None, если её не вычислить).
    """
    raw = sample.value
    sample.raw_value = raw
    if raw is None:
        return

    if db_previous is None or db_previous.raw_value is None:
        sample.value = None
        sample.detail = "первое измерение — скорость появится со следующего опроса"
        return

    seconds = (as_aware(sample.taken_at) - as_aware(db_previous.taken_at)).total_seconds()
    counter_bits = int(probe.params.get("counter_bits", 32))
    max_rate = probe.params.get("max_rate")
    rate, skip_reason = compute_rate(
        raw, db_previous.raw_value, seconds, counter_bits,
        max_rate=float(max_rate) if max_rate else None,
    )
    sample.value = rate
    if skip_reason:
        sample.detail = skip_reason


def previous_rate_sample(db, probe_id: int) -> Sample | None:
    """Последний Sample этого Probe с сырым показанием. Вызывать ДО
    добавления текущего: измерения, где счётчик не прочитался, для дельты
    бесполезны, поэтому фильтр по raw_value, а не просто «последний»."""
    return (
        db.query(Sample)
        .filter(Sample.probe_id == probe_id, Sample.raw_value.isnot(None))
        .order_by(Sample.taken_at.desc())
        .first()
    )
