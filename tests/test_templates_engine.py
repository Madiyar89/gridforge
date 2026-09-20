import pytest

from app.templates_engine import TemplateValidationError, validate_probe_defs


def _valid_probe_def(**overrides):
    base = {
        "kind": "tcp_port",
        "watches": [{"operator": "eq", "label": "порт закрыт", "severity": "critical"}],
    }
    base.update(overrides)
    return base


def test_valid_probe_defs_pass():
    validate_probe_defs([_valid_probe_def()])  # не должно бросать


def test_empty_list_rejected():
    with pytest.raises(TemplateValidationError):
        validate_probe_defs([])


def test_not_a_list_rejected():
    with pytest.raises(TemplateValidationError):
        validate_probe_defs({"kind": "tcp_port"})  # type: ignore[arg-type]


def test_probe_def_must_be_dict():
    with pytest.raises(TemplateValidationError):
        validate_probe_defs(["not-a-dict"])


def test_missing_kind_rejected():
    with pytest.raises(TemplateValidationError, match="kind"):
        validate_probe_defs([{"watches": []}])


def test_unknown_kind_rejected():
    with pytest.raises(TemplateValidationError, match="допустимо"):
        validate_probe_defs([_valid_probe_def(kind="not_a_real_kind")])


def test_watch_missing_operator_or_label_rejected():
    bad = _valid_probe_def(watches=[{"operator": "eq"}])  # нет label
    with pytest.raises(TemplateValidationError):
        validate_probe_defs([bad])


def test_unknown_operator_rejected():
    bad = _valid_probe_def(watches=[{"operator": "not_real", "label": "x"}])
    with pytest.raises(TemplateValidationError, match="допустимо"):
        validate_probe_defs([bad])


def test_unknown_severity_rejected():
    bad = _valid_probe_def(watches=[{"operator": "eq", "label": "x", "severity": "extreme"}])
    with pytest.raises(TemplateValidationError, match="допустимо"):
        validate_probe_defs([bad])


def test_severity_is_optional():
    # severity не указан вообще — не должно требоваться (см. валидатор:
    # проверка только "if 'severity' in wdef").
    ok = _valid_probe_def(watches=[{"operator": "eq", "label": "x"}])
    validate_probe_defs([ok])


def test_watches_field_is_optional():
    # probe_defs[i] без "watches" вообще — .get("watches", []) даёт пустой
    # список, цикл просто не выполняется, не должно падать.
    validate_probe_defs([{"kind": "icmp_ping"}])
