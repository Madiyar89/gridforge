"""Применение Template к Node — создаёт реальные Probe/Watch из черновика
(см. models.py:Template для формата probe_defs и предупреждения про
лицензию). Отдельный модуль, не метод на модели — та же причина, что и
watch_engine.py/signal.py: логика годна для юнит-теста без FastAPI/HTTP."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import Probe, ProbeKind, Template, Watch, WatchOperator, WatchSeverity


class TemplateValidationError(ValueError):
    pass


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise TemplateValidationError(message)


def validate_probe_defs(probe_defs: list[dict]) -> None:
    """Бросает TemplateValidationError с понятным сообщением при первой
    проблеме — лучше явный 400 при создании шаблона, чем 500 позже при
    применении к живому узлу."""
    _require(isinstance(probe_defs, list) and len(probe_defs) > 0, "probe_defs должен быть непустым списком")
    for i, pdef in enumerate(probe_defs):
        _require(isinstance(pdef, dict), f"probe_defs[{i}] должен быть объектом")
        _require("kind" in pdef, f"probe_defs[{i}].kind обязателен")
        try:
            ProbeKind(pdef["kind"])
        except ValueError:
            valid = ", ".join(k.value for k in ProbeKind)
            raise TemplateValidationError(f"probe_defs[{i}].kind={pdef['kind']!r} — допустимо: {valid}")
        for j, wdef in enumerate(pdef.get("watches", [])):
            _require(isinstance(wdef, dict), f"probe_defs[{i}].watches[{j}] должен быть объектом")
            _require("operator" in wdef and "label" in wdef, f"probe_defs[{i}].watches[{j}]: нужны operator и label")
            try:
                WatchOperator(wdef["operator"])
            except ValueError:
                valid = ", ".join(o.value for o in WatchOperator)
                raise TemplateValidationError(f"probe_defs[{i}].watches[{j}].operator={wdef['operator']!r} — допустимо: {valid}")
            if "severity" in wdef:
                try:
                    WatchSeverity(wdef["severity"])
                except ValueError:
                    valid = ", ".join(s.value for s in WatchSeverity)
                    raise TemplateValidationError(f"probe_defs[{i}].watches[{j}].severity={wdef['severity']!r} — допустимо: {valid}")


def apply_template(db: Session, template: Template, node_id: int) -> dict:
    """Создаёт Probe (+ вложенные Watch) для node_id по описанию шаблона.
    Не проверяет дубликаты — повторное применение того же шаблона к узлу
    честно заведёт вторые копии проверок (явное действие пользователя,
    не тихая проверка на "уже применялось", которой Template физически не
    отслеживает — здесь только черновик, не привязка к узлам)."""
    created_probe_ids: list[int] = []
    created_watch_ids: list[int] = []
    for pdef in template.probe_defs:
        probe = Probe(
            node_id=node_id,
            kind=ProbeKind(pdef["kind"]),
            params=pdef.get("params", {}),
            interval_seconds=pdef.get("interval_seconds", 60),
            timeout_seconds=pdef.get("timeout_seconds", 2.0),
        )
        db.add(probe)
        db.flush()  # нужен probe.id для дочерних Watch
        created_probe_ids.append(probe.id)
        for wdef in pdef.get("watches", []):
            watch = Watch(
                probe_id=probe.id,
                operator=WatchOperator(wdef["operator"]),
                threshold=wdef.get("threshold"),
                streak_required=wdef.get("streak_required", 1),
                severity=WatchSeverity(wdef.get("severity", "warning")),
                label=wdef["label"],
            )
            db.add(watch)
            db.flush()
            created_watch_ids.append(watch.id)
    db.commit()
    return {"probe_ids": created_probe_ids, "watch_ids": created_watch_ids}
