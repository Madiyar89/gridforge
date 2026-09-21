"""Риск-скор по категориям — общий движок для AD-аудита и аудита сети,
перенесено из NetOpsHub (hub/backend/app/shared/risk_scoring.py). Одна
и та же арифметика для обоих отчётов — потому и вынесена отдельно, а не
задублирована в ad_audit/net_audit.

Правило = штраф (points) при провале, 0 при успехе. Балл категории —
сумма штрафов провалившихся правил, но не больше 100 (один провал не
должен единолично утопить всю шкалу без потолка). Балл объекта (узла
или домена) — максимум среди его категорий: одна тяжёлая проблема
делает объект рискованным целиком, даже если остальные категории
чистые."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

POINTS_BY_SEVERITY = {"critical": 30, "high": 15, "medium": 10, "low": 5}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str  # critical | high | medium | low
    name: str
    description: str
    fix: str
    # check(facts) -> True, если правило ПРОШЛО (нарушения нет)
    check: Callable[[dict], bool]
    # objects(facts) -> список затронутых объектов (для "Затронуто: N"),
    # вызывается только если check() вернул False
    objects: Callable[[dict], list[str]] = field(default=lambda facts: [])
    # applies(facts) -> False, если правило неприменимо к этому объекту
    # (например, HSRP-правила там, где HSRP вообще не настроен) — тогда
    # правило пропускается целиком, не считается ни провалом, ни успехом
    applies: Callable[[dict], bool] = field(default=lambda facts: True)

    @property
    def points(self) -> int:
        return POINTS_BY_SEVERITY[self.severity]


def evaluate_rules(rules: list[Rule], facts: dict) -> list[dict]:
    """Прогоняет все правила категории по фактам, возвращает список
    результатов в формате для отчёта (не персистится — тот же принцип,
    что в NetOpsHub: отчёт считается на лету по запросу, история не
    хранится)."""
    results = []
    for rule in rules:
        if not rule.applies(facts):
            continue
        ok = rule.check(facts)
        results.append(
            {
                "id": rule.id,
                "severity": rule.severity if not ok else "pass",
                "points": 0 if ok else rule.points,
                "name": rule.name,
                "description": rule.description,
                "fix": rule.fix,
                "objects": [] if ok else rule.objects(facts),
            }
        )
    return results


def category_score(rule_results: list[dict]) -> int:
    return min(100, sum(r["points"] for r in rule_results))


def object_score(category_scores: dict[str, int]) -> int:
    return max(category_scores.values()) if category_scores else 0


def risk_band(score: int) -> str:
    if score <= 25:
        return "низкий"
    if score <= 50:
        return "средний"
    if score <= 75:
        return "высокий"
    return "критический"
