"""Сторож для CSS-переменных фронтенда.

Фронтенд GridForge — обычные .html/.js без шага сборки, поэтому опечатку
в `var(--что-то)` не ловит вообще ничего: браузер молча подставляет
пустоту, элемент остаётся без фона или текст без цвета, и выглядит это
как «просто так задумано».

Именно так и случилось: страница входа рисовалась с `var(--panel)` и
`var(--bad)`, которых в теме нет (там `--surface` и `--crit`), — карточка
осталась без фона, ошибки без красного цвета. Те же две опечатки
разъехались ещё по двум файлам. Нашлось только при ручном сравнении
списков, поэтому сравнение теперь живёт здесь.
"""

import re
from pathlib import Path

import pytest

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
THEME_FILE = STATIC_DIR / "style.css"

_DEFINITION = re.compile(r"^\s*(--[a-z0-9-]+)\s*:", re.MULTILINE)
_USAGE = re.compile(r"var\(\s*(--[a-z0-9-]+)\s*[,)]")


def _defined_variables() -> set[str]:
    return set(_DEFINITION.findall(THEME_FILE.read_text(encoding="utf-8")))


def _files_using_variables() -> list[Path]:
    return sorted(
        path
        for path in STATIC_DIR.iterdir()
        if path.suffix in {".html", ".js", ".css"} and "var(--" in path.read_text(encoding="utf-8")
    )


def test_theme_defines_variables():
    """Если разбор сломается, остальные тесты станут бессмысленно
    зелёными — проверяем, что переменные вообще находятся."""
    defined = _defined_variables()
    assert len(defined) > 10
    assert "--text" in defined and "--surface" in defined


@pytest.mark.parametrize("path", _files_using_variables(), ids=lambda p: p.name)
def test_every_used_variable_exists(path):
    defined = _defined_variables()
    used = set(_USAGE.findall(path.read_text(encoding="utf-8")))
    unknown = sorted(used - defined)
    assert not unknown, (
        f"{path.name} использует переменные, которых нет в style.css: {', '.join(unknown)}. "
        "Браузер подставит пустоту — элемент останется без цвета, и это не будет видно как ошибка."
    )
