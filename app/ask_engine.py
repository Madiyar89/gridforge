"""«Спроси про сеть» — read-only ИИ-отчёт по уже собранным данным GridForge
(docs/landscape-report.md, §4.9). Модель — Gemini (Google), ключ хранится
как обычная Integration (key="gemini"), тот же зашифрованный механизм,
что у MaxMind/Zabbix/Graylog (см. integrations_engine.py).

Ограничение "только чтение" — НЕ на честном слове промпта (модель можно
уговорить проигнорировать инструкцию), а на уровне самого SQL-доступа:

1. Отдельное, по-настоящему read-only соединение SQLite — `file:...?mode=ro`
   (для SQLite; на MySQL это будет отдельная read-only учётка на уровне
   СУБД, см. README). Даже если модель пришлёт DROP TABLE, соединение
   физически не может писать.
2. Поверх — ещё и текстовая проверка запроса (`_validate_readonly_sql`):
   один-единственный SELECT, без ATTACH/PRAGMA/VACUUM и без второго
   выражения после `;` — второй слой защиты, не единственный.

Модель получает не прямой доступ к БД, а единственный tool `query_db`,
который вызывает `_run_readonly_query()` — цикл (main.py) выполняет вызов
и отдаёт модели результат, сама модель SQL не исполняет."""

from __future__ import annotations

import logging
import os
import re
import sqlite3

import httpx

from app.db import DB_PATH, _IS_SQLITE

logger = logging.getLogger("gridforge.ask")

GEMINI_MODEL = os.environ.get("GRIDFORGE_ASK_MODEL", "gemini-3.6-flash")
_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
MAX_TOOL_ROUNDS = 6
MAX_ROWS = 200

_FORBIDDEN_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|REPLACE)\b",
    re.IGNORECASE,
)


class AskError(Exception):
    pass


def _validate_readonly_sql(sql: str) -> str:
    """Второй слой защиты поверх read-only соединения (см. докстринг
    модуля) — падает честной ошибкой, а не пытается "исправить" запрос."""
    stripped = sql.strip().rstrip(";").strip()
    if not stripped:
        raise AskError("пустой SQL-запрос")
    if ";" in stripped:
        raise AskError("допускается только одно выражение (без ';' внутри запроса)")
    if not re.match(r"^\s*SELECT\b", stripped, re.IGNORECASE):
        raise AskError("допускаются только SELECT-запросы")
    if _FORBIDDEN_KEYWORDS.search(stripped):
        raise AskError("запрос содержит запрещённое ключевое слово (только чтение)")
    return stripped


def _run_readonly_query(sql: str) -> dict:
    stripped = _validate_readonly_sql(sql)
    if not _IS_SQLITE:
        # MySQL/MariaDB: нужна read-only учётка на уровне СУБД (см. README) —
        # здесь честно отказываем, а не притворяемся, что защита есть.
        raise AskError(
            "read-only соединение для этой БД не настроено (GRIDFORGE_DATABASE_URL указывает не на SQLite) — "
            "см. README, раздел «Спроси про сеть»"
        )
    uri = f"file:{DB_PATH}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.OperationalError as exc:
        raise AskError(f"не удалось открыть БД в режиме только для чтения: {exc}") from exc
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(stripped)
        rows = cur.fetchmany(MAX_ROWS)
        columns = [d[0] for d in cur.description] if cur.description else []
        truncated = len(rows) == MAX_ROWS and cur.fetchone() is not None
    except sqlite3.Error as exc:
        raise AskError(f"ошибка выполнения запроса: {exc}") from exc
    finally:
        conn.close()
    return {
        "columns": columns,
        "rows": [list(r) for r in rows],
        "row_count": len(rows),
        "truncated": truncated,
    }


def _schema_summary() -> str:
    """Список таблиц и колонок — та же read-only техника, что у самих
    запросов модели (не читерство мимо защиты, просто для системного
    промпта нужно один раз на старте)."""
    uri = f"file:{DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        lines = []
        for table in sorted(tables):
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
            lines.append(f"- {table}({', '.join(cols)})")
        return "\n".join(lines)
    finally:
        conn.close()


_QUERY_TOOL = {
    "function_declarations": [
        {
            "name": "query_db",
            "description": "Выполняет один read-only SQL SELECT-запрос к базе GridForge и возвращает строки результата.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"sql": {"type": "STRING", "description": "Один SELECT-запрос, без точки с запятой внутри."}},
                "required": ["sql"],
            },
        }
    ]
}

_SYSTEM_PROMPT_TEMPLATE = """Ты — read-only ассистент по данным сетевого мониторинга GridForge. \
Отвечай на русском, кратко и по делу, всегда опираясь на реальные данные из БД через инструмент query_db \
(никогда не выдумывай цифры и имена узлов). В финальном ответе перечисли, на какие таблицы/записи опирался \
(например: "по данным incidents за последние 7 дней" или "watches.id=42"), чтобы ответ можно было проверить.

Схема БД (таблица(колонки)):
{schema}

Текущее время (UTC): {now}
"""


async def ask_network(api_key: str, question: str, model: str | None = None) -> dict:
    """Возвращает {"answer": str, "queries": [{"sql": str, "row_count": int}]}.
    api_key — расшифрованный ключ Integration(key="gemini"), достаётся
    вызывающей стороной (main.py) перед вызовом, этот модуль сам с БД
    интеграций не работает. model — переопределение из Integration.url,
    пусто — берётся GEMINI_MODEL."""
    from datetime import datetime, timezone

    model = model or GEMINI_MODEL

    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(schema=_schema_summary(), now=datetime.now(timezone.utc).isoformat())
    contents = [{"role": "user", "parts": [{"text": question}]}]
    executed_queries: list[dict] = []

    async with httpx.AsyncClient(timeout=30) as client:
        for _round in range(MAX_TOOL_ROUNDS):
            payload = {
                "system_instruction": {"parts": [{"text": system_prompt}]},
                "contents": contents,
                "tools": [_QUERY_TOOL],
            }
            try:
                res = await client.post(
                    f"{_API_BASE}/{model}:generateContent",
                    params={"key": api_key},
                    json=payload,
                )
                res.raise_for_status()
                body = res.json()
            except httpx.HTTPError as exc:
                raise AskError(f"вызов Gemini не удался: {exc}") from exc

            candidates = body.get("candidates") or []
            if not candidates:
                raise AskError("Gemini не вернул ответ (пустые candidates)")
            parts = candidates[0].get("content", {}).get("parts", [])

            function_calls = [p for p in parts if "functionCall" in p]
            if not function_calls:
                text = "".join(p.get("text", "") for p in parts).strip()
                if not text:
                    raise AskError("Gemini вернул пустой текстовый ответ")
                return {"answer": text, "queries": executed_queries}

            # Модель-турн с functionCall уходит в историю ЦЕЛИКОМ, включая
            # thoughtSignature — без него следующий вызов падает 400
            # (проверено вживую, не в документации на момент разработки).
            contents.append({"role": "model", "parts": parts})

            response_parts = []
            for call_part in function_calls:
                call = call_part["functionCall"]
                sql = call.get("args", {}).get("sql", "")
                try:
                    result = _run_readonly_query(sql)
                    executed_queries.append({"sql": sql, "row_count": result["row_count"]})
                    response_payload = result
                except AskError as exc:
                    response_payload = {"error": str(exc)}
                response_parts.append(
                    {
                        "functionResponse": {
                            "name": call["name"],
                            "id": call.get("id"),
                            "response": response_payload,
                        }
                    }
                )
            contents.append({"role": "user", "parts": response_parts})

    raise AskError(f"превышен лимит шагов ({MAX_TOOL_ROUNDS}) — вопрос слишком сложный или модель зациклилась")
