import pytest

from app import ask_engine
from app.db import _IS_SQLITE


def test_allowed_table_passes_validation():
    # nodes — обычные инвентарные данные, не секрет; запрос должен пройти
    # оба слоя проверки без ошибки (само выполнение — отдельный вопрос,
    # здесь только whitelist-проверка).
    sql = "SELECT id, name FROM nodes"
    forbidden = ask_engine._referenced_tables(sql) - ask_engine._ALLOWED_TABLES
    assert not forbidden


@pytest.mark.parametrize("table", ["credentials", "api_keys"])
def test_sensitive_table_is_rejected(table):
    sql = f"SELECT * FROM {table}"
    with pytest.raises(ask_engine.AskError, match="закрытой"):
        ask_engine._run_readonly_query(sql)


def test_join_with_forbidden_table_is_rejected():
    sql = "SELECT nodes.name, credentials.username FROM nodes JOIN credentials ON credentials.node_id = nodes.id"
    with pytest.raises(ask_engine.AskError, match="закрытой"):
        ask_engine._run_readonly_query(sql)


@pytest.mark.skipif(
    not _IS_SQLITE,
    reason="_schema_summary() — read-only SQLite-файловое соединение, см. ask_engine.py",
)
def test_schema_summary_omits_sensitive_tables():
    summary = ask_engine._schema_summary()
    for table in (
        "credentials",
        "integrations",
        "ldap_connections",
        "api_keys",
        "users",
        "sessions",
        "channels",
        "domain_scan_credential_sets",
    ):
        assert table not in summary
